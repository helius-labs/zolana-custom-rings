package ring

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

// Frame byte lengths the circuit does not bind itself, mirrored by program-libs/interface/src/instructions/transact.rs.
const (
	frameProofLen    = 192
	frameSppProofLen = 128
	frameTreeLen     = 4
	frameSlotTagLen  = 8
	frameExitBodyLen = 83
	frameViewTagLen  = 32
	frameCacheWrites = 16
)

type frameRail int

const (
	frameConfidential frameRail = iota
	frameDelegate
	frameAnonymous
	frameAnonymousDelegate
)

// frameCases lists the rail of every line of settlement/frame.hex, in Fixture::cases order.
var frameCases = []frameRail{
	frameConfidential, frameConfidential, frameConfidential, frameConfidential, frameConfidential, frameConfidential, frameConfidential,
	frameAnonymous, frameAnonymous, frameAnonymous, frameDelegate, frameAnonymousDelegate, frameAnonymous, frameAnonymous, frameConfidential,
}

type frameCursor struct {
	t    *testing.T
	rest []byte
}

func (c *frameCursor) take(n int) []byte {
	c.t.Helper()
	if n > len(c.rest) {
		c.t.Fatalf("frame ends %d bytes short", n-len(c.rest))
	}
	head := c.rest[:n]
	c.rest = c.rest[n:]
	return head
}

func (c *frameCursor) bits(count int) uint64 {
	c.t.Helper()
	bits := uint64(0)
	for i, b := range c.take((count + 7) / 8) {
		bits |= uint64(b) << (8 * i)
	}
	return bits
}

// The Go lengths walk every frame the program parses to its last byte, a length off the program's would miss the end.
func TestFrameVectorWalksEveryField(t *testing.T) {
	lines := vectorLines(t, "../../test-vectors/settlement/frame.hex")
	if len(lines) != len(frameCases) {
		t.Fatalf("%d frames, %d cases", len(lines), len(frameCases))
	}
	for i, line := range lines {
		t.Run(fmt.Sprint(i), func(t *testing.T) { walkTransferFrame(t, line, frameCases[i]) })
	}
}

func walkTransferFrame(t *testing.T, line []byte, rail frameRail) {
	t.Helper()
	const (
		curatorFlag, ownerInProof, ownRoot, secondTree, replyFlag, extensionsFlag = 2, 8, 16, 32, 64, 128
		defaultOwnerTag, publicOwners                                             = 64, 128
		hasData, entry                                                            = 64, 128
		wideOwners, lowBits                                                       = 128, 63
	)
	anonymousFrame := rail == frameAnonymous || rail == frameAnonymousDelegate
	c := frameCursor{t: t, rest: line}
	head := c.take(5)
	flags, shape, inputByte, m := head[0], head[1], head[2], int(head[3]&^wideOwners)
	n := int(inputByte & lowBits)
	if m < 1 || m > 16 {
		t.Fatalf("output count %d", m)
	}
	c.take(frameProofLen + 8)
	if flags&ownRoot != 0 {
		c.take(8)
	}
	if flags&curatorFlag != 0 {
		c.take(8)
	}
	c.take(4 + 32 + 16)
	if flags&extensionsFlag != 0 {
		walkExtensions(&c)
	}
	transfers := int(c.take(1)[0])
	splWithdrawals := 0
	for range transfers {
		kind := c.take(1)[0]
		c.take(8)
		if kind >= 2 {
			c.take(1)
		}
		if kind == 3 {
			splWithdrawals++
		}
	}
	if flags&ownRoot != 0 {
		c.take(32 * splWithdrawals)
	}
	exits := c.bits(m)
	bodies := 0
	for slot := range m {
		exit := exits>>slot&1 == 1
		// The bytes past the record, a payload or an exit's scheme 3 body.
		extra := 0
		switch {
		case inputByte&hasData != 0:
			extra = int(binary.LittleEndian.Uint16(c.take(2)))
		case exit:
			extra = frameExitBodyLen
		}
		tag := frameSlotTagLen
		if exit {
			tag = 32
		} else {
			bodies++
		}
		c.take(32 + tag + audit.RecordLen + extra)
	}
	if flags&replyFlag != 0 {
		c.take(int(binary.LittleEndian.Uint16(c.take(2))) * bodies)
	}
	if anonymousFrame {
		c.take(32 + ringprotocol.SenderBundleLen(m))
	}
	stream := audit.StreamShape{InputClass: n, Outputs: m, Entry: inputByte&entry != 0}.Ranges()
	c.take(stream.EnvelopeLen(n) + m*audit.KeyLen)
	c.take(32)
	if rail == frameAnonymous && shape&publicOwners == 0 {
		c.take(64)
		if shape&defaultOwnerTag != 0 {
			c.take(32)
		}
	}
	if flags&ownerInProof != 0 {
		c.take(96)
	}
	c.take(frameSppProofLen + 32*n)
	if flags&secondTree != 0 {
		c.bits(n)
		c.take(frameTreeLen)
	}
	c.take(frameTreeLen)
	if len(c.rest) != 0 {
		t.Fatalf("%d bytes past the last field", len(c.rest))
	}
}

// walkExtensions mirrors FrameExtensions::read.
func walkExtensions(c *frameCursor) {
	const dataHash, ringDataHash, messages, cache, approvalTotals = 1, 2, 4, 8, 16
	flags := c.take(1)[0]
	if flags&^(dataHash|ringDataHash|messages|cache|approvalTotals) != 0 {
		c.t.Fatalf("extension flags %b past the known", flags)
	}
	if flags&dataHash != 0 {
		c.take(32)
	}
	if flags&ringDataHash != 0 {
		c.take(32)
	}
	if flags&messages != 0 {
		for range int(c.take(1)[0]) {
			c.take(frameViewTagLen)
			c.take(int(binary.LittleEndian.Uint16(c.take(2))))
		}
	}
	if flags&cache != 0 {
		c.take(8 + 2*frameCacheWrites)
	}
	if flags&approvalTotals != 0 {
		c.take(32)
	}
}

func TestMergeFrameVectorWalksTheRecord(t *testing.T) {
	lines := vectorLines(t, "../../test-vectors/merge/merge_frame.hex")
	c := frameCursor{t: t, rest: lines[0]}
	c.take(8 + 32 + 32 + frameProofLen + 33 + circuits.MergeEnvelopeLen + circuits.MergeRecordLen)
	if len(c.rest) == 0 {
		t.Fatal("the frame holds no SPP merge body")
	}
}

func vectorLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		decoded, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, decoded)
	}
	return lines
}
