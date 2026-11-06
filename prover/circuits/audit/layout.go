// Fixes where each byte of the auditor stream and of each output record sits, per key shape and per frame.
//
// A circuit encrypts one plaintext length per key, and a frame publishes less. The key alone fixes
// every counter, no published count moves a region, and a reader decrypts recipient key i at its own
// counter with no other slot. The frame omits padding and unpublished slots, so the bytes the statement
// hashes are the regions the published n and m select.
//
// The auditor stream holds the envelope, then one recipient key per output slot at full output capacity.
// The envelope seals the viewing key and the note count before any entry evidence. Entry evidence keeps
// one record per published input in note order. Key counters start after the envelope at full input
// capacity, rounded up to an AES block. Readers must use that capacity even when the frame carries fewer
// inputs, or they select another keystream.
//
// Each output record is its own stream under its slot secret, so no counter of the auditor stream serves it.
//
// The file proves the following.
//  1. The layout value holds the entry flag alone, a value past it fails its decomposition.
//  2. The entry flag equals the key's entry capacity.
//  3. Range construction rejects an input capacity outside the entry bitmap.
//
// Read after shared/envelope.go. Read before audit/audit.go, audit/record.go.

package audit

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// LayoutEntry is the one flag of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const LayoutEntry = 1 << 1

const layoutBits = 2

type StreamShape struct {
	InputClass, Outputs int
	Entry               bool
}

// AssertLayout pins the layout to the key's entry flag, bit 0 stays clear.
func (s StreamShape) AssertLayout(api frontend.API, layout frontend.Variable) {
	// The decomposition bounds the layout to its two bits.
	bits := api.ToBinary(layout, layoutBits)
	entry := 0
	if s.Entry {
		entry = 1
	}
	api.AssertIsEqual(bits[0], 0)
	api.AssertIsEqual(bits[1], entry)
}

// StreamRanges mirrors AuditStreamLayout in program-libs/interface/src/proof/audit_stream.rs.
//
//	envelope, EnvelopeBlocks | recipient keys, Outputs * KeyBlocks
type StreamRanges struct {
	StreamShape
}

const (
	streamBlockLen = 16
	// StreamFirstCounter is aes.Cipher.CTREncrypt's first counter, mirrored by STREAM_FIRST_COUNTER.
	StreamFirstCounter  = 2
	EnvelopeKeyLen      = 32
	RealInputCountLen   = 1
	DefaultInputBitsLen = 8
	fieldLen            = 32
	amountLen           = 8
	kindLen             = 1
	// RecordLen is the bytes a slot carries, mirrored by OUTPUT_RECORD_LEN.
	RecordLen = kindLen + amountLen + 4*fieldLen
	// KeyLen is one sealed recipient key, its region holds no padding.
	KeyLen    = fieldLen
	KeyBlocks = KeyLen / streamBlockLen
	// EntryRecordLen mirrors ENTRY_RECORD_LEN.
	EntryRecordLen = amountLen + 4*fieldLen
)

func (s StreamShape) Ranges() StreamRanges {
	if err := shared.ValidateInputCapacity(s.InputClass); err != nil {
		panic(err)
	}
	return StreamRanges{StreamShape: s}
}

func (r StreamRanges) EnvelopeHeadLen() int {
	head := EnvelopeKeyLen + RealInputCountLen
	if r.Entry {
		return head + DefaultInputBitsLen
	}
	return head
}

func (r StreamRanges) entryLen() int {
	if r.Entry {
		return EntryRecordLen
	}
	return 0
}

// EnvelopeLen is what the frame carries, with no padding.
func (r StreamRanges) EnvelopeLen(count int) int {
	return r.EnvelopeHeadLen() + count*r.entryLen()
}

// EnvelopeBlocks is fixed per shape, no published count moves a key's counter.
func (r StreamRanges) EnvelopeBlocks() int {
	return (r.EnvelopeLen(r.InputClass) + streamBlockLen - 1) / streamBlockLen
}

// KeyCounter must match the readers, another counter decrypts noise.
func (r StreamRanges) KeyCounter(i int) int {
	return StreamFirstCounter + r.EnvelopeBlocks() + i*KeyBlocks
}

// CapacityBlocks covers the envelope and every slot's key, a frame omits what it does not publish.
func (r StreamRanges) CapacityBlocks() int {
	return r.EnvelopeBlocks() + r.Outputs*KeyBlocks
}

func (r StreamRanges) KeyOffset(i int) int {
	return (r.KeyCounter(i) - StreamFirstCounter) * streamBlockLen
}
