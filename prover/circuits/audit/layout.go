// Fixes where each byte of the auditor stream sits, per key shape and per frame.
//
// A circuit encrypts one plaintext length per key, and a frame publishes less. The key alone fixes
// every counter, no published count moves a region, and a reader decrypts slot i at its own counter
// with no other slot. The frame omits padding and unpublished slots, so the bytes the statement hashes
// are the regions the published n, m and has_data select. The program cuts every ciphertext from n, m
// and the layout flags, the entry flag moves the envelope's length and has_data adds one tail per slot.
//
// The envelope seals the viewing key, note count and address bitmap before any entry evidence.
// Entry evidence keeps one position per published input, including addresses and dummies.
// Record counters start after the envelope at full input capacity, rounded up to an AES block.
// Readers must use that capacity even when the frame carries fewer inputs, or they select another keystream.
// Tail counters follow every output record at full output capacity.
//
// The file proves the following.
//  1. The layout value holds two flags, a value past them fails its decomposition.
//  2. The entry flag equals the key's entry capacity.
//  3. Range construction rejects an input capacity outside the address bitmap bound.
//
// Read after shared/envelope.go. Read before audit/audit.go, audit/record.go.

package audit

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Flags of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const (
	LayoutHasData = 1 << iota
	LayoutEntry
	LayoutSingleAssetPayout
)

const layoutBits = 3

type StreamShape struct {
	InputClass, Outputs int
	Entry               bool
	SingleAssetPayout   bool
}

// DecodeLayout returns has_data and pins the entry flag to the key.
func (s StreamShape) DecodeLayout(api frontend.API, layout frontend.Variable) frontend.Variable {
	// The decomposition bounds the layout to its flags.
	bits := api.ToBinary(layout, layoutBits)
	entry := 0
	if s.Entry {
		entry = 1
	}
	api.AssertIsEqual(bits[1], entry)
	payout := 0
	if s.SingleAssetPayout {
		payout = 1
		api.AssertIsEqual(bits[0], 0)
	}
	api.AssertIsEqual(bits[2], payout)
	return bits[0]
}

// StreamRanges mirrors AuditStreamLayout in program-libs/interface/src/proof/audit_stream.rs.
//
//	envelope, EnvelopeBlocks | records, Outputs * RecordBlocks | tails, Outputs * TailBlocks
type StreamRanges struct {
	StreamShape
}

const (
	streamBlockLen = 16
	// StreamFirstCounter is aes.Cipher.CTREncrypt's first counter, mirrored by STREAM_FIRST_COUNTER.
	StreamFirstCounter  = 2
	EnvelopeKeyLen      = 32
	RealInputCountLen   = 1
	AddressInputBitsLen = shared.InputBitmapBits / 8
	DefaultInputBitsLen = 8
	fieldLen            = 32
	amountLen           = 8
	kindLen             = 1
	// RecordLen is the bytes a transfer frame carries, mirrored by AUDIT_RECORD_LEN.
	RecordLen = kindLen + amountLen + 3*fieldLen
	TailLen   = 2 * fieldLen
	// EntryRecordLen mirrors ENTRY_RECORD_LEN.
	EntryRecordLen = amountLen + 4*fieldLen
	RecordBlocks   = (RecordLen + streamBlockLen - 1) / streamBlockLen
	// RecordStride mirrors RECORD_STRIDE, slot i keeps its counter and a transfer frame omits the padding.
	RecordStride       = RecordBlocks * streamBlockLen
	TailBlocks         = TailLen / streamBlockLen
	PayoutRecordLen    = kindLen + amountLen + 2*fieldLen
	PayoutRecordBlocks = (PayoutRecordLen + streamBlockLen - 1) / streamBlockLen
	PayoutRecordStride = PayoutRecordBlocks * streamBlockLen
	recordMintStart    = kindLen + amountLen + fieldLen
	recordMintEnd      = recordMintStart + fieldLen
)

func (s StreamShape) Ranges() StreamRanges {
	if err := shared.ValidateInputCapacity(s.InputClass); err != nil {
		panic(err)
	}
	if s.SingleAssetPayout && (s.InputClass != 1 || s.Outputs != 16 || s.Entry) {
		panic("invalid single asset payout shape")
	}
	return StreamRanges{StreamShape: s}
}

func (r StreamRanges) EnvelopeHeadLen() int {
	head := EnvelopeKeyLen + RealInputCountLen + AddressInputBitsLen
	if r.SingleAssetPayout {
		return head + fieldLen
	}
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

// EnvelopeBlocks is fixed per shape, no published count moves a record's counter.
func (r StreamRanges) EnvelopeBlocks() int {
	return (r.EnvelopeLen(r.InputClass) + streamBlockLen - 1) / streamBlockLen
}

// RecordCounter must match the readers, another counter decrypts noise.
func (r StreamRanges) RecordCounter(i int) int {
	return StreamFirstCounter + r.EnvelopeBlocks() + i*r.RecordBlocks()
}

// TailCounter must match the readers, a tail shares no counter with a record.
func (r StreamRanges) TailCounter(i int) int {
	return r.RecordCounter(r.Outputs) + i*TailBlocks
}

// CapacityBlocks covers every slot's record and tail, a frame omits what it does not publish.
func (r StreamRanges) CapacityBlocks() int {
	if r.SingleAssetPayout {
		return r.EnvelopeBlocks() + r.Outputs*r.RecordBlocks()
	}
	return r.EnvelopeBlocks() + r.Outputs*(r.RecordBlocks()+TailBlocks)
}

func (r StreamRanges) RecordOffset(i int) int {
	return (r.RecordCounter(i) - StreamFirstCounter) * streamBlockLen
}

func (r StreamRanges) TailOffset(i int) int {
	return (r.TailCounter(i) - StreamFirstCounter) * streamBlockLen
}

func (r StreamRanges) RecordLen() int {
	if r.SingleAssetPayout {
		return PayoutRecordLen
	}
	return RecordLen
}

func (r StreamRanges) RecordBlocks() int {
	if r.SingleAssetPayout {
		return PayoutRecordBlocks
	}
	return RecordBlocks
}

func (r StreamRanges) RecordStride() int {
	return r.RecordBlocks() * streamBlockLen
}
