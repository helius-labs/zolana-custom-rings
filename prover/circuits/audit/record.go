// Encodes the output record a recipient and the auditor both read, and the evidence about spent notes.
//
// SPP's output hash commits the owner key and the mint only as hashes, and no reader inverts a hash. A
// record therefore carries the raw key and the raw mint with the proof holding each to its hash, so the
// auditor names an owner and an asset with no directory. Its amount, nullifier key and blinding are the
// slot's own wires. The recipient holds no viewing secret of the transaction, so the record carries the
// blinding SPP derived. The reader rebuilds the published hash from these fields, the frame's tree id
// and the data hashes of the slot's payload, so a record of another slot rebuilds nothing.
//
// A dummy's plaintext is all zero, the auditor knows it by one byte under a proof and rebuilds its
// hash from the derived blinding and the frame's tree id. That byte is no prover choice. Kind derives
// from the domain and ring id the slot's hash commits, a note called a dummy would need another hash.
// Exit marks a note of the default ring, its recipient body is SPP's.
//
// The file proves the following.
//  1. A live record's kind, amount, owner key, mint, nullifier key and blinding are the opened slot's,
//     with the amount below 2^64 and each field the one canonical encoding.
//  2. Every other record is all zero.
//  3. A merge record is a record followed by the seed that rebuilds its blinding.
//  4. R counts only notes, and a key with no entry capacity refuses a default ring note.
//  5. Each default ring note has an entry record at its note position on an entry key, with its default
//     bit set. The record holds the note's owner key, nullifier key, amount and mint, and the commitment
//     the input section opened. Every other position has a zero default bit and a zero record.
//
// Read after audit/audit.go, audit/layout.go, shared/utxo.go, transfer/input.go.
// Read before merge.go.

package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// The record's kind byte, mirrored by RecordKind in program-libs/interface/src/proof/audit_stream.rs.
const (
	KindDummy = 0
	KindRing  = 1
	KindExit  = 2
)

type OutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
	// MintChunks open Asset to the 31 and 1 byte chunks of the raw mint.
	MintChunks [2]frontend.Variable
	// RecipientKey is the u the record is sealed to, the envelope seals it for the auditor.
	RecipientKey [32]frontend.Variable
}

func (o OutputWires) record(api frontend.API, rc frontend.Rangechecker, slot shared.Output) []frontend.Variable {
	return RecordOpening{
		Live: slot.Utxo, Kind: api.Add(api.Mul(slot.Ring, KindRing), api.Mul(slot.Exit, KindExit)),
		Amount: slot.Amount, OwnerPkHash: slot.OwnerPkHash, NullifierPk: slot.NullifierPk, Asset: slot.Asset, Blinding: slot.Blinding,
		OwnerKey: o.OwnerKey, MintChunks: o.MintChunks,
	}.Encode(api, rc)
}

// Live clear masks every byte but Kind, a dummy's Kind derives to zero.
type RecordOpening struct {
	Live, Kind, Amount, OwnerPkHash, NullifierPk, Asset, Blinding frontend.Variable
	OwnerKey                                                      [32]frontend.Variable
	MintChunks                                                    [2]frontend.Variable
}

// Encode mirrors OutputRecord::encode in program-libs/interface/src/proof/audit_stream.rs, RecordLen bytes.
func (r RecordOpening) Encode(api frontend.API, rc frontend.Rangechecker) []frontend.Variable {
	raw := identityOpening{Live: r.Live, OwnerPkHash: r.OwnerPkHash, Asset: r.Asset, OwnerKey: r.OwnerKey, MintChunks: r.MintChunks}.open(api)
	// FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
	nullifierPk := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(r.Live, r.NullifierPk))
	blinding := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(r.Live, r.Blinding))
	return slices.Concat([]frontend.Variable{r.Kind}, ringgadget.UintBytesBE(api, api.Mul(r.Live, r.Amount), amountLen), raw.ownerKey, raw.mint, nullifierPk[:], blinding[:])
}

// identityOpening is a slot's owner and asset beside the raw key and mint the auditor reads.
type identityOpening struct {
	Live, OwnerPkHash, Asset frontend.Variable
	OwnerKey                 [32]frontend.Variable
	MintChunks               [2]frontend.Variable
}

type rawIdentity struct {
	ownerKey, mint []frontend.Variable
}

// open holds the raw bytes to the slot's commitment fields while Live is set, and zeroes them otherwise. A record of another key or mint would rebuild no commitment the reader accepts.
func (o identityOpening) open(api frontend.API) rawIdentity {
	mint := assertMint(api, o.Live, o.Asset, o.MintChunks)
	// SolanaOwnerIdentity bounds every owner key byte, the reader rebuilds the owner from the key.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: o.Live, A: o.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, o.OwnerKey)})
	return rawIdentity{ownerKey: masked(api, o.Live, o.OwnerKey[:]), mint: masked(api, o.Live, mint)}
}

// assertMint holds a live asset to the raw mint the record carries, the auditor needs no mint registry.
func assertMint(api frontend.API, live, asset frontend.Variable, chunks [2]frontend.Variable) []frontend.Variable {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: live, A: asset, B: gadget.HashChain(api, chunks[:])})
	return slices.Concat(ringgadget.UintBytesBE(api, chunks[0], 31), ringgadget.UintBytesBE(api, chunks[1], 1))
}

// MergeRecordLen mirrors MERGE_RECORD_LEN in program-libs/interface/src/proof/audit_stream.rs.
const MergeRecordLen = RecordLen + fieldLen

// A zero key's merge seed reaches the auditor through the record alone.
type MergeRecord struct {
	RecordOpening
	// A clear Live seals zero.
	Seed frontend.Variable
}

// Encode mirrors MergeRecord::encode in program-libs/interface/src/proof/audit_stream.rs.
func (o MergeRecord) Encode(api frontend.API, rc frontend.Rangechecker) []frontend.Variable {
	seed := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(o.Live, o.Seed))
	return slices.Concat(o.RecordOpening.Encode(api, rc), seed[:])
}

type EntryWires struct {
	OwnerKey   [32]frontend.Variable
	MintChunks [2]frontend.Variable
}

// SPP publishes nullifiers without input class labels, and the ring proof reads none of them. The
// input section holds the spent notes in SPP's note order with dummies last, so position k is note k.
// The auditor links a spent ring note by reconstructing its nullifier from an earlier opening and the
// owner's escrowed secret, and classifies the rest of SPP's list from its own address index. R tells it
// how many notes to find. A default ring note can lack an earlier ring record, so its entry record names
// the note beside its spent commitment, never its blinding.
type SpentInputs struct {
	Slots []shared.Output
	// The published n, R may sit below it.
	Count   ringgadget.Count
	Entries []EntryWires
}

type evidence struct {
	head       []frontend.Variable
	entries    [][]frontend.Variable
	realInputs frontend.Variable
}

// evidence mirrors AuditEnvelope::encode in program-libs/interface/src/proof/audit_stream.rs past the sealed key.
func (s SpentInputs) evidence(api frontend.API, rc frontend.Rangechecker, ranges StreamRanges) evidence {
	if len(s.Slots) != ranges.InputClass {
		panic("audit: the input section differs from the key's class")
	}
	// 1. R reads the note selectors already bound by the input section.
	realInputs := frontend.Variable(0)
	defaults := make([]frontend.Variable, len(s.Slots))
	for i, slot := range s.Slots {
		realInputs = api.Add(realInputs, slot.Utxo)
		defaults[i] = slot.Exit
	}
	head := ringgadget.UintBytesBE(api, realInputs, RealInputCountLen)
	// 2. A default ring note can lack an earlier ring record, so the entry key must supply its record.
	if !ranges.Entry {
		for _, slot := range s.Slots {
			api.AssertIsEqual(slot.Exit, 0)
		}
		return evidence{head: head, realInputs: realInputs}
	}
	if len(s.Entries) != len(s.Slots) {
		panic("audit: an entry key needs one evidence wire per input")
	}
	// 3. Exit is a note selector, so a default bit cannot select a dummy.
	// Each record keeps its note position and is zero unless the same default bit is set.
	head = slices.Concat(head, ringgadget.UintBytesBE(api, weightedBits(api, defaults), DefaultInputBitsLen))
	entries := make([][]frontend.Variable, len(s.Slots))
	for i, slot := range s.Slots {
		entries[i] = s.Entries[i].encode(api, rc, slot)
	}
	return evidence{head: head, entries: entries, realInputs: realInputs}
}

// encode mirrors EntryRecord::extend in program-libs/interface/src/proof/audit_stream.rs, zero off a default-ring note.
func (e EntryWires) encode(api frontend.API, rc frontend.Rangechecker, slot shared.Output) []frontend.Variable {
	live := slot.Exit
	// Per input owner and key, mixed owners read apart with no nullifier secret disclosed.
	raw := identityOpening{Live: live, OwnerPkHash: slot.OwnerPkHash, Asset: slot.Asset, OwnerKey: e.OwnerKey, MintChunks: e.MintChunks}.open(api)
	field := func(value frontend.Variable) []frontend.Variable {
		bytes := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(live, value))
		return bytes[:]
	}
	// slot.Hash is the commitment private_tx_hash chains at the note position, every other field binds to its preimage.
	return slices.Concat(
		raw.ownerKey, field(slot.NullifierPk),
		ringgadget.UintBytesBE(api, api.Mul(live, slot.Amount), amountLen),
		raw.mint, field(slot.Hash),
	)
}

func weightedBits(api frontend.API, bits []frontend.Variable) frontend.Variable {
	bitmap := frontend.Variable(0)
	for i, bit := range bits {
		bitmap = api.Add(bitmap, api.Mul(bit, uint64(1)<<i))
	}
	return bitmap
}
