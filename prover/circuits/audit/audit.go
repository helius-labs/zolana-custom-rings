// Package audit proves what a ring auditor reads from a ring transfer.
//
// SPP gives an auditor nothing to read. Its transfer proof hides every opening behind the output
// hashes, and its external data hash binds the ciphertext bytes a sender submits with no claim about
// what they contain. A ring must let its auditor open every note it settles, so the ring proof adds
// one AES stream sealed to the auditor and ties its plaintext to SPP's published hashes. Without
// these constraints a sender could settle a note no auditor can read.
//
// Sealing. The stream needs no key of its own. SPP publishes a tx_viewing_pk per transaction, and the
// program feeds its coordinate tx_u to SPP's external data hash and to the ring statement from the same
// frame bytes. tx_viewing_sk is the ephemeral key of the auditor's agreement, and the plaintext opens
// with tx_viewing_sk itself.
//
// One sealed key opens every blinding. SPP holds each output blinding to
// TXOB(n0, TXOS(n0, BlindingSeed), i), with BlindingSeed a free private input. The ring holds the same
// wire to that derivation at BlindingSeed = CRBS(tx_viewing_sk, salt). Both proofs hash the blinding
// into the one output hash, so a Poseidon collision aside SPP's seed is the ring's, and a record
// carries no blinding.
//
// The auditor reads a transfer in three steps.
//  1. X25519(auditor_sk, tx_u) and the salt give the stream's key and nonce.
//  2. The envelope gives tx_viewing_sk, note count R, absolute address bitmap A and any entry evidence.
//  3. Each record, its tail, the derived blinding and the frame's tree id rebuild that slot's
//     published hash. A dummy's record is zero and its hash rebuilds from the blinding and the
//     frame's tree id.
//
// A statement built on the package proves the following.
//  1. The stream is AES-256-CTR under a key schedule bound to the auditor key, tx_u and the salt,
//     over the sealed tx_viewing_sk, R, A, the entry evidence, one record per slot and one tail per slot.
//  2. Each live slot's record and tail hold the opening its published commitment hashes, and a
//     published slot's blinding derives from the sealed key. The auditor rebuilds every commitment
//     from the stream and the frame.
//  3. R counts spent notes and A selects address positions among the published inputs. Entry evidence
//     opens each default ring note at its absolute input position, with zero openings elsewhere.
//  4. A slot's kind derives from the domain and ring id its hash commits, no prover bit passes a note
//     as a dummy.
//  5. Every transmitted ciphertext byte is bound, the envelope through its counted digest and each
//     record and tail through its chain.
//
// It proves nothing about a recipient's body or tag, delivery stays outside the circuit. Those bytes
// reach the proof only under SPP's external data hash, as on SPP, and no constraint reads them. A
// transfer with a correct proof can therefore carry a body its recipient cannot open. The sender wants
// its payment received, and delivery stays its own incentive. A bad body credits nobody, since a
// reader accepts a note only when the commitment rebuilds under its own keys, and a full scan repairs
// a bad tag. The auditor's copy is the proven one and holds the opening whatever the body says, and
// Ring RPC can return it to the authorized owner. Nothing here promises delivery to an owner who has
// no Ring RPC.
//
// It proves nothing about the freshness of tx_viewing_sk or the salt, see shared.Envelope.
//
// Read after transfer/transfer.go, shared/envelope.go, shared/derivation.go, shared/utxo.go,
// audit/layout.go. Read before audit/record.go, transfer/input.go.
package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// AuditWires are the values one stream reads. Head binds all but TxViewingSk, and the program
// rebuilds the bound values from the frame, its own program id and the ring's configured auditor key.
type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingProgramID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingProgramID frontend.Variable
	TxViewingSk   [32]frontend.Variable
	AuditorPk     [32]frontend.Variable
	Salt          [16]frontend.Variable
	Layout        frontend.Variable
}

type Envelope struct {
	// txPk is pack_be(0x04 ‖ tx_u).
	txPk       [2]frontend.Variable
	salt       frontend.Variable
	outputSeed frontend.Variable
}

func (w AuditWires) OpenEnvelope(api frontend.API, rc frontend.Rangechecker) Envelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. An unclamped alias keeps tx_u and the stream key under another CRBS seed, and the reader refuses it.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_viewing_sk, the generator bounds every secret byte the packings read.
	txPk := shared.PackedKey(api, x25519.ScalarMulGenerator(api, w.TxViewingSk))
	packedTxViewingSk := [2]frontend.Variable(shared.PackBounded(api, w.TxViewingSk[:]))
	// 4. outputSeed is SPP's TXOS(n0, BlindingSeed) at the ring's seed, its inputs are the sealed key and two values the frame publishes.
	return Envelope{
		txPk:       [2]frontend.Variable(txPk),
		salt:       salt,
		outputSeed: transaction.DeriveOutputBlindingSeed(api, w.FirstNullifier, shared.BlindingSeed(api, packedTxViewingSk, salt)),
	}
}

// AssertClamped pins the RFC 7748 clamped encoding, the one byte string per X25519 key.
func AssertClamped(api frontend.API, secret [32]frontend.Variable) {
	low := api.ToBinary(secret[0], 8)
	high := api.ToBinary(secret[31], 8)
	// Bits 0 to 2 are clear, the scalar is a multiple of the cofactor.
	for _, bit := range low[:3] {
		api.AssertIsEqual(bit, 0)
	}
	// Bit 254 is set and bit 255 is clear, the top RFC 7748 fixes.
	api.AssertIsEqual(high[6], 1)
	api.AssertIsEqual(high[7], 0)
}

// Opened holds every output slot once, every section reads these wires.
type Opened struct {
	Slots []shared.Output
	Count ringgadget.Count
	// OutputChain covers every published slot hash, a dummy's included, zero past m as SPP's padded chain reads.
	OutputChain frontend.Variable
	hasData     frontend.Variable
	records     [][]frontend.Variable
	tails       [][]frontend.Variable
	commonMint  []frontend.Variable
}

// OpenSlots holds each output wire to the hash SPP publishes, so a later section reads the note that settles.
func (s StreamShape) OpenSlots(api frontend.API, rc frontend.Rangechecker, w AuditWires, e Envelope, hasData frontend.Variable, outputs []OutputWires, outputCount frontend.Variable) Opened {
	// 1. m selects the published slots, a key's capacity may exceed it and a slot past it publishes nothing.
	if s.SingleAssetPayout {
		api.AssertIsEqual(outputCount, s.Outputs)
		api.AssertIsEqual(hasData, 0)
	}
	count := ringgadget.SelectCount(api, outputCount, 1, len(outputs))
	opened := Opened{Slots: make([]shared.Output, len(outputs)), Count: count, hasData: hasData, records: make([][]frontend.Variable, len(outputs))}
	hashes := make([]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot := output.Output.Open(api)
		active := count.Active[i]
		// 2. An omitted slot holds no note, SPP's padded chain would miss it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: slot.Utxo})
		// 3. The auditor rebuilds every commitment from the sealed key's blinding, another value leaves the slot unopened.
		w.AssertBlinding(api, e, slot, active, i)
		// 4. A clear has_data transmits no tail, a nonzero data hash would leave the commitment unrebuilt.
		assertNoData(api, hasData, slot)
		// 5. The plaintext reads the opened wires, SealStream seals them with no second opening to disagree.
		record := output.record(api, rc, slot)
		if s.SingleAssetPayout {
			api.AssertIsEqual(slot.Ring, 1)
			api.AssertIsEqual(slot.Asset, outputs[0].Output.Asset)
			if i == 0 {
				opened.commonMint = record[recordMintStart:recordMintEnd]
			}
			record = slices.Concat(record[:recordMintStart], record[recordMintEnd:RecordLen], shared.Zeros(PayoutRecordStride-PayoutRecordLen))
		} else {
			opened.tails = append(opened.tails, dataTail(api, rc, slot))
		}
		opened.records[i] = record
		opened.Slots[i], hashes[i] = slot, api.Mul(active, slot.Hash)
	}
	// 6. The program rebuilds the chain from the hashes it forwards to SPP, one opening off them fails the statement.
	opened.OutputChain = gadget.HashChain4(api, hashes)
	return opened
}

// AssertBlinding holds a published dummy's blinding too, an all dummy transfer has no other link to SPP's seed.
func (w AuditWires) AssertBlinding(api frontend.API, e Envelope, slot shared.Output, active frontend.Variable, i int) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: slot.Blinding, B: transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)})
}

type Stream struct {
	sealed shared.Sealed
	digest frontend.Variable
	// RecordChain hashes every published record's ciphertext, zero past m.
	RecordChain frontend.Variable
	// TailChain hashes every published tail's ciphertext, zero while has_data is clear.
	TailChain frontend.Variable
	// NoSpend is set at a zero R, address authorization remains with SPP.
	NoSpend frontend.Variable
}

// SealStream mirrors AuditEnvelope::encode and the record layout in program-libs/interface/src/proof/audit_stream.rs.
func (w AuditWires) SealStream(api frontend.API, rc frontend.Rangechecker, e Envelope, shape StreamShape, opened Opened, spent SpentInputs) Stream {
	ranges := shape.Ranges()
	// 1. The envelope binds tx_viewing_sk, the note count and absolute address positions before any entry openings.
	evidence := spent.evidence(api, rc, ranges)
	head := slices.Concat(evidence.head, opened.commonMint)
	plaintext := slices.Concat(w.TxViewingSk[:], head, slices.Concat(evidence.entries...))
	// The envelope's padding ends on the block before R0, the longest evidence never reaches a record's counter.
	plaintext = append(plaintext, shared.Zeros(ranges.EnvelopeBlocks()*streamBlockLen-len(plaintext))...)
	// A record holds its blocks alone, a counter serving two regions reveals the XOR of their plaintexts.
	plaintext = slices.Concat(plaintext, slices.Concat(opened.records...), slices.Concat(opened.tails...))
	// A plaintext off its ranges moves every record off the counters the readers use.
	if len(plaintext) != ranges.CapacityBlocks()*streamBlockLen {
		panic("audit: the stream plaintext differs from its ranges")
	}
	// 2. One key expansion and nonce cover every block, the cipher's tables bound every plaintext and ciphertext byte.
	// tx_viewing_sk is the ephemeral key and txPk its public key, a resend under one first nullifier repeats
	// both, and the salt in the schedule keeps its keystream apart.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: w.TxViewingSk, AuditorPk: w.AuditorPk, Info: shared.AuditEncInfo}.SealSalted(api, e.txPk[:], e.salt)
	// 3. Padding and unpublished slots never leave the prover, the statement binds only what the frame transmits.
	// The program hashes those bytes in one form per region, the envelope's length moves with n and each
	// record and tail has one length.
	return Stream{
		sealed:      sealed,
		digest:      countedDigest(api, sealed.Ciphertext, EnvelopeKeyLen+len(head), ranges.entryLen(), spent.Count),
		RecordChain: gadget.HashChain4(api, SlotRegions{Start: ranges.RecordOffset(0), Stride: ranges.RecordStride(), Length: ranges.RecordLen()}.Hashes(api, sealed.Ciphertext, opened.Count.Active)),
		TailChain:   tailChain(api, sealed.Ciphertext, ranges, opened),
		NoSpend:     api.IsZero(evidence.realInputs),
	}
}

// SlotRegions locates one ciphertext region per slot inside a sealed stream.
type SlotRegions struct {
	Start, Stride, Length int
}

// Hashes is hash_bytes(region_i) per slot, zero while the slot's flag is clear, the one form every statement binds a slot's ciphertext in.
func (r SlotRegions) Hashes(api frontend.API, ciphertext, active []frontend.Variable) []frontend.Variable {
	hashes := make([]frontend.Variable, len(active))
	for i, flag := range active {
		offset := r.Start + i*r.Stride
		hashes[i] = api.Mul(flag, gadget.HashBoundedBytes(api, ciphertext[offset:offset+r.Length]))
	}
	return hashes
}

func tailChain(api frontend.API, ciphertext []frontend.Variable, ranges StreamRanges, opened Opened) frontend.Variable {
	if ranges.SingleAssetPayout {
		return 0
	}
	// A clear has_data transmits no tail, the program binds zero.
	return api.Mul(opened.hasData, gadget.HashChain4(api, SlotRegions{Start: ranges.TailOffset(0), Stride: TailLen, Length: TailLen}.Hashes(api, ciphertext, opened.Count.Active)))
}

// countedDigest mirrors ciphertext_digest in program-libs/interface/src/proof/statement.rs over the head and the count's entries.
func countedDigest(api frontend.API, ciphertext []frontend.Variable, head, entry int, count ringgadget.Count) frontend.Variable {
	transmitted := slices.Clone(ciphertext[:head+len(count.Active)*entry])
	// 1. An entry at or past the count packs as zero, the chunk the cut falls in then equals pack_left31 of the transmitted bytes.
	for i, active := range count.Active {
		offset := head + i*entry
		copy(transmitted[offset:], masked(api, active, transmitted[offset:offset+entry]))
	}
	fields := shared.PackDisclosure(api, transmitted)
	// 2. SelectCount sets exactly one candidate, its flag falls on the last chunk of that count's bytes and HashPrefix4 ends the chain there.
	ends := shared.Zeros(len(fields))
	length := frontend.Variable(0)
	for k, selected := range count.OneHot {
		byteLen := head + count.Candidate(k)*entry
		last := (byteLen+gadget.HashBytesChunkSize-1)/gadget.HashBytesChunkSize - 1
		ends[last] = api.Add(ends[last], selected)
		length = api.Add(length, api.Mul(selected, byteLen))
	}
	// 3. The tag is the selected count's transmitted length, two counts whose chains agree over trailing zero bytes hash apart.
	return gadget.PoseidonHash(api, []frontend.Variable{length, ringgadget.HashPrefix4(api, fields, ends)})
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}

// Head opens every audit statement under domain, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs. The stream's ephemeral key is tx_u, txPk already binds it.
func (e Envelope) Head(w AuditWires, s Stream, domain frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{domain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1]},
		s.sealed.Auditor,
		[]frontend.Variable{s.digest, e.salt, w.Layout},
	)
}
