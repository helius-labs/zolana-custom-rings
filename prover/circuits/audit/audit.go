// Package audit proves what a ring auditor and each recipient read from a ring transfer.
//
// SPP gives a reader nothing to read. Its transfer proof hides every opening behind the output
// hashes, and its external data hash binds the ciphertext bytes a sender submits with no claim about
// what they contain. A ring must let its auditor open every note it settles, so the ring proof seals
// one record per output slot and ties its plaintext to SPP's published hashes. The same record is the
// recipient's delivery. Without these constraints a sender could settle a note no auditor can read.
//
// Sealing. No ciphertext needs a key of its own. SPP publishes a tx_viewing_pk per transaction, and
// the program feeds its coordinate tx_u to SPP's external data hash and to the ring statement from the
// same frame bytes. tx_viewing_sk is the ephemeral key of every agreement. Record i is sealed by
// X25519(tx_viewing_sk, V_i) to the recipient key V_i the sender supplies. The auditor stream is sealed
// by X25519(tx_viewing_sk, auditor_u) and carries tx_viewing_sk and every V_i.
//
// One sealed key opens every blinding. SPP holds each output blinding to
// TXOB(n0, TXOS(n0, BlindingSeed), i) and its private_tx_blinding to TXPB(n0, BlindingSeed), with
// BlindingSeed a free private input. The ring derives private_tx_blinding as TXPB(n0, CRBS(tx_viewing_sk,
// salt)) and both proofs open the one public private_tx_hash, so a Poseidon collision aside SPP's seed is
// the ring's and n0 is SPP's first nullifier. Real output slots open the output chain of private_tx_hash
// in order, and both proofs place dummies last, so ring slot i is SPP slot i and its blinding is SPP's.
//
// The auditor reads a transfer in three steps.
//  1. X25519(auditor_sk, tx_u) and the salt give the stream's key and nonce.
//  2. The envelope gives tx_viewing_sk, note count R and any entry evidence, the key region each V_i.
//  3. X25519(tx_viewing_sk, V_i) opens record i, and the record, the frame's tree id and the payload's
//     data hashes rebuild that slot's published hash. A dummy's record is zero and its hash rebuilds from
//     the derived blinding and the frame's tree id.
//
// A statement built on the package proves the following.
//  1. The auditor stream is AES-256-CTR under a key schedule bound to the auditor key, tx_u and the salt,
//     over the sealed tx_viewing_sk, R, the entry evidence and one recipient key per slot.
//  2. Each record is AES-256-CTR under the slot secret of tx_viewing_sk and that slot's sealed key.
//  3. Each live slot's record holds the opening its published commitment hashes, but for the data hashes.
//  4. Slots are notes or dummies, dummies last, and a dummy carries nothing but its blinding.
//  5. R counts spent notes. An entry record names each default ring note's owner, nullifier key, amount,
//     mint and spent commitment at its note position, with zero records elsewhere.
//  6. A slot's kind derives from the domain and ring id its hash commits, no prover bit passes a note
//     as a dummy.
//  7. Every transmitted ciphertext byte is bound, the envelope and keys through their counted digests and
//     each record through the record chain.
//
// It proves nothing about the key a sender supplies for a recipient, as SPP proved nothing about a
// body. A record sealed to another key credits nobody, since a reader accepts a note only when the
// commitment rebuilds under its own keys. The auditor's reading needs no correct V_i choice, it reads
// each V_i from the stream. It proves nothing about a data payload, a tag or a reply, SPP's external
// data hash binds those bytes alone.
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
	txPk [2]frontend.Variable
	salt frontend.Variable
	// PrivateTxBlinding is SPP's TXPB(n0, BlindingSeed) at the ring's seed, the last preimage element of private_tx_hash.
	PrivateTxBlinding frontend.Variable
}

func (w AuditWires) OpenEnvelope(api frontend.API, rc frontend.Rangechecker) Envelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. An unclamped alias keeps tx_u and the stream key under another CRBS seed, and the reader refuses it.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_viewing_sk, the generator bounds every secret byte the packings read.
	txPk := shared.PackedKey(api, x25519.ScalarMulGenerator(api, w.TxViewingSk))
	packedTxViewingSk := [2]frontend.Variable(shared.PackBounded(api, w.TxViewingSk[:]))
	// 4. Through private_tx_hash the blinding fixes SPP's seed to the sealed key's and SPP's n0 to FirstNullifier, and SPP derives every output blinding from both.
	return Envelope{
		txPk:              [2]frontend.Variable(txPk),
		salt:              salt,
		PrivateTxBlinding: transaction.DerivePrivateTxBlinding(api, w.FirstNullifier, shared.BlindingSeed(api, packedTxViewingSk, salt)),
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
	Slots   []shared.Output
	Count   ringgadget.Count
	records [][]frontend.Variable
	keys    [][32]frontend.Variable
}

// OpenSlots opens each output wire and holds the slots to SPP's output form, so a later section reads the note that settles.
func (s StreamShape) OpenSlots(api frontend.API, rc frontend.Rangechecker, outputs []OutputWires, outputCount frontend.Variable) Opened {
	// 1. m selects the published slots, a key's capacity may exceed it and a slot past it publishes nothing.
	count := ringgadget.SelectCount(api, outputCount, 1, len(outputs))
	opened := Opened{Slots: make([]shared.Output, len(outputs)), Count: count, records: make([][]frontend.Variable, len(outputs)), keys: make([][32]frontend.Variable, len(outputs))}
	ordered := make([]transaction.UtxoCircuitFields, len(outputs))
	for i, output := range outputs {
		// 2. Dummies stay off the output chain, the slot form alone keeps them empty.
		slot := output.Output.OpenSlot(api)
		ordered[i] = transaction.UtxoCircuitFields{Domain: slot.Domain}
		// 3. An omitted slot holds no note, SPP's compact slots publish none.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, count.Active[i]), V: slot.Utxo})
		// 4. The plaintext reads the opened wires, RecordChain seals them with no second opening to disagree.
		opened.records[i] = output.record(api, rc, slot)
		opened.keys[i] = output.RecipientKey
		opened.Slots[i] = slot
	}
	// 5. SPP holds its own outputs dummies last, so equal output chains place every real slot at one index on both sides.
	transaction.AssertDummiesLast(api, ordered)
	return opened
}

// RecordChain seals each slot's record to its recipient key and returns the chain the program rebuilds from the transmitted records.
func (w AuditWires) RecordChain(api frontend.API, e Envelope, opened Opened) frontend.Variable {
	hashes := make([]frontend.Variable, len(opened.records))
	for i, record := range opened.records {
		// The index and n0 enter the slot secret, two slots to one key never share a keystream.
		ciphertext := shared.SlotSeal{
			Plaintext: record, EphSk: w.TxViewingSk, Eph: e.txPk[:], RecipientPk: opened.keys[i],
			Salt: e.salt, Index: i, FirstNullifier: w.FirstNullifier, Info: shared.OutputRecordInfo,
		}.Seal(api)
		// A slot past m publishes nothing.
		hashes[i] = api.Mul(opened.Count.Active[i], gadget.HashBoundedBytes(api, ciphertext))
	}
	return gadget.HashChain4(api, hashes)
}

type Stream struct {
	sealed shared.Sealed
	digest frontend.Variable
	// NoSpend is set at a zero R, address authorization remains with SPP.
	NoSpend frontend.Variable
}

// SealStream mirrors AuditEnvelope::encode and AuditStreamLayout in program-libs/interface/src/proof/audit_stream.rs.
func (w AuditWires) SealStream(api frontend.API, rc frontend.Rangechecker, e Envelope, shape StreamShape, opened Opened, spent SpentInputs) Stream {
	ranges := shape.Ranges()
	// 1. The envelope binds tx_viewing_sk and the note count before any entry records.
	evidence := spent.evidence(api, rc, ranges)
	plaintext := slices.Concat(w.TxViewingSk[:], evidence.head, slices.Concat(evidence.entries...))
	// The envelope's padding ends on the block before the first key, the longest evidence never reaches a key's counter.
	plaintext = append(plaintext, shared.Zeros(ranges.EnvelopeBlocks()*streamBlockLen-len(plaintext))...)
	// 2. One key per slot on its own blocks, the auditor reads V_i with no directory.
	for _, key := range opened.keys {
		plaintext = append(plaintext, key[:]...)
	}
	// A plaintext off its ranges moves every key off the counters the readers use.
	if len(plaintext) != ranges.CapacityBlocks()*streamBlockLen {
		panic("audit: the stream plaintext differs from its ranges")
	}
	// 3. One key expansion and nonce cover every block, the cipher's tables bound every plaintext and ciphertext byte.
	// tx_viewing_sk is the ephemeral key and txPk its public key, a resend under one first nullifier repeats
	// both, and the salt in the schedule keeps its keystream apart.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: w.TxViewingSk, AuditorPk: w.AuditorPk, Info: shared.AuditEncInfo}.SealSalted(api, e.txPk[:], e.salt)
	// 4. Padding and unpublished slots never leave the prover, the program digests the envelope over n and the keys over m.
	head := EnvelopeKeyLen + len(evidence.head)
	keys := sealed.Ciphertext[ranges.KeyOffset(0):]
	return Stream{
		sealed: sealed,
		digest: gadget.PoseidonHash(api, []frontend.Variable{
			countedDigest(api, sealed.Ciphertext, head, ranges.entryLen(), spent.Count),
			countedDigest(api, keys, 0, KeyLen, opened.Count),
		}),
		NoSpend: api.IsZero(evidence.realInputs),
	}
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
