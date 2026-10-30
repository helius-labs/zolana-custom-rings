// Package audit proves what a ring auditor reads from a ring transfer.
package audit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type AnonymousAuditShape struct {
	InputClass   int
	Outputs      int
	FullOpenings bool
}

// layout is the flags the shape fixes.
func (s AnonymousAuditShape) layout() int {
	if s.FullOpenings {
		return LayoutFullOpenings
	}
	return 0
}

func (s AnonymousAuditShape) senderKeyLen() int {
	if s.FullOpenings {
		return 32
	}
	return 0
}

// Audit key shapes, mirrored by the audit capacities and the anonymous classes of program-libs/interface/src/proof/disclosure.rs.
var (
	// DeliveredAuditCapacities prove every confidential and delegate body.
	DeliveredAuditCapacities = [...]int{2, 4, 8, 16}
	// AnonymousAuditShapes name spent notes by hash and prefix, a transfer takes the smallest class holding its published inputs.
	AnonymousAuditShapes = [...]AnonymousAuditShape{
		{InputClass: 4, Outputs: 2}, {InputClass: 16, Outputs: 2},
		{InputClass: 4, Outputs: 4}, {InputClass: 16, Outputs: 4},
		{InputClass: 4, Outputs: 8}, {InputClass: 8, Outputs: 8},
	}
	// AnonymousEntryShapes open every spent UTXO, the keys of a transfer that spends a default-ring note.
	AnonymousEntryShapes = [...]AnonymousAuditShape{
		{InputClass: 8, Outputs: 2, FullOpenings: true},
		{InputClass: 8, Outputs: 4, FullOpenings: true},
		{InputClass: 8, Outputs: 8, FullOpenings: true},
	}
)

type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingProgramID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingProgramID frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
	AuditorPk     [32]frontend.Variable
	Salt          [16]frontend.Variable
	Layout        frontend.Variable
}

type auditEnvelope struct {
	txViewingSk [32]frontend.Variable
	// txPk is pack_be(0x04 ‖ tx_u).
	txPk [2]frontend.Variable
	// packedTxViewingSk is pack_be(tx_viewing_sk), the key of the CRBS blinding seed and the CROD pad.
	packedTxViewingSk [2]frontend.Variable
	salt              frontend.Variable
	outputSeed        frontend.Variable
	sealed            shared.Sealed
	sealedHash        frontend.Variable
}

type outputSlot struct {
	shared.OpenedUtxo
	live frontend.Variable
	ring frontend.Variable
	exit frontend.Variable
}

// sealEnvelope binds tx_viewing_sk to its tagged public key and seals it to the auditor.
func (w AuditWires) sealEnvelope(api frontend.API, rc frontend.Rangechecker) auditEnvelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_viewing_sk, the generator bounds every secret byte the packings read.
	txPk := shared.PackBounded(api, TaggedPubkey(api, w.TxViewingSk))
	// 4. The envelope seals tx_viewing_sk to the auditor under the audit stream schedule.
	sealed := shared.Envelope{Plaintext: w.TxViewingSk[:], EphSk: w.EphSk, AuditorPk: w.AuditorPk}.SealAuditStream(api)
	packedTxViewingSk := [2]frontend.Variable(shared.PackBounded(api, w.TxViewingSk[:]))
	return auditEnvelope{
		txViewingSk:       w.TxViewingSk,
		txPk:              [2]frontend.Variable(txPk),
		packedTxViewingSk: packedTxViewingSk,
		salt:              salt,
		outputSeed:        transaction.DeriveOutputBlindingSeed(api, w.FirstNullifier, shared.BlindingSeed(api, packedTxViewingSk, salt)),
		sealed:            sealed,
		// The cipher's byte tables bound every ciphertext byte.
		sealedHash: gadget.HashBoundedBytes(api, sealed.Ciphertext),
	}
}

func classify(api frontend.API, o shared.UtxoWires, opened shared.OpenedUtxo, live frontend.Variable) outputSlot {
	// SPP holds every UTXO's ring id to 0 or the ring's on the same output hashes, AssertRingMemberOrFree in spp_transaction/shared/ring.go.
	ring := api.Mul(live, ringgadget.IsNonZero(api, o.RingProgramID))
	return outputSlot{OpenedUtxo: opened, live: live, ring: ring, exit: api.Sub(live, ring)}
}

// assertBlinding pins a live UTXO's blinding to SPP's TXOB blinding over the seed tx_viewing_sk fixes.
func (w AuditWires) assertBlinding(api frontend.API, e auditEnvelope, o shared.UtxoWires, slot outputSlot, i int) {
	blinding := transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.live, A: o.Blinding, B: blinding})
}

// statementHead opens every audit statement, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs.
//
//	CRAU, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout
func (e auditEnvelope) statementHead(w AuditWires) []frontend.Variable {
	return []frontend.Variable{
		shared.AuditStatementDomain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1],
		e.sealed.Auditor[0], e.sealed.Auditor[1], e.sealed.Eph[0], e.sealed.Eph[1], e.sealedHash, e.salt, w.Layout,
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

// TaggedPubkey is 0x04 ‖ u of the clamped secret, the generator gadget bounds every secret byte.
func TaggedPubkey(api frontend.API, secret [32]frontend.Variable) []frontend.Variable {
	return shared.Tagged(x25519.ScalarMulGenerator(api, secret))
}

// uintBytes is the big-endian encoding of an unsigned value below 2^(8n), a larger value fails the decomposition.
func uintBytes(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, 8*n))
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}
