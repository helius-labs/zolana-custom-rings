// Seals a ciphertext to the ring's auditor inside the proof.
//
// SPP's transfer proof binds its ciphertext as bytes and proves nothing about what they decrypt to. An
// auditor must read what the ring proof claims, so here the key, the nonce and every AES block are
// constraints. The cipher has no authentication tag. Integrity comes from the statement, it hashes the
// ciphertext and the program rebuilds that hash from the instruction.
//
// The schedule is mirrored by sdk-libs/client/src/crypto/encryption/mod.rs and RingStream::new in
// sdk-libs/keys/src/stream_cipher.rs.
//
//	dh     = X25519(eph_sk, auditor_u)
//	secret = Poseidon(CR_S, pack_be(dh), pack_be(0x04 ‖ eph_u), pack_be(0x04 ‖ auditor_u))
//	salted = Poseidon(secret, salt), on a salted stream alone
//	head   = Poseidon(label ‖ 0x00, secret or salted)
//	tail   = Poseidon(label ‖ 0x01, secret or salted)
//	key    = low31_be(head) ‖ low13_be(tail)[0]
//	nonce  = low13_be(tail)[1..13]
//	ct     = AES-256-CTR(key, nonce ‖ u32_be(counter), plaintext), counter from 2
//
// The schedule is Poseidon where SPP runs HKDF off chain, since the proof must derive the key. Each
// step answers one failure.
//  1. The auditor key is canonical, so the bytes the program configures are the ones the agreement
//     read. The gadget also refuses a zero agreement.
//  2. secret binds both public keys, an agreement that repeats under another key pair gives another secret.
//  3. A transfer's ephemeral key is SPP's tx_viewing_sk, derived per first nullifier, and a resend under
//     that nullifier repeats it. The SDKs draw the salt fresh per build, and it keeps the keystream
//     apart as it does in SPP's own schedule.
//  4. One Poseidon output holds under 32 bytes, so two give the 44 bytes of key and nonce.
//  5. The low bytes are those of the canonical field value. An alias at value + q would give the prover
//     a second key no reader derives, the ciphertext would pass its statement and decrypt to noise.
//  6. The label enters the first input, one secret gives one key and nonce per ciphertext kind.
//  7. AES-CTR starts at counter 2 in SPP's gadget, and every reader starts there.
//
// The file proves the following.
//  1. Ciphertext is AES-256-CTR of Plaintext under the schedule above, with every byte below 2^8.
//  2. The agreement is the one between EphSk and AuditorPk. The auditor's secret opens it from eph_u
//     when eph_u is EphSk's key, SealStream derives that key and a SealSalted caller holds it.
//  3. Auditor and Eph hold the packed keys that schedule read.
//
// Read after shared/disclosure.go, ringgadget/bytes.go, shared/derivation.go.
// Read before audit/audit.go, merge.go, registry/register_key.go.

package shared

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// EphSk must be fresh per envelope or per SealSalted salt, a reuse under one auditor key repeats the keystream.
// No constraint holds that freshness, a circuit sees no earlier envelope. A prover that reuses a key reveals the XOR of its own plaintexts to any chain reader, each ciphertext still decrypts to what its proof sealed.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	Info      string
}

// Every Ciphertext byte is bounded to 8 bits by the cipher's tables.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

// SealStream starts at counter 2, the readers start there.
func (e Envelope) SealStream(api frontend.API) Sealed {
	// The X25519 gadgets bound every key byte and return canonical bytes, the packings need no byte check.
	sealed, secret := e.agree(api, PackedKey(api, x25519.ScalarMulGenerator(api, e.EphSk)))
	return e.seal(api, sealed, secret)
}

// SealSalted takes eph as the packed key of EphSk, a resend repeats EphSk and the salt keeps its keystream apart.
func (e Envelope) SealSalted(api frontend.API, eph []frontend.Variable, salt frontend.Variable) Sealed {
	sealed, secret := e.agree(api, eph)
	return e.seal(api, sealed, gadget.PoseidonHash(api, []frontend.Variable{secret, salt}))
}

func (s Sealed) StatementFields(api frontend.API) []frontend.Variable {
	return append(slices.Concat(s.Auditor, s.Eph), gadget.HashBoundedBytes(api, s.Ciphertext))
}

func (e Envelope) agree(api frontend.API, eph []frontend.Variable) (Sealed, frontend.Variable) {
	// One encoding per auditor key, the program packs the configured key bytes as they are.
	agreement := AgreeCanonical(api, e.EphSk, e.AuditorPk)
	sealed := Sealed{Auditor: PackedKey(api, e.AuditorPk), Eph: eph}
	// Binding both keys keeps the key schedule input from replaying under another key pair.
	return sealed, gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{uint64(DomSepCRShared)}, PackBounded(api, agreement[:]), sealed.Eph, sealed.Auditor,
	))
}

func (e Envelope) seal(api frontend.API, sealed Sealed, secret frontend.Variable) Sealed {
	// The cipher's byte tables bound every plaintext byte.
	key, nonce := AuditStreamKeySchedule(api, secret, e.Info)
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}

// SlotSeal keys its stream with DeliveredSlot::secret in program-libs/interface/src/codec/stream.rs, no constraint ties recipient_u to the intended recipient.
//
//	dh     = X25519(eph_sk, recipient_u)
//	secret = Poseidon(CRDS, pack_be(dh), Eph, pack_be(0x04 ‖ recipient_u), salt, index, n0)
type SlotSeal struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	// Eph is pack_be(0x04 ‖ eph_u), the caller holds it to EphSk.
	Eph         []frontend.Variable
	RecipientPk [32]frontend.Variable
	// Index and FirstNullifier part two slots of one key pair, a shared keystream would reveal the XOR of their records.
	Salt, Index, FirstNullifier frontend.Variable
	Info                        string
}

// Seal returns the ciphertext from counter 2, every byte below 2^8.
func (s SlotSeal) Seal(api frontend.API) []frontend.Variable {
	// A low order recipient_u yields a zero agreement, refused here, else anyone opens the record.
	agreement := AgreeCanonical(api, s.EphSk, s.RecipientPk)
	secret := gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{uint64(DeliveredSlotDomain)}, PackBounded(api, agreement[:]), s.Eph, PackedKey(api, s.RecipientPk),
		[]frontend.Variable{s.Salt, s.Index, s.FirstNullifier},
	))
	key, nonce := AuditStreamKeySchedule(api, secret, s.Info)
	return aes.NewCipher(api, key).CTREncrypt(nonce, s.Plaintext)
}

// AuditStreamKeySchedule mirrors RingStream::new in sdk-libs/keys/src/stream_cipher.rs, the label separates every ring line over one secret.
func AuditStreamKeySchedule(api frontend.API, secret frontend.Variable, label string) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	rc := rangecheck.New(api)
	tag := func(counter byte) *big.Int {
		return new(big.Int).SetBytes(append([]byte(label), counter))
	}
	// FieldLowBytesBE reads the canonical value, the reader's own Poseidon output holds no alias.
	head := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(0), secret}), 31)
	tail := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(1), secret}), 13)
	copy(key[:31], head)
	key[31] = tail[0]
	copy(nonce[:], tail[1:])
	return
}

// AgreeCanonical is X25519(scalar, peer) for a peer encoded below p = 2^255-19, one encoding per key.
func AgreeCanonical(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	x25519.AssertCanonical(api, peer)
	return x25519.ECDH(api, scalar, peer)
}

// PackedKey is pack_be(0x04 ‖ u), the caller bounds every byte of u.
func PackedKey(api frontend.API, u [32]frontend.Variable) []frontend.Variable {
	return PackBounded(api, append([]frontend.Variable{4}, u[:]...))
}
