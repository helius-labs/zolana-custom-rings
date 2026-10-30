// Proves that a ciphertext is encrypted to the ring's auditor key, so the
// auditor can always open what the proof binds. Each envelope needs a fresh
// one-time key, a reused key repeats the keystream.
//
// Read after shared/disclosure.go, ringgadget/bytes.go, shared/derivation.go.
// Read before audit/audit.go, deposit.go, merge.go.

package shared

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// EphSk must be fresh per envelope, a reuse under one auditor key repeats the keystream.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	// Info keys the schedule of Seal, SealAuditStream reads no info.
	Info string
}

// Every Ciphertext byte is bounded to 8 bits by the cipher's tables.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

func (s Sealed) StatementFields(api frontend.API) []frontend.Variable {
	return append(slices.Concat(s.Auditor, s.Eph), gadget.HashBoundedBytes(api, s.Ciphertext))
}

type keySchedule func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable)

// Seal encrypts under the verifiable-encryption key schedule of Info.
func (e Envelope) Seal(api frontend.API) Sealed {
	return e.seal(api, func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable) {
		return ve.KeySchedule(api, secret, ringgadget.ConstBytes(e.Info), len(e.Info))
	})
}

// SealAuditStream encrypts under the audit stream schedule every delivered body shares.
func (e Envelope) SealAuditStream(api frontend.API) Sealed {
	return e.seal(api, func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable) {
		return AuditStreamKeySchedule(api, secret)
	})
}

func (e Envelope) seal(api frontend.API, schedule keySchedule) Sealed {
	// 1. One encoding per auditor key, the program packs the configured key bytes as they are.
	agreement := AgreeCanonical(api, e.EphSk, e.AuditorPk)
	// 2. The X25519 gadgets bound every key byte and return canonical bytes, the packings below need no byte check.
	eph := x25519.ScalarMulGenerator(api, e.EphSk)
	sealed := Sealed{Auditor: PackBounded(api, Tagged(e.AuditorPk)), Eph: PackBounded(api, Tagged(eph))}
	// 3. Binding both keys keeps the key schedule input from replaying under another key pair.
	secret := gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{uint64(DomSepCRShared)}, PackBounded(api, agreement[:]), sealed.Eph, sealed.Auditor,
	))
	// 4. The cipher's byte tables bound every plaintext byte.
	key, nonce := schedule(secret)
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}

// AuditStreamKeySchedule draws the AES-256 key and CTR nonce from the low canonical bytes of Poseidon(AuditEncInfo ‖ 0, secret) and Poseidon(AuditEncInfo ‖ 1, secret).
func AuditStreamKeySchedule(api frontend.API, secret frontend.Variable) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	rc := rangecheck.New(api)
	tag := func(counter byte) *big.Int {
		return new(big.Int).SetBytes(append([]byte(AuditEncInfo), counter))
	}
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

func Tagged(u [32]frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{4}, u[:]...)
}
