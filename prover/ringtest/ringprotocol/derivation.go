// Package ringprotocol is the host twin of circuits/shared for the Go tests.
package ringprotocol

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Recipient delivery stays outside every circuit, these mirror what Rust and TS derive for the vectors.
const (
	// deliveredSlotSecretDomain = "CRDS"
	deliveredSlotSecretDomain = 0x43524453
	// recipientTagDomain = "CRRT"
	recipientTagDomain = 0x43525254
	// senderTagDomain = "CRST"
	senderTagDomain = 0x43525354
)

// DeliveredSlotSecret is Poseidon(CRDS, dh0, dh1, txpk0, txpk1, r0, r1, salt, i, n0) over X25519(tx_viewing_sk, u), the recipient rebuilds it from X25519(u_sk, tx_u).
func DeliveredSlotSecret(t testing.TB, txViewingSk [32]byte, u [32]byte, salt [16]byte, i int, firstNullifier *big.Int) *big.Int {
	t.Helper()
	peer, err := ecdh.X25519().NewPublicKey(u[:])
	if err != nil {
		t.Fatal(err)
	}
	tx := XPrivateKey(t, txViewingSk)
	agreement, err := tx.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	dhLo, dhHi := Pack32([32]byte(agreement))
	txLo, txHi := Pack33(Tagged(tx.PublicKey().Bytes()))
	rLo, rHi := Pack33(Tagged(u[:]))
	return ringtest.MustPoseidonHash(t, big.NewInt(deliveredSlotSecretDomain), dhLo, dhHi, txLo, txHi, rLo, rHi,
		new(big.Int).SetBytes(salt[:]), big.NewInt(int64(i)), firstNullifier)
}

// BlindingSeed mirrors shared.BlindingSeed.
func BlindingSeed(t testing.TB, txViewingSk [32]byte, salt [16]byte) *big.Int {
	t.Helper()
	keyLo, keyHi := Pack32(txViewingSk)
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.BlindingSeedDomain), keyLo, keyHi, new(big.Int).SetBytes(salt[:]))
}

// OutputBlinding is SPP's TXOB blinding of slot i under the output blinding seed.
func OutputBlinding(t testing.TB, firstNullifier, seedOut *big.Int, i int) *big.Int {
	t.Helper()
	blinding, err := protocol.OutputBlinding(firstNullifier, seedOut, i)
	return spptest.MustHash(t, blinding, err)
}

// RecipientTag is the slot tag over its preimage.
func RecipientTag(t testing.TB, preimage *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(recipientTagDomain), preimage)
}

// SenderBundleTag is the bundle tag over its slot secret.
func SenderBundleTag(t testing.TB, secret *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(senderTagDomain), secret)
}
