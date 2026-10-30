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

// DeliveredSlotSecret mirrors shared.DeliveredSlot.Secret over X25519(tx_viewing_sk, u).
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
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.DeliveredSlotSecretDomain), dhLo, dhHi, txLo, txHi, rLo, rHi,
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

// DepositBlinding mirrors shared.DepositBlinding.
func DepositBlinding(t testing.TB, blindingSecret *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.DepositBlindingDomain), blindingSecret)
}

// SenderCommitment mirrors shared.SenderCommitment.
func SenderCommitment(t testing.TB, senderPkHash, privateTxBlinding *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.SenderCommitmentDomain), senderPkHash, privateTxBlinding)
}
