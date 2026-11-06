package shared_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// A twin off Poseidon(0) would refuse every program-owned note or waive the tracking row for a real key.
func TestZeroNullifierPkIsPoseidonOfZero(t *testing.T) {
	if got := ringtest.MustPoseidonHash(t, big.NewInt(0)); got.Cmp(shared.ZeroNullifierPk) != 0 {
		t.Fatalf("Poseidon(0) is %x, the twin holds %x", got, shared.ZeroNullifierPk)
	}
	if protocol.SolAsset().Cmp(shared.SolAssetField) != 0 {
		t.Fatalf("SOL asset %x, the twin holds %x", protocol.SolAsset(), shared.SolAssetField)
	}
	ringtest.PinVector(t, "registry/zero_nullifier.json", map[string]string{
		"description":  "ZERO_NULLIFIER_PUBKEY, the nullifier public key of nullifier secret 0 = Poseidon(0). A note under it waives the tracking row only. Produced by prover/circuits/shared/zero_nullifier_test.go with WRITE_AUDIT_VECTORS=1.",
		"nullifier_pk": ringtest.FieldHex(shared.ZeroNullifierPk),
	})
}
