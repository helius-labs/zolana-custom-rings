package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func TestPooledPolicyGroth16(t *testing.T) {
	for _, world := range []ringpolicy.World{curated(), ringpolicy.Anonymous(), delegate2()} {
		pooled := world.Build(t)
		assignment := pooled.Assignment()
		schema := world.Build(t)
		cs := ringkey.Compile(t, schema.Assignment())
		pk, vk, err := groth16.Setup(cs)
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		proof, err := groth16.Prove(cs, pk, witness)
		if err != nil {
			t.Fatal(err)
		}
		public, err := witness.Public()
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof, vk, public); err != nil {
			t.Fatal(err)
		}
		if pooled.Member != nil {
			pooled.Member.PublicInputHash = 1
		} else {
			pooled.Delegate.PublicInputHash = 1
		}
		wrong, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			t.Fatal(err)
		}
		if groth16.Verify(proof, vk, wrong) == nil {
			t.Fatal("proof accepted a different policy statement")
		}
	}
}
