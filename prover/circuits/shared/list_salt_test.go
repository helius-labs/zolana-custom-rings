package shared_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type listTagCircuit struct{ Salt, Tag frontend.Variable }

func (c *listTagCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(shared.ListTag(api, c.Salt), c.Tag)
	return nil
}

func TestListTagOpensTheVectorSalt(t *testing.T) {
	var vector struct {
		ListSalt string `json:"list_salt"`
		ListTag  string `json:"list_tag"`
	}
	ringtest.ReadVector(t, "registry/list_salt.json", &vector)
	witness := &listTagCircuit{Salt: ringtest.VectorField(t, vector.ListSalt), Tag: ringtest.VectorField(t, vector.ListTag)}
	if err := test.IsSolved(&listTagCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
