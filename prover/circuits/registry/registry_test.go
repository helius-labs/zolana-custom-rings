package registry_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type rootCircuit struct {
	Root, Leaf frontend.Variable
	Path       registry.QuadPath
}

func (c *rootCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Path.Root(api, c.Leaf), c.Root)
	return nil
}

// MEMBER_REGISTRY_EMPTY_ROOT in program-libs/interface/src/accounts/member_registry.rs, the sentinel leaf of eight inputs.
func TestEmptyRootMatchesRust(t *testing.T) {
	const rust = "053b2136ce0e6cffb89cb76c7a81b6d7e1bd424159ff4579f284a7e5f198956d"
	if got := fmt.Sprintf("%064x", ringregistry.New(t).Root()); got != rust {
		t.Fatalf("empty root %s, Rust %s", got, rust)
	}
}

func TestQuadPathFoldsTheHostTree(t *testing.T) {
	members := ringregistry.New(t)
	for m := int64(1); m <= 20; m++ {
		members.Apply(t, ringregistry.Entry{Member: big.NewInt(m * 10), Mask: big.NewInt(1), Value: big.NewInt(1)})
	}
	root := members.Root()
	for _, member := range []int64{10, 20, 30, 40, 50, 160, 170, 200} {
		opening := members.Opening(big.NewInt(member))
		assignment := &rootCircuit{Root: root, Leaf: opening.Record.Hash(t), Path: opening.Path.Wires()}
		if err := test.IsSolved(&rootCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("member %d at %d: %v", member, opening.Path.Index, err)
		}
	}
	// An empty leaf opens under the same root, its digits reach the top levels.
	for _, index := range []uint64{21, 1 << 18, 2 << 18, 3 << 18, registry.Capacity - 1} {
		assignment := &rootCircuit{Root: root, Leaf: 0, Path: members.Path(index).Wires()}
		if err := test.IsSolved(&rootCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("empty leaf %d: %v", index, err)
		}
	}
}

func TestQuadPathRejectsAnotherIndex(t *testing.T) {
	members := ringregistry.New(t)
	members.Apply(t, ringregistry.Entry{Member: big.NewInt(10), Mask: big.NewInt(1), Value: big.NewInt(1)})
	opening := members.Opening(big.NewInt(10))
	for _, tc := range []struct {
		name   string
		index  *big.Int
		frames []string
	}{
		{"a neighbour sharing the siblings", big.NewInt(2), []string{"[assertIsEqual]", "registry_test.(*rootCircuit).Define"}},
		{"the index plus the capacity", new(big.Int).Add(big.NewInt(1), big.NewInt(registry.Capacity)), []string{"[ToBinary]", "registry.QuadPath.digits"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := opening.Path.Wires()
			path.Index = tc.index
			err := test.IsSolved(&rootCircuit{}, &rootCircuit{Root: members.Root(), Leaf: opening.Record.Hash(t), Path: path}, ecc.BN254.ScalarField())
			ringtest.RequireRefused(t, err, tc.frames...)
		})
	}
}
