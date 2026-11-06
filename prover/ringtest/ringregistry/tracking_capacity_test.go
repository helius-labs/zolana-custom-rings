package ringregistry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type trackingSlotCircuit struct {
	Leaf, Root frontend.Variable
	Path       registry.TrackingPath
}

func (c *trackingSlotCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Path.Root(api, c.Leaf), c.Root)
	return nil
}

// The last leaf of the tree opens under its root, the index one past it has no slot.
func TestTrackingTreeHoldsItsLastLeafAndNoMore(t *testing.T) {
	last := uint64(registry.TrackingCapacity - 1)
	tree := newQuadTree(t, registry.TrackingHeight)
	leaf := big.NewInt(7)
	tree.setLeaf(t, last, leaf)
	path := TrackingPath{Index: last}
	copy(path.Siblings[:], tree.siblings(last))
	c := &trackingSlotCircuit{Leaf: leaf, Root: tree.root(), Path: path.Wires()}
	if err := test.IsSolved(c, c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	c.Path.Index = new(big.Int).SetUint64(registry.TrackingCapacity)
	ringtest.RequireRefused(t, test.IsSolved(c, c, ecc.BN254.ScalarField()), "[ToBinary]", "registry.TrackingPath.digits")
}
