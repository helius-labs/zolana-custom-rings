// Opens many registry records under one root at a lower cost, because their Merkle
// paths share the top of the tree. SPP opens one path per input, a ring proof reads a
// pool of records per registry and would otherwise pay for the same top levels on every
// record. Each record still proves its full path to the root.
//
// Read after registry/registry.go. Read before policy/record_pool.go, policy/tracking.go.

package registry

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/selector"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. While active is set every leaf sits at its own Index under root, its path folds to the canopy node its index's high digits name and the canopy folds to root.
// 2. Index is bound to the tree's index width, one index per leaf.
// 3. While active is clear root binds nothing, every read of the pool's leaves must carry its own gate, pooledTable.lookup in policy/record_pool.go holds it.
// 4. The proof authenticates leaves only, member matching and absence stay with the caller.

// SharedQuadPath's Siblings stop at the canopy level.
type SharedQuadPath struct {
	Index    frontend.Variable
	Siblings [][Arity - 1]frontend.Variable
}

// SharedQuadProof's Canopy is one whole level of the tree, every node in index order.
type SharedQuadProof struct {
	// TreeHeight is zero for a policy registry of Height.
	TreeHeight int `gnark:"-"`
	Canopy     []frontend.Variable
	Paths      []SharedQuadPath
}

// A canopy up to the limit reads through a mux and adds no commitment, a wider one through one log derivative table, both read the same node.
const muxCanopyLimit = 16

func NewSharedQuadProof(openings int) (SharedQuadProof, error) {
	return newSharedProof(openings, 0)
}

func NewTrackingProof(openings int) (SharedQuadProof, error) {
	return newSharedProof(openings, TrackingHeight)
}

func newSharedProof(openings, treeHeight int) (SharedQuadProof, error) {
	proof := SharedQuadProof{TreeHeight: treeHeight}
	if openings < 1 || openings > 1<<(2*proof.height()) {
		return SharedQuadProof{}, fmt.Errorf("registry opening count outside capacity")
	}
	width, levels := canopyShape(openings)
	proof.Canopy, proof.Paths = make([]frontend.Variable, width), make([]SharedQuadPath, openings)
	for i := range proof.Paths {
		proof.Paths[i].Siblings = make([][Arity - 1]frontend.Variable, proof.height()-levels)
	}
	return proof, nil
}

// canopyShape picks the narrowest level at least as wide as the pool, the levels above it hash once.
func canopyShape(openings int) (width, levels int) {
	width = 1
	for width < openings {
		width *= Arity
		levels++
	}
	return width, levels
}

func (p SharedQuadProof) height() int {
	if p.TreeHeight == 0 {
		return Height
	}
	return p.TreeHeight
}

func (p SharedQuadProof) AssertLeaves(api frontend.API, root frontend.Variable, leaves []frontend.Variable) {
	p.AssertLeavesWhen(api, 1, root, leaves)
}

// AssertLeavesWhen panics on a shape Validate refuses.
func (p SharedQuadProof) AssertLeavesWhen(api frontend.API, active, root frontend.Variable, leaves []frontend.Variable) {
	if err := p.Validate(len(leaves)); err != nil {
		panic(err)
	}
	api.AssertIsBoolean(active)
	// 1. The canopy folds to root while active is set, a prover cannot supply a node the tree under root does not hold.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: canopyRoot(api, p.Canopy), B: root})
	// 2. Each leaf folds to the canopy node at its index's high digits, the two steps together are a full path.
	if len(p.Canopy) <= muxCanopyLimit {
		for i, path := range p.Paths {
			node := path.root(api, leaves[i], p.height())
			// Ungated, an inactive pool's canopy is prover-chosen and always admits its paths.
			api.AssertIsEqual(selector.BinaryMux(api, node.bits, p.Canopy), node.value)
		}
		return
	}
	// The table reads the entry at the index the bits fix, a value that is no canopy node at that index fails the lookup.
	table := logderivlookup.New(api)
	for _, node := range p.Canopy {
		table.Insert(node)
	}
	for i, path := range p.Paths {
		node := path.root(api, leaves[i], p.height())
		api.AssertIsEqual(table.Lookup(api.FromBinary(node.bits...))[0], node.value)
	}
}

func (p SharedQuadProof) Validate(count int) error {
	if len(p.Paths) == 0 || len(p.Paths) != count {
		return fmt.Errorf("registry shared opening count mismatch")
	}
	width, levels := canopyShape(len(p.Canopy))
	if len(p.Canopy) != width {
		return fmt.Errorf("registry canopy width is not a supported power of four")
	}
	for _, path := range p.Paths {
		if len(path.Siblings) != p.height()-levels {
			return fmt.Errorf("registry shared path height mismatch")
		}
	}
	return nil
}

func canopyRoot(api frontend.API, nodes []frontend.Variable) frontend.Variable {
	for len(nodes) > 1 {
		parents := make([]frontend.Variable, len(nodes)/Arity)
		for i := range parents {
			parents[i] = gadget.PoseidonHash(api, nodes[i*Arity:(i+1)*Arity])
		}
		nodes = parents
	}
	return nodes[0]
}

// canopyNode's bits are the index's high digits, low bit first, the node's position in the canopy level.
type canopyNode struct {
	bits  []frontend.Variable
	value frontend.Variable
}

func (p SharedQuadPath) root(api frontend.API, leaf frontend.Variable, height int) canopyNode {
	// The tree's index width bounds Index, one index per leaf.
	bits := api.ToBinary(p.Index, 2*height)
	return canopyNode{bits: bits[2*len(p.Siblings):], value: foldQuadPath(api, p.Siblings, bits, leaf)}
}
