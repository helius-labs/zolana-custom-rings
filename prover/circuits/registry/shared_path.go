package registry

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/selector"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type SharedQuadPath struct {
	Index    frontend.Variable
	Siblings [][Arity - 1]frontend.Variable
}

type SharedQuadProof struct {
	Canopy []frontend.Variable
	Paths  []SharedQuadPath
}

func NewSharedQuadProof(openings int) (SharedQuadProof, error) {
	if openings < 1 || openings > Capacity {
		return SharedQuadProof{}, fmt.Errorf("registry opening count outside capacity")
	}
	width, levels := canopyShape(openings)
	proof := SharedQuadProof{Canopy: make([]frontend.Variable, width), Paths: make([]SharedQuadPath, openings)}
	for i := range proof.Paths {
		proof.Paths[i].Siblings = make([][Arity - 1]frontend.Variable, Height-levels)
	}
	return proof, nil
}

const muxCanopyLimit = 16

func (p SharedQuadProof) AssertLeaves(api frontend.API, root frontend.Variable, leaves []frontend.Variable) {
	p.AssertLeavesWhen(api, 1, root, leaves)
}

// AssertLeavesWhen panics on a shape Validate refuses.
func (p SharedQuadProof) AssertLeavesWhen(api frontend.API, active, root frontend.Variable, leaves []frontend.Variable) {
	if err := p.Validate(len(leaves)); err != nil {
		panic(err)
	}
	api.AssertIsBoolean(active)
	api.AssertIsEqual(api.Mul(active, api.Sub(canopyRoot(api, p.Canopy), root)), 0)
	if len(p.Canopy) <= muxCanopyLimit {
		for i, path := range p.Paths {
			node := path.root(api, leaves[i])
			// Ungated, an inactive pool's canopy is prover-chosen and always admits its paths.
			api.AssertIsEqual(selector.BinaryMux(api, node.bits, p.Canopy), node.value)
		}
		return
	}
	table := logderivlookup.New(api)
	for _, node := range p.Canopy {
		table.Insert(node)
	}
	for i, path := range p.Paths {
		node := path.root(api, leaves[i])
		api.AssertIsEqual(table.Lookup(api.FromBinary(node.bits...))[0], node.value)
	}
}

type canopyNode struct {
	bits  []frontend.Variable
	value frontend.Variable
}

func (p SharedQuadPath) root(api frontend.API, leaf frontend.Variable) canopyNode {
	bits := api.ToBinary(p.Index, IndexBits)
	return canopyNode{bits: bits[2*len(p.Siblings):], value: foldQuadPath(api, p.Siblings, bits, leaf)}
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
		if len(path.Siblings) != Height-levels {
			return fmt.Errorf("registry shared path height mismatch")
		}
	}
	return nil
}

func canopyShape(openings int) (width, levels int) {
	width = 1
	for width < openings {
		width *= Arity
		levels++
	}
	return width, levels
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
