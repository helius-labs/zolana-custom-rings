package registry

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

func foldQuadPath(api frontend.API, siblings [][Arity - 1]frontend.Variable, bits []frontend.Variable, leaf frontend.Variable) frontend.Variable {
	node := leaf
	for level, siblings := range siblings {
		node = gadget.PoseidonHash(api, quadChildren(api, node, siblings, bits[2*level], bits[2*level+1]))
	}
	return node
}
