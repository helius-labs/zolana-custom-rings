package ringregistry

import (
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
)

func (r *Registry) SharedProof(indices []uint64) (registry.SharedQuadProof, error) {
	proof, err := registry.NewSharedQuadProof(len(indices))
	if err != nil {
		return registry.SharedQuadProof{}, err
	}
	depth := len(proof.Paths[0].Siblings)
	for i := range proof.Canopy {
		proof.Canopy[i] = new(big.Int).Set(r.node(depth, uint64(i)))
	}
	for i, index := range indices {
		if index >= registry.Capacity {
			return registry.SharedQuadProof{}, fmt.Errorf("registry leaf index outside capacity")
		}
		path := r.Path(index).Wires()
		proof.Paths[i].Index = index
		copy(proof.Paths[i].Siblings, path.Siblings[:])
	}
	return proof, nil
}
