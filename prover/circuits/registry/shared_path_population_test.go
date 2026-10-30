package registry_test

import (
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func TestSharedQuadProofMillionMembers(t *testing.T) {
	if os.Getenv("RING_MILLION_RECORDS") != "1" {
		t.Skip("set RING_MILLION_RECORDS=1")
	}
	const population = 1_000_000
	if population+1 > registry.Capacity {
		t.Fatal("registry cannot hold the sentinel and requested population")
	}
	zero, one := big.NewInt(0), big.NewInt(1)
	maximum := new(big.Int).Sub(ecc.BN254.ScalarField(), one)
	levels := make([][]*big.Int, registry.Height+1)
	levels[0] = make([]*big.Int, population+1)
	fillPopulation(levels[0], func(index int) *big.Int {
		next := big.NewInt(int64(2 * (index + 1)))
		if index == population {
			next = maximum
		}
		lists := one
		if index == 0 {
			lists = zero
		}
		return ringtest.MustPoseidonHash(t, big.NewInt(int64(2*index)), next, lists, zero, zero, zero)
	})
	emptyNodes := make([]*big.Int, registry.Height+1)
	emptyNodes[0] = zero
	empty := zero
	for level := 1; level <= registry.Height; level++ {
		children := levels[level-1]
		levels[level] = make([]*big.Int, (len(children)+registry.Arity-1)/registry.Arity)
		fillPopulation(levels[level], func(index int) *big.Int {
			values := make([]*big.Int, registry.Arity)
			for child := range values {
				values[child] = empty
				if offset := index*registry.Arity + child; offset < len(children) {
					values[child] = children[offset]
				}
			}
			return ringtest.MustPoseidonHash(t, values...)
		})
		empty = ringtest.MustPoseidonHash(t, empty, empty, empty, empty)
		emptyNodes[level] = empty
	}
	nodeAt := func(level, index int) *big.Int {
		if index < len(levels[level]) {
			return levels[level][index]
		}
		return emptyNodes[level]
	}
	for _, topology := range []string{"distinct", "repeated"} {
		t.Run(topology, func(t *testing.T) {
			circuit := sharedCircuit(t, 197)
			circuit.Root = levels[registry.Height][0]
			depth := len(circuit.Proof.Paths[0].Siblings)
			for i := range circuit.Proof.Canopy {
				circuit.Proof.Canopy[i] = nodeAt(depth, i)
			}
			for i := range circuit.Leaves {
				index := 1 + i*(population-1)/(len(circuit.Leaves)-1)
				if topology == "repeated" {
					index = population
				}
				circuit.Leaves[i] = levels[0][index]
				circuit.Proof.Paths[i].Index = index
				for level := range circuit.Proof.Paths[i].Siblings {
					node := index >> (2 * level)
					first := node &^ (registry.Arity - 1)
					sibling := 0
					for child := first; child < first+registry.Arity; child++ {
						if child != node {
							circuit.Proof.Paths[i].Siblings[level][sibling] = nodeAt(level, child)
							sibling++
						}
					}
				}
			}
			if err := test.IsSolved(sharedCircuit(t, len(circuit.Leaves)), circuit, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			circuit.Leaves[0] = frontend.Variable(0)
			if err := test.IsSolved(sharedCircuit(t, len(circuit.Leaves)), circuit, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("missing populated record accepted")
			}
		})
	}
}

func fillPopulation(values []*big.Int, value func(int) *big.Int) {
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			for i := worker; i < len(values); i += 4 {
				values[i] = value(i)
			}
		})
	}
	workers.Wait()
}
