package registry_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type sharedPathCircuit struct {
	Root   frontend.Variable `gnark:",public"`
	Leaves []frontend.Variable
	Proof  registry.SharedQuadProof
}

func (c *sharedPathCircuit) Define(api frontend.API) error {
	c.Proof.AssertLeaves(api, c.Root, c.Leaves)
	return nil
}

func sharedCircuit(t *testing.T, count int) *sharedPathCircuit {
	t.Helper()
	proof, err := registry.NewSharedQuadProof(count)
	if err != nil {
		t.Fatal(err)
	}
	return &sharedPathCircuit{Leaves: make([]frontend.Variable, count), Proof: proof}
}

func sharedAssignment(t *testing.T, members *ringregistry.Registry, indices []uint64) *sharedPathCircuit {
	t.Helper()
	proof, err := members.SharedProof(indices)
	if err != nil {
		t.Fatal(err)
	}
	witness := &sharedPathCircuit{Root: members.Root(), Proof: proof, Leaves: make([]frontend.Variable, len(indices))}
	for i, index := range indices {
		witness.Leaves[i] = 0
		if index < members.NextIndex() {
			witness.Leaves[i] = members.Opening(big.NewInt(int64(index * 10))).Record.Hash(t)
		}
	}
	return witness
}

func sharedRegistry(t *testing.T) *ringregistry.Registry {
	t.Helper()
	members := ringregistry.New(t)
	for i := int64(1); i <= 20; i++ {
		members.Apply(t, entry(i*10, 1, 1, 0))
	}
	return members
}

func TestSharedQuadProofAcceptsEveryTopology(t *testing.T) {
	members := sharedRegistry(t)
	for _, count := range []int{1, 2, 4, 5, 16, 17, 64, 197} {
		for _, topology := range []string{"repeated", "adjacent", "spread"} {
			t.Run(fmt.Sprintf("%d/%s", count, topology), func(t *testing.T) {
				indices := make([]uint64, count)
				for i := range indices {
					switch topology {
					case "repeated":
						indices[i] = 1
					case "adjacent":
						indices[i] = uint64(i)
					case "spread":
						indices[i] = uint64(i) * registry.Capacity / uint64(count)
					}
				}
				if err := test.IsSolved(sharedCircuit(t, count), sharedAssignment(t, members, indices), ecc.BN254.ScalarField()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSharedQuadProofRejectsUnboundPaths(t *testing.T) {
	members := sharedRegistry(t)
	indices := []uint64{1, 2, 3, 1 << 18, registry.Capacity - 1}
	for name, tamper := range map[string]func(*sharedPathCircuit){
		"root":                  func(c *sharedPathCircuit) { c.Root = 1 },
		"leaf":                  func(c *sharedPathCircuit) { c.Leaves[0] = 1 },
		"low index":             func(c *sharedPathCircuit) { c.Proof.Paths[0].Index = 2 },
		"canopy index":          func(c *sharedPathCircuit) { c.Proof.Paths[0].Index = 1 + (1 << 18) },
		"capacity alias":        func(c *sharedPathCircuit) { c.Proof.Paths[0].Index = registry.Capacity + 1 },
		"negative index":        func(c *sharedPathCircuit) { c.Proof.Paths[0].Index = -1 },
		"sibling":               func(c *sharedPathCircuit) { c.Proof.Paths[0].Siblings[0][0] = 1 },
		"queried canopy node":   func(c *sharedPathCircuit) { c.Proof.Canopy[0] = 1 },
		"unqueried canopy node": func(c *sharedPathCircuit) { c.Proof.Canopy[2] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			assignment := sharedAssignment(t, members, indices)
			tamper(assignment)
			if err := test.IsSolved(sharedCircuit(t, len(indices)), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid shared proof accepted")
			}
		})
	}
}

func TestSharedQuadProofRejectsInvalidShape(t *testing.T) {
	full, err := registry.NewSharedQuadProof(registry.Capacity)
	if err != nil || len(full.Canopy) != registry.Capacity || len(full.Paths[0].Siblings) != 0 {
		t.Fatal("full capacity shape rejected")
	}
	if _, err := sharedRegistry(t).SharedProof(nil); err == nil {
		t.Fatal("empty host opening set accepted")
	}
	for _, count := range []int{0, -1, registry.Capacity + 1} {
		if _, err := registry.NewSharedQuadProof(count); err == nil {
			t.Fatalf("invalid count %d accepted", count)
		}
	}
	for name, tamper := range map[string]func(*sharedPathCircuit){
		"oversize canopy": func(c *sharedPathCircuit) { c.Proof.Canopy = make([]frontend.Variable, registry.Capacity+1) },
		"empty canopy":    func(c *sharedPathCircuit) { c.Proof.Canopy = nil },
		"canopy width":    func(c *sharedPathCircuit) { c.Proof.Canopy = c.Proof.Canopy[:3] },
		"short path":      func(c *sharedPathCircuit) { c.Proof.Paths[0].Siblings = c.Proof.Paths[0].Siblings[:1] },
		"missing leaf":    func(c *sharedPathCircuit) { c.Leaves = nil },
	} {
		t.Run(name, func(t *testing.T) {
			circuit := sharedCircuit(t, 5)
			tamper(circuit)
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit); err == nil {
				t.Fatal("invalid shared proof shape accepted")
			}
		})
	}
	if _, err := sharedRegistry(t).SharedProof([]uint64{registry.Capacity}); err == nil {
		t.Fatal("invalid host index accepted")
	}
}

type independentPathsCircuit struct {
	Root   frontend.Variable `gnark:",public"`
	Leaves []frontend.Variable
	Paths  []registry.QuadPath
}

func (c *independentPathsCircuit) Define(api frontend.API) error {
	for i, path := range c.Paths {
		api.AssertIsEqual(path.Root(api, c.Leaves[i]), c.Root)
	}
	return nil
}

func TestSharedQuadProofConstraintCounts(t *testing.T) {
	pinned := map[int]int{1: 3103, 2: 5892, 4: 11486, 8: 21494, 16: 41502, 33: 78638, 69: 155258, 97: 207674, 100: 213290, 197: 394874}
	for _, count := range []int{1, 2, 4, 8, 16, 33, 69, 97, 100, 197} {
		shared, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, sharedCircuit(t, count))
		if err != nil {
			t.Fatal(err)
		}
		independent, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &independentPathsCircuit{Leaves: make([]frontend.Variable, count), Paths: make([]registry.QuadPath, count)})
		if err != nil {
			t.Fatal(err)
		}
		if got := shared.GetNbConstraints(); got != pinned[count] {
			t.Fatalf("openings=%d constraints=%d want=%d", count, got, pinned[count])
		}
		wantCommitments := 0
		if count > 16 {
			wantCommitments = 1
		}
		if got := len(shared.GetCommitments().(constraint.Groth16Commitments)); got != wantCommitments {
			t.Fatalf("commitments=%d want=%d", got, wantCommitments)
		}
		t.Logf("openings=%d independent=%d shared=%d reduction=%.2f%%", count, independent.GetNbConstraints(), shared.GetNbConstraints(), 100*(1-float64(shared.GetNbConstraints())/float64(independent.GetNbConstraints())))
	}
}

type sharedPoolsCircuit struct {
	Own     sharedPathCircuit
	Curator sharedPathCircuit
}

func (c *sharedPoolsCircuit) Define(api frontend.API) error {
	if err := c.Own.Define(api); err != nil {
		return err
	}
	return c.Curator.Define(api)
}

func TestSharedQuadProofPoolsShareCommitment(t *testing.T) {
	circuit := &sharedPoolsCircuit{Own: *sharedCircuit(t, 100), Curator: *sharedCircuit(t, 97)}
	compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	commitments := compiled.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Fatalf("unsupported commitments %v", commitments)
	}
	t.Logf("own100_curator97 constraints=%d", compiled.GetNbConstraints())
}

func TestSharedQuadProofCompiledSolver(t *testing.T) {
	members := sharedRegistry(t)
	for _, count := range []int{5, 100} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			circuit := sharedCircuit(t, count)
			compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			indices := make([]uint64, count)
			for i := range indices {
				indices[i] = uint64(i * (registry.Capacity - 1) / (count - 1))
			}
			assignment := sharedAssignment(t, members, indices)
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := compiled.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
			assignment.Proof.Paths[0].Index = 1 << 18
			witness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := compiled.IsSolved(witness); err == nil {
				t.Fatal("wrong canopy route accepted by compiled solver")
			}
		})
	}
}

type conditionalSharedCircuit struct {
	Active frontend.Variable
	Path   sharedPathCircuit
}

func (c *conditionalSharedCircuit) Define(api frontend.API) error {
	c.Path.Proof.AssertLeavesWhen(api, c.Active, c.Path.Root, c.Path.Leaves)
	return nil
}

func TestSharedQuadProofConditionalRoot(t *testing.T) {
	members := sharedRegistry(t)
	for _, count := range []int{1, 5, 33} {
		indices := make([]uint64, count)
		for i := range indices {
			indices[i] = 1
		}
		circuit := &conditionalSharedCircuit{Active: 0, Path: *sharedAssignment(t, members, indices)}
		circuit.Path.Root = 0
		shape := &conditionalSharedCircuit{Path: *sharedCircuit(t, count)}
		if err := test.IsSolved(shape, circuit, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
		for _, active := range []int{1, 2} {
			circuit.Active = active
			if err := test.IsSolved(shape, circuit, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid active root accepted")
			}
		}
		circuit.Active = 0
		circuit.Path.Leaves[0] = 0
		if err := test.IsSolved(shape, circuit, ecc.BN254.ScalarField()); err == nil {
			t.Fatal("invalid inactive path accepted")
		}
	}
}
