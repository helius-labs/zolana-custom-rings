package registry

import (
	"testing"

	"github.com/consensys/gnark/frontend"
)

func TestSharedQuadProofMaximumCanopyWidth(t *testing.T) {
	proof := SharedQuadProof{
		Canopy: make([]frontend.Variable, Capacity),
		Paths:  []SharedQuadPath{{Index: Capacity - 1}},
	}
	if err := proof.Validate(1); err != nil {
		t.Fatal(err)
	}
	proof.Canopy = append(proof.Canopy, 0)
	if err := proof.Validate(1); err == nil {
		t.Fatal("oversize canopy accepted")
	}
}

func TestSharedQuadProofRefusesAMissingOrShortPath(t *testing.T) {
	proof, err := NewSharedQuadProof(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Validate(2); err != nil {
		t.Fatal(err)
	}
	if proof.Validate(3) == nil {
		t.Fatal("a record without a path accepted")
	}
	short := SharedQuadProof{Canopy: proof.Canopy, Paths: []SharedQuadPath{proof.Paths[0], {Siblings: proof.Paths[1].Siblings[1:]}}}
	if short.Validate(2) == nil {
		t.Fatal("a path that stops below the canopy accepted")
	}
}
