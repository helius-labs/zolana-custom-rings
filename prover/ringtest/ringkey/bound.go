package ringkey

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Bound is a compiled circuit with the constraint binding its public input located, a refusal test then tells a predicate from a statement mismatch.
type Bound struct {
	CS constraint.ConstraintSystem
	// statementCID is the constraint binding the public input, a predicate refusal must fail elsewhere.
	statementCID int
}

// Bind compiles circuit and locates the public input binding with the honest assignment.
func Bind(t testing.TB, circuit, honest frontend.Circuit) *Bound {
	t.Helper()
	b := &Bound{CS: Compile(t, circuit)}
	b.RequireSolved(t, honest)
	publicInput := reflect.ValueOf(honest).Elem().FieldByName("PublicInputHash")
	moved := new(big.Int).Add(ringtest.AsBigInt(publicInput.Interface()), big.NewInt(1))
	SetPublicInput(honest, moved)
	b.statementCID = b.unsatisfied(t, honest).CID
	SetPublicInput(honest, new(big.Int).Sub(moved, big.NewInt(1)))
	return b
}

func (b *Bound) RequireSolved(t testing.TB, assignment frontend.Circuit, options ...solver.Option) {
	t.Helper()
	if err := b.Solve(t, assignment, options...); err != nil {
		t.Fatalf("honest witness refused: %v", err)
	}
}

// Refuse requires a constraint other than the public input binding to fail, the host statement matches the mutation.
func (b *Bound) Refuse(t testing.TB, assignment frontend.Circuit, options ...solver.Option) {
	t.Helper()
	if unsatisfied := b.unsatisfied(t, assignment, options...); unsatisfied.CID == b.statementCID {
		t.Fatalf("refused by the public input binding only, the host statement drifted: %v", unsatisfied)
	}
}

// RefuseStatement requires the public input binding alone to refuse assignment under the program's statement.
func (b *Bound) RefuseStatement(t testing.TB, assignment frontend.Circuit, statement []*big.Int) {
	t.Helper()
	SetPublicInput(assignment, spptest.MustHashChain4(t, statement))
	if unsatisfied := b.unsatisfied(t, assignment); unsatisfied.CID != b.statementCID {
		t.Fatalf("refused before the public input binding: %v", unsatisfied)
	}
}

func SetPublicInput(assignment frontend.Circuit, value *big.Int) {
	reflect.ValueOf(assignment).Elem().FieldByName("PublicInputHash").Set(reflect.ValueOf(value))
}

func (b *Bound) unsatisfied(t testing.TB, assignment frontend.Circuit, options ...solver.Option) *cs_bn254.UnsatisfiedConstraintError {
	t.Helper()
	err := b.Solve(t, assignment, options...)
	hintattack.RequireConstraintRejection(t, err)
	var unsatisfied *cs_bn254.UnsatisfiedConstraintError
	errors.As(err, &unsatisfied)
	return unsatisfied
}

// Solve runs the compiled constraints on assignment, a lookup query past the table reads as missing.
func (b *Bound) Solve(t testing.TB, assignment frontend.Circuit, options ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return b.CS.IsSolved(witness, append(options, hintattack.SkipMissingLookupQueries(t))...)
}
