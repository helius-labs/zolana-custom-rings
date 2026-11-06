// Refusals of the record pool, a forged lookup hint, a column off its row and a second split of a record's lists, and the peak gadget.

package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type recordPoolCircuit struct {
	Root    frontend.Variable `gnark:",public"`
	Active  frontend.Variable
	Records []registry.Record
	Proof   registry.SharedQuadProof
	Queries []poolQueryWires
}

type poolQueryWires struct {
	Member, Index, Active frontend.Variable
	Lists, MintPolicy     frontend.Variable
}

func (c *recordPoolCircuit) Define(api frontend.API) error {
	pool := openRecordPool(api, c.Active, c.Root, c.Records, c.Proof, ownColumns)
	for _, query := range c.Queries {
		resolved := pooledRecordAt(withLists(api, pool.read(api, recordQuery{active: query.Active, member: query.Member, index: query.Index})))
		api.AssertIsEqual(api.FromBinary(resolved.onList[:]...), query.Lists)
		mintPolicy := decodeMintPolicy(api, resolved.mintPolicy)
		api.AssertIsEqual(api.Add(api.Mul(mintPolicy.threshold, new(big.Int).Lsh(big.NewInt(1), 128)), api.Mul(mintPolicy.cap, new(big.Int).Lsh(big.NewInt(1), 64)), mintPolicy.cosignAbove), query.MintPolicy)
	}
	return nil
}

func poolFixture(t testing.TB) *recordPoolCircuit {
	t.Helper()
	tree := ringregistry.New(t)
	tree.Apply(t, ringregistry.Entry{Member: big.NewInt(11), Mask: big.NewInt(3), Value: big.NewInt(3), MintPolicy: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(31))})
	tree.Apply(t, ringregistry.Entry{Member: big.NewInt(17), Mask: big.NewInt(1), Value: big.NewInt(1)})
	circuit := &recordPoolCircuit{Root: tree.Root(), Active: 1}
	for _, member := range []int64{11, 17} {
		circuit.Records = append(circuit.Records, tree.Opening(big.NewInt(member)).Record.Wires())
	}
	var err error
	circuit.Proof, err = tree.SharedProof([]uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	circuit.Queries = []poolQueryWires{
		{Member: 11, Index: 0, Active: 1, Lists: 3, MintPolicy: 31},
		{Member: 11, Index: 0, Active: 1, Lists: 3, MintPolicy: 31},
		{Member: 17, Index: 1, Active: 1, Lists: 1, MintPolicy: 0},
		{Member: 13, Index: 0, Active: 1, Lists: 0, MintPolicy: 0},
		{Member: 41, Index: 0, Active: 0, Lists: 0, MintPolicy: 0},
	}
	return circuit
}

func TestRecordPoolBindsEveryActiveQuery(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*recordPoolCircuit)
	}{
		{"wrong member", func(c *recordPoolCircuit) { c.Queries[1].Member = 17 }},
		{"wrong index", func(c *recordPoolCircuit) { c.Queries[1].Index = 1 }},
		{"index beyond pool", func(c *recordPoolCircuit) { c.Queries[1].Index = 3 }},
		{"negative index", func(c *recordPoolCircuit) { c.Queries[1].Index = -1 }},
		{"wrong lists", func(c *recordPoolCircuit) { c.Queries[1].Lists = 1 }},
		{"wrong mint policy", func(c *recordPoolCircuit) { c.Queries[1].MintPolicy = 37 }},
		{"wrong root", func(c *recordPoolCircuit) { c.Root = 37 }},
		{"wrong opening member", func(c *recordPoolCircuit) { c.Records[0].Member = 17 }},
		{"wrong opening lists", func(c *recordPoolCircuit) { c.Records[0].Lists = 1 }},
		{"absent member moved", func(c *recordPoolCircuit) { c.Queries[3].Member = 17 }},
		{"fractional active query", func(c *recordPoolCircuit) { c.Queries[1].Active = 2 }},
		{"inactive pool active query", func(c *recordPoolCircuit) { c.Active = 0 }},
	}
	if err := test.IsSolved(poolFixture(t), poolFixture(t), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			circuit := poolFixture(t)
			tc.mutate(circuit)
			if test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()) == nil {
				t.Fatal("forged pool query solved")
			}
		})
	}
}

func TestRecordPoolRejectsLookupHintForgery(t *testing.T) {
	circuit := poolFixture(t)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, poolCircuitShape(t, circuit))
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
	for _, hint := range []solver.Hint{lookup.RowLookupHint, lookup.RowCountHint} {
		calls := 0
		err = cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(hint), func(_ *big.Int, in, out []*big.Int) error {
			calls++
			for _, value := range out {
				value.SetInt64(0)
			}
			return nil
		}))
		if calls == 0 {
			t.Fatal("lookup hint was not called")
		}
		if err == nil {
			t.Fatal("omitted lookup solved")
		}
	}
}

func TestRecordPoolBindsEveryLookupColumn(t *testing.T) {
	circuit := poolFixture(t)
	requireLookupColumnsBound(t, poolCircuitShape(t, circuit), circuit, 2+ownColumns.width)
}

func requireLookupColumnsBound(t *testing.T, shape, circuit frontend.Circuit, columns int) {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	for column := range columns {
		calls := 0
		err = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(lookup.RowLookupHint), func(q *big.Int, in, out []*big.Int) error {
			if err := lookup.RowLookupHint(q, in, out); err != nil {
				return err
			}
			if calls == 0 {
				out[column].Add(out[column], big.NewInt(1))
			}
			calls++
			return nil
		}))
		if calls == 0 {
			t.Fatal("lookup hint was not called")
		}
		if err == nil {
			t.Fatalf("forged lookup column %d solved", column)
		}
	}
}

func poolCircuitShape(t testing.TB, circuit *recordPoolCircuit) *recordPoolCircuit {
	t.Helper()
	proof, err := registry.NewSharedQuadProof(len(circuit.Records))
	if err != nil {
		t.Fatal(err)
	}
	return &recordPoolCircuit{Records: make([]registry.Record, len(circuit.Records)), Queries: make([]poolQueryWires, len(circuit.Queries)), Proof: proof}
}

type curatorPoolCircuit struct {
	Root    frontend.Variable `gnark:",public"`
	Active  frontend.Variable
	Records []registry.Record
	Proof   registry.SharedQuadProof
	Queries []curatorQueryWires
}

type curatorQueryWires struct {
	Member, Index, Active, Lists frontend.Variable
}

func (c *curatorPoolCircuit) Define(api frontend.API) error {
	pool := openRecordPool(api, c.Active, c.Root, c.Records, c.Proof, curatorColumns)
	for _, query := range c.Queries {
		resolved := withLists(api, pool.read(api, recordQuery{active: query.Active, member: query.Member, index: query.Index}))
		api.AssertIsEqual(api.FromBinary(resolved...), query.Lists)
	}
	return nil
}

// undecodableMintPolicy sets bits past the three limbs the own pool decodes.
func undecodableMintPolicy() *big.Int {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 193), new(big.Int).Lsh(big.NewInt(1), 192))
}

func curatorPoolFixture(t testing.TB) *curatorPoolCircuit {
	t.Helper()
	tree := ringregistry.New(t)
	tree.Apply(t, ringregistry.Entry{Member: big.NewInt(11), Mask: big.NewInt(3), Value: big.NewInt(3), MintPolicy: undecodableMintPolicy(), WithdrawalThreshold: big.NewInt(43), AssetLimits: ringregistry.Limits{big.NewInt(47), big.NewInt(53), big.NewInt(59)}})
	tree.Apply(t, ringregistry.Entry{Member: big.NewInt(17), Mask: big.NewInt(1), Value: big.NewInt(1)})
	circuit := &curatorPoolCircuit{Root: tree.Root(), Active: 1}
	for _, member := range []int64{11, 17} {
		circuit.Records = append(circuit.Records, tree.Opening(big.NewInt(member)).Record.Wires())
	}
	var err error
	if circuit.Proof, err = tree.SharedProof([]uint64{1, 2}); err != nil {
		t.Fatal(err)
	}
	circuit.Queries = []curatorQueryWires{
		{Member: 11, Index: 0, Active: 1, Lists: 3},
		{Member: 17, Index: 1, Active: 1, Lists: 1},
		{Member: 13, Index: 0, Active: 1, Lists: 0},
		{Member: 19, Index: 1, Active: 1, Lists: 0},
		{Member: 41, Index: 0, Active: 0, Lists: 0},
	}
	return circuit
}

func TestCuratorPoolReadsNonMembershipThroughAnotherRecord(t *testing.T) {
	if err := test.IsSolved(curatorPoolFixture(t), curatorPoolFixture(t), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*curatorPoolCircuit)
	}{
		{"predecessor lists read through", func(c *curatorPoolCircuit) { c.Queries[2].Lists = 3 }},
		{"member beyond predecessor link", func(c *curatorPoolCircuit) { c.Queries[1].Index = 0 }},
		{"predecessor above member", func(c *curatorPoolCircuit) { c.Queries[2].Index = 1 }},
		{"wrong lists", func(c *curatorPoolCircuit) { c.Queries[0].Lists = 1 }},
		{"wrong root", func(c *curatorPoolCircuit) { c.Root = 37 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			circuit := curatorPoolFixture(t)
			tc.mutate(circuit)
			if test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()) == nil {
				t.Fatal("forged curator query solved")
			}
		})
	}
}

// The leaf hash binds every field the curator projection leaves unread.
func TestCuratorPoolKeepsFieldsThePolicyDoesNotRead(t *testing.T) {
	fixture := curatorPoolFixture(t)
	if err := test.IsSolved(fixture, fixture, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	unreadFields := []func(*registry.Record){
		func(r *registry.Record) { r.Next = 12 },
		func(r *registry.Record) { r.MintPolicy = 0 },
		func(r *registry.Record) { r.WithdrawalThreshold = 44 },
		func(r *registry.Record) { r.AssetLimits[2] = 60 },
	}
	for i, mutate := range unreadFields {
		circuit := curatorPoolFixture(t)
		mutate(&circuit.Records[0])
		if test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("unread field %d escaped the leaf hash", i)
		}
	}
	// An own pool reader decodes the same record and refuses it, a query that reads zeros does not.
	unread := &recordPoolCircuit{Root: fixture.Root, Active: 1, Records: fixture.Records, Proof: fixture.Proof, Queries: []poolQueryWires{{Member: 41, Index: 0, Active: 0, Lists: 0, MintPolicy: 0}}}
	if err := test.IsSolved(unread, unread, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	read := &recordPoolCircuit{Root: fixture.Root, Active: 1, Records: fixture.Records, Proof: fixture.Proof, Queries: []poolQueryWires{{Member: 11, Index: 0, Active: 1, Lists: 3, MintPolicy: 0}}}
	if test.IsSolved(read, read, ecc.BN254.ScalarField()) == nil {
		t.Fatal("own pool decoded a mint policy past its limbs")
	}
}

func TestCuratorPoolBindsEveryLookupColumn(t *testing.T) {
	circuit := curatorPoolFixture(t)
	proof, err := registry.NewSharedQuadProof(len(circuit.Records))
	if err != nil {
		t.Fatal(err)
	}
	shape := &curatorPoolCircuit{Records: make([]registry.Record, len(circuit.Records)), Queries: make([]curatorQueryWires, len(circuit.Queries)), Proof: proof}
	requireLookupColumnsBound(t, shape, circuit, 2+curatorColumns.width)
}

type sourceListsCircuit struct {
	Lists frontend.Variable
	Bits  [NSources]frontend.Variable
}

func (c *sourceListsCircuit) Define(api frontend.API) error {
	for i, bit := range sourceLists(api, c.Lists) {
		api.AssertIsEqual(bit, c.Bits[i])
	}
	return nil
}

func TestSourceListsSplitsOneWay(t *testing.T) {
	field := ecc.BN254.ScalarField()
	honest := &sourceListsCircuit{Lists: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), registry.ListBits-1), big.NewInt(5)), Bits: [NSources]frontend.Variable{1, 0, 1, 0, 0, 0, 0, 0, 0}}
	if err := test.IsSolved(honest, honest, field); err != nil {
		t.Fatal(err)
	}
	past := &sourceListsCircuit{Lists: new(big.Int).Lsh(big.NewInt(1), registry.ListBits), Bits: [NSources]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0}}
	if test.IsSolved(past, past, field) == nil {
		t.Fatal("lists past their width accepted")
	}
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &sourceListsCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	// Any other low part leaves the rest off a multiple of the bit width.
	forged := &sourceListsCircuit{Lists: 5, Bits: [NSources]frontend.Variable{0, 1, 1, 0, 0, 0, 0, 0, 0}}
	witness, err := frontend.NewWitness(forged, field)
	if err != nil {
		t.Fatal(err)
	}
	err = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(rangecheck.DecomposeHint), func(_ *big.Int, inputs, outputs []*big.Int) error {
		if inputs[0].Int64() == NSources {
			outputs[0].SetInt64(6)
			return nil
		}
		return rangecheck.DecomposeHint(ecc.BN254.ScalarField(), inputs, outputs)
	}))
	if err == nil {
		t.Fatal("a forged low part accepted")
	}
}

type peakCircuit struct {
	Values [3]frontend.Variable
	Peak   frontend.Variable
}

func (c *peakCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(newComparator(rangecheck.New(api)).peak(api, c.Values[:]), c.Peak)
	return nil
}

func TestPeakIsTheLargestValue(t *testing.T) {
	field := ecc.BN254.ScalarField()
	honest := &peakCircuit{Values: [3]frontend.Variable{3, 7, 5}, Peak: 7}
	if err := test.IsSolved(honest, honest, field); err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &peakCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for name, forged := range map[string]int64{"below a value": 5, "above every value": 8} {
		witness, err := frontend.NewWitness(&peakCircuit{Values: [3]frontend.Variable{3, 7, 5}, Peak: forged}, field)
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(peakHint), func(_ *big.Int, _, outputs []*big.Int) error {
			outputs[0].SetInt64(forged)
			return nil
		}))
		if err == nil {
			t.Fatalf("a peak %s accepted", name)
		}
	}
}
