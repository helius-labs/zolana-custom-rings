package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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
	Member, Index, Active        frontend.Variable
	Lists, EscrowKey, MintPolicy frontend.Variable
}

func (c *recordPoolCircuit) Define(api frontend.API) error {
	pool := openRecordPool(api, c.Active, c.Root, c.Records, c.Proof)
	for _, q := range c.Queries {
		v := pool.resolve(api, recordQuery{active: q.Active, member: q.Member, index: q.Index})
		api.AssertIsEqual(api.FromBinary(v.onList[:]...), q.Lists)
		api.AssertIsEqual(v.escrowKey, q.EscrowKey)
		api.AssertIsEqual(api.Add(api.Mul(v.mintPolicy.threshold, new(big.Int).Lsh(big.NewInt(1), 128)), api.Mul(v.mintPolicy.cap, new(big.Int).Lsh(big.NewInt(1), 64)), v.mintPolicy.cosignAbove), q.MintPolicy)
	}
	return nil
}

func poolFixture(t testing.TB) *recordPoolCircuit {
	t.Helper()
	r := ringregistry.New(t)
	r.Apply(t, ringregistry.Entry{Member: big.NewInt(11), Mask: big.NewInt(3), Value: big.NewInt(3), EscrowKey: big.NewInt(29), MintPolicy: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(31))})
	r.Apply(t, ringregistry.Entry{Member: big.NewInt(17), Mask: big.NewInt(1), Value: big.NewInt(1), EscrowKey: big.NewInt(37)})
	c := &recordPoolCircuit{Root: r.Root(), Active: 1}
	for _, member := range []int64{11, 17} {
		c.Records = append(c.Records, r.Opening(big.NewInt(member)).Record.Wires())
	}
	var err error
	c.Proof, err = r.SharedProof([]uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	c.Queries = []poolQueryWires{
		{Member: 11, Index: 0, Active: 1, Lists: 3, EscrowKey: 29, MintPolicy: 31},
		{Member: 11, Index: 0, Active: 1, Lists: 3, EscrowKey: 29, MintPolicy: 31},
		{Member: 17, Index: 1, Active: 1, Lists: 1, EscrowKey: 37, MintPolicy: 0},
		{Member: 13, Index: 0, Active: 1, Lists: 0, EscrowKey: 0, MintPolicy: 0},
		{Member: 41, Index: 0, Active: 0, Lists: 0, EscrowKey: 0, MintPolicy: 0},
	}
	return c
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
		{"wrong escrow", func(c *recordPoolCircuit) { c.Queries[1].EscrowKey = 37 }},
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
			c := poolFixture(t)
			tc.mutate(c)
			if test.IsSolved(c, c, ecc.BN254.ScalarField()) == nil {
				t.Fatal("forged pool query solved")
			}
		})
	}
}

func TestRecordPoolRejectsLookupHintForgery(t *testing.T) {
	c := poolFixture(t)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, poolCircuitShape(t, c))
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
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
			for _, v := range out {
				v.SetInt64(0)
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
	c := poolFixture(t)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, poolCircuitShape(t, c))
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	for column := range 2 + pooledColumns {
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

func poolCircuitShape(t testing.TB, c *recordPoolCircuit) *recordPoolCircuit {
	t.Helper()
	proof, err := registry.NewSharedQuadProof(len(c.Records))
	if err != nil {
		t.Fatal(err)
	}
	return &recordPoolCircuit{Records: make([]registry.Record, len(c.Records)), Queries: make([]poolQueryWires, len(c.Queries)), Proof: proof}
}
