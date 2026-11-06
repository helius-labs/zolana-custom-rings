package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type inputCompositionCircuit struct {
	Inputs         []shared.UtxoWires
	Nullifiers     []frontend.Variable
	Count          frontend.Variable
	AddressChain   frontend.Variable
	NullifierChain frontend.Variable
}

func (c *inputCompositionCircuit) Define(api frontend.API) error {
	inputs := transfer.OpenInputs(api, c.Inputs, c.Count, c.Nullifiers)
	api.AssertIsEqual(inputs.AddressChain, c.AddressChain)
	api.AssertIsEqual(inputs.NullifierChain, c.NullifierChain)
	return nil
}

func inputComposition(t testing.TB, domains []int, count int) *inputCompositionCircuit {
	t.Helper()
	c := &inputCompositionCircuit{
		Inputs:     make([]shared.UtxoWires, len(domains)),
		Nullifiers: make([]frontend.Variable, len(domains)),
		Count:      count,
	}
	for i, domain := range domains {
		c.Inputs[i] = dummySlot()
		c.Inputs[i].Domain = domain
		c.Nullifiers[i] = 0
		if i < count {
			c.Nullifiers[i] = 101 + i
		}
	}
	c.rebindAddresses(t)
	c.rebindNullifiers(t)
	return c
}

func (c *inputCompositionCircuit) rebindAddresses(t testing.TB) {
	t.Helper()
	addresses := make([]*big.Int, len(c.Inputs))
	for i, input := range c.Inputs {
		addresses[i] = new(big.Int)
		if ringtest.AsBigInt(input.Domain).Int64() == transaction.AddressDomain {
			addresses[i] = ringtest.AsBigInt(c.Nullifiers[i])
		}
	}
	c.AddressChain = spptest.MustNonZeroHashChain(t, addresses)
}

func (c *inputCompositionCircuit) rebindNullifiers(t testing.TB) {
	t.Helper()
	fields := append([]frontend.Variable{c.Count}, c.Nullifiers...)
	c.NullifierChain = spptest.MustHashChain4(t, ringtest.ToBigInts(fields))
}

func TestInputsInterleaveBeforePadding(t *testing.T) {
	const note, address, dummy = transaction.UtxoDomain, transaction.AddressDomain, transaction.DummyDomain
	for _, tc := range []struct {
		name    string
		domains []int
		count   int
	}{
		{"notes and addresses", []int{note, address, note, address, dummy}, 4},
		{"address before note", []int{address, note, dummy}, 2},
		{"addresses only", []int{address, address, dummy}, 2},
		{"notes only", []int{note, note, dummy}, 2},
		{"published padding", []int{note, address, dummy, dummy}, 4},
		{"dummy only", []int{dummy}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireSolved(t, inputComposition(t, tc.domains, tc.count))
		})
	}
}

func TestInputCompositionRefusesChangedBindings(t *testing.T) {
	const note, address, dummy = transaction.UtxoDomain, transaction.AddressDomain, transaction.DummyDomain
	for _, tc := range []struct {
		name   string
		mutate func(*inputCompositionCircuit)
	}{
		{"moved nullifiers", func(c *inputCompositionCircuit) {
			c.Nullifiers[0], c.Nullifiers[1] = c.Nullifiers[1], c.Nullifiers[0]
		}},
		{"moved address with rebound nullifiers", func(c *inputCompositionCircuit) {
			c.Nullifiers[0], c.Nullifiers[1] = c.Nullifiers[1], c.Nullifiers[0]
			c.rebindNullifiers(t)
		}},
		{"changed domain map", func(c *inputCompositionCircuit) {
			c.Inputs[0].Domain, c.Inputs[1].Domain = address, note
		}},
		{"zero address nullifier", func(c *inputCompositionCircuit) {
			c.Nullifiers[1] = 0
			c.rebindAddresses(t)
			c.rebindNullifiers(t)
		}},
		{"zero note nullifier", func(c *inputCompositionCircuit) {
			c.Nullifiers[0] = 0
			c.rebindNullifiers(t)
		}},
		{"nullifier past count", func(c *inputCompositionCircuit) {
			c.Nullifiers[3] = 900
			c.rebindNullifiers(t)
		}},
		{"address past count", func(c *inputCompositionCircuit) { c.Inputs[3].Domain = address }},
		{"note past count", func(c *inputCompositionCircuit) { c.Inputs[3].Domain = note }},
		{"address after dummy", func(c *inputCompositionCircuit) { c.Inputs[0].Domain = dummy }},
		{"note after dummy", func(c *inputCompositionCircuit) { c.Inputs[1].Domain = dummy }},
		{"zero count", func(c *inputCompositionCircuit) { c.Count = 0 }},
		{"count past capacity", func(c *inputCompositionCircuit) { c.Count = len(c.Inputs) + 1 }},
		{"unknown domain", func(c *inputCompositionCircuit) { c.Inputs[0].Domain = 99 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := inputComposition(t, []int{note, address, note, dummy}, 3)
			tc.mutate(c)
			refused(t, c)
		})
	}
}

func TestInputCompositionUsesTheLastBitmapSlot(t *testing.T) {
	domains := make([]int, shared.InputBitmapBits)
	for i := range domains {
		domains[i] = transaction.UtxoDomain
	}
	domains[len(domains)-1] = transaction.AddressDomain
	c := inputComposition(t, domains, len(domains))
	requireSolved(t, c)
	c = inputComposition(t, domains, len(domains))
	c.Nullifiers[len(c.Nullifiers)-1] = 0
	c.rebindAddresses(t)
	c.rebindNullifiers(t)
	refused(t, c, "transfer.OpenInputs")
}
