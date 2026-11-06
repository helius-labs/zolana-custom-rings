package transfer_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type inputCompositionCircuit struct {
	Inputs []shared.UtxoWires
	Count  frontend.Variable
}

func (c *inputCompositionCircuit) Define(api frontend.API) error {
	transfer.OpenInputs(api, c.Inputs, c.Count)
	return nil
}

func inputComposition(domains []int, count int) *inputCompositionCircuit {
	c := &inputCompositionCircuit{Inputs: make([]shared.UtxoWires, len(domains)), Count: count}
	for i, domain := range domains {
		c.Inputs[i] = dummySlot()
		c.Inputs[i].Domain = domain
	}
	return c
}

// Notes lead in SPP's note order, dummies follow, no address opens.
func TestInputsHoldNotesThenDummies(t *testing.T) {
	const note, dummy = transaction.UtxoDomain, transaction.DummyDomain
	for _, tc := range []struct {
		name    string
		domains []int
		count   int
	}{
		{"notes only", []int{note, note}, 2},
		{"notes then padding", []int{note, note, dummy}, 2},
		{"published padding", []int{note, dummy, dummy}, 3},
		{"dummy only", []int{dummy}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) { requireSolved(t, inputComposition(tc.domains, tc.count)) })
	}
}

func TestInputCompositionRefusesAnotherOrder(t *testing.T) {
	const note, address, dummy = transaction.UtxoDomain, transaction.AddressDomain, transaction.DummyDomain
	for _, tc := range []struct {
		name   string
		mutate func(*inputCompositionCircuit)
	}{
		{"an address slot", func(c *inputCompositionCircuit) { c.Inputs[1].Domain = address }},
		{"a note past the count", func(c *inputCompositionCircuit) { c.Inputs[3].Domain = note }},
		{"a note after a dummy", func(c *inputCompositionCircuit) { c.Inputs[0].Domain = dummy }},
		{"a zero count", func(c *inputCompositionCircuit) { c.Count = 0 }},
		{"a count past capacity", func(c *inputCompositionCircuit) { c.Count = len(c.Inputs) + 1 }},
		{"an unknown domain", func(c *inputCompositionCircuit) { c.Inputs[0].Domain = 99 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := inputComposition([]int{note, note, dummy, dummy}, 3)
			tc.mutate(c)
			refused(t, c)
		})
	}
}

func TestInputCompositionFillsTheEntryBitmap(t *testing.T) {
	domains := make([]int, shared.InputBitmapBits)
	for i := range domains {
		domains[i] = transaction.UtxoDomain
	}
	requireSolved(t, inputComposition(domains, len(domains)))
}
