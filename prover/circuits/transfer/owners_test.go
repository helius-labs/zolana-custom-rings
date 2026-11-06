// Refusals of the owner predicates, a key off the enrolled row and a zero key for an enrolled owner under a salted payee read.

package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	testRows    = 4
	testInputs  = 4
	testOutputs = 2
	testRing    = 0x7711
)

// ownersCircuit runs the owner sections alone.
type ownersCircuit struct {
	policy.Tracking
	Members          []frontend.Variable
	Inputs, Outputs  []shared.UtxoWires
	Delegate, Hidden frontend.Variable
	HiddenOwner      frontend.Variable
	SaltedPayees     frontend.Variable
}

func newOwnersCircuit(t testing.TB) *ownersCircuit {
	t.Helper()
	tracking, err := policy.NewTracking(testRows, testOutputs, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &ownersCircuit{Tracking: tracking, Members: make([]frontend.Variable, testRows), Inputs: make([]shared.UtxoWires, testInputs), Outputs: make([]shared.UtxoWires, testOutputs)}
}

func (c *ownersCircuit) Define(api frontend.API) error {
	if err := c.ValidateTracking(testRows, testOutputs, 0); err != nil {
		return err
	}
	pool := c.OpenTracking(api)
	rows := transfer.OpenOwnerRows(api, c.Members, c.RowEntries, pool)
	inputs := make([]shared.Output, len(c.Inputs))
	for i, input := range c.Inputs {
		inputs[i] = input.Open(api)
	}
	rows.AssertInputOwners(api, transfer.InputRail{Delegate: c.Delegate, Hidden: c.Hidden, HiddenOwner: c.HiddenOwner}, inputs)
	outputs := make([]shared.Output, len(c.Outputs))
	for o, output := range c.Outputs {
		outputs[o] = output.Open(api)
	}
	transfer.AssertOutputOwners(api, pool, outputs, c.OutputEntries, c.SaltedPayees)
	return nil
}

var (
	alice    = big.NewInt(0x0a11)
	bob      = big.NewInt(0x0b0b)
	carol    = big.NewInt(0x0c0c)
	stranger = big.NewInt(0x0d0d)
)

func enrolledKey(t testing.TB, owner *big.Int) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, new(big.Int).Add(owner, big.NewInt(1)))
}

func note(owner, key *big.Int, ring int64) shared.UtxoWires {
	return shared.UtxoWires{Domain: transaction.UtxoDomain, TreeID: 9, OwnerPkHash: owner, NullifierPk: key, Asset: 5, Amount: 10, Blinding: 3, DataHash: 0, RingDataHash: 0, RingProgramID: ring}
}

func dummySlot() shared.UtxoWires {
	return shared.UtxoWires{Domain: transaction.DummyDomain, TreeID: 0, OwnerPkHash: 0, NullifierPk: 0, Asset: 0, Amount: 0, Blinding: 1, DataHash: 0, RingDataHash: 0, RingProgramID: 0}
}

// ownersWorld enrolls alice and bob, carol and stranger hold no row.
type ownersWorld struct {
	rows             []*big.Int
	inputs, outputs  []shared.UtxoWires
	delegate, hidden bool
	saltedPayees     bool
	hiddenOwner      *big.Int
	// entries overrides the fixture's row entries after filling.
	mutate func(c *ownersCircuit)
}

func (w ownersWorld) build(t testing.TB) *ownersCircuit {
	t.Helper()
	c := newOwnersCircuit(t)
	tree := ringregistry.NewTracking(t)
	ringpolicy.Enroll(t, tree, alice, enrolledKey(t, alice))
	ringpolicy.Enroll(t, tree, bob, enrolledKey(t, bob))
	for j := range c.Members {
		c.Members[j] = 0
		if j < len(w.rows) {
			c.Members[j] = w.rows[j]
		}
	}
	for i := range c.Inputs {
		c.Inputs[i] = dummySlot()
		if i < len(w.inputs) {
			c.Inputs[i] = w.inputs[i]
		}
	}
	outputOwners := make([]frontend.Variable, testOutputs)
	for o := range c.Outputs {
		c.Outputs[o], outputOwners[o] = dummySlot(), 0
		if o < len(w.outputs) {
			c.Outputs[o], outputOwners[o] = w.outputs[o], w.outputs[o].OwnerPkHash
			if ringtest.AsBigInt(w.outputs[o].RingProgramID).Sign() == 0 {
				outputOwners[o] = 0
			}
		}
	}
	ringpolicy.FillTracking(t, &c.Tracking, tree, c.Members, outputOwners, nil, nil)
	c.Delegate, c.Hidden, c.HiddenOwner, c.SaltedPayees = ringtest.Bit(w.delegate), ringtest.Bit(w.hidden), 0, ringtest.Bit(w.saltedPayees)
	if w.hiddenOwner != nil {
		c.HiddenOwner = w.hiddenOwner
	}
	if w.mutate != nil {
		w.mutate(c)
	}
	return c
}

func solveOwners(t testing.TB, w ownersWorld) error {
	t.Helper()
	return test.IsSolved(newOwnersCircuit(t), w.build(t), ecc.BN254.ScalarField())
}

func TestOwnerPredicates(t *testing.T) {
	aliceNote := func(t testing.TB) shared.UtxoWires { return note(alice, enrolledKey(t, alice), testRing) }
	bobNote := func(t testing.TB) shared.UtxoWires { return note(bob, enrolledKey(t, bob), testRing) }
	zero := shared.ZeroNullifierPk
	for _, tc := range []struct {
		name  string
		world func(t testing.TB) ownersWorld
		frame string
	}{
		{name: "enrolled owners under their keys", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{alice, bob}, inputs: []shared.UtxoWires{aliceNote(t), bobNote(t), aliceNote(t)}, outputs: []shared.UtxoWires{bobNote(t), aliceNote(t)}}
		}},
		{name: "an empty transaction", world: func(t testing.TB) ownersWorld { return ownersWorld{} }},
		{name: "a zero-key input of an unenrolled public owner", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{carol}, inputs: []shared.UtxoWires{note(carol, zero, testRing)}}
		}},
		{name: "a zero-key input of an enrolled owner", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{alice}, inputs: []shared.UtxoWires{note(alice, zero, testRing), aliceNote(t)}}
		}},
		{name: "a default-ring input under a key the ring never enrolled", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{alice}, inputs: []shared.UtxoWires{note(alice, big.NewInt(99), 0)}}
		}},
		{name: "a default-ring input of an unenrolled owner", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{carol}, inputs: []shared.UtxoWires{note(carol, big.NewInt(99), 0)}}
		}},
		{name: "a zero-key output to an unenrolled owner", world: func(t testing.TB) ownersWorld {
			return ownersWorld{saltedPayees: true, outputs: []shared.UtxoWires{note(carol, zero, testRing)}}
		}},
		{name: "a zero-key output to an enrolled owner off a salted payee read", world: func(t testing.TB) ownersWorld {
			return ownersWorld{outputs: []shared.UtxoWires{note(alice, zero, testRing), bobNote(t)}}
		}},
		{name: "an exit to anyone", world: func(t testing.TB) ownersWorld {
			return ownersWorld{outputs: []shared.UtxoWires{note(stranger, big.NewInt(99), 0)}}
		}},
		{name: "a delegate moving a zero-key note with no row", world: func(t testing.TB) ownersWorld {
			return ownersWorld{delegate: true, inputs: []shared.UtxoWires{note(carol, zero, testRing)}}
		}},
		{name: "a delegate moving a zero-key note in slot 0 of a hidden frame", world: func(t testing.TB) ownersWorld {
			return ownersWorld{delegate: true, hiddenOwner: carol, inputs: []shared.UtxoWires{note(carol, zero, testRing)}}
		}},
		{name: "a delegate moving a nonzero note under its registered key", world: func(t testing.TB) ownersWorld {
			return ownersWorld{delegate: true, rows: []*big.Int{alice}, inputs: []shared.UtxoWires{aliceNote(t)}}
		}},
		{name: "a public co-owner's zero-key input beside a hidden sender", world: func(t testing.TB) ownersWorld {
			return ownersWorld{hidden: true, hiddenOwner: alice, rows: []*big.Int{alice, carol}, inputs: []shared.UtxoWires{aliceNote(t), note(carol, zero, testRing)}}
		}},

		{name: "a ring input under another key", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{alice}, inputs: []shared.UtxoWires{note(alice, enrolledKey(t, bob), testRing)}}
		}},
		{name: "a nonzero key with an absent row", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{carol}, inputs: []shared.UtxoWires{note(carol, enrolledKey(t, carol), testRing)}}
		}},
		{name: "a live input past the rows", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{rows: []*big.Int{alice}, inputs: []shared.UtxoWires{aliceNote(t), bobNote(t)}}
		}},
		{name: "a zero-key input with no row", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{inputs: []shared.UtxoWires{note(carol, zero, testRing)}}
		}},
		{name: "a default-ring input with no row", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{inputs: []shared.UtxoWires{note(alice, big.NewInt(99), 0)}}
		}},
		{name: "a delegate moving a nonzero note with no row", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{delegate: true, inputs: []shared.UtxoWires{aliceNote(t)}}
		}},
		{name: "a delegate moving a note under another key", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{delegate: true, rows: []*big.Int{alice}, inputs: []shared.UtxoWires{note(alice, enrolledKey(t, bob), testRing)}}
		}},
		{name: "a hidden sender's zero-key input", frame: "transfer.OwnerRows.AssertInputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{hidden: true, hiddenOwner: alice, rows: []*big.Int{alice}, inputs: []shared.UtxoWires{note(alice, zero, testRing), aliceNote(t)}}
		}},
		{name: "a nonzero key to an enrolled owner other than its own", frame: "transfer.AssertOutputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{outputs: []shared.UtxoWires{note(alice, enrolledKey(t, bob), testRing)}}
		}},
		{name: "a zero key to an enrolled owner under a salted payee read", frame: "transfer.AssertOutputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{saltedPayees: true, outputs: []shared.UtxoWires{note(alice, zero, testRing)}}
		}},
		{name: "a nonzero key to an unenrolled owner", frame: "transfer.AssertOutputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{outputs: []shared.UtxoWires{note(carol, enrolledKey(t, carol), testRing)}}
		}},
		{name: "a literal zero key to an unenrolled owner", frame: "transfer.AssertOutputOwners", world: func(t testing.TB) ownersWorld {
			return ownersWorld{outputs: []shared.UtxoWires{note(carol, big.NewInt(0), testRing)}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := solveOwners(t, tc.world(t))
			if tc.frame == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			ringtest.RequireRefused(t, err, tc.frame)
		})
	}
}
