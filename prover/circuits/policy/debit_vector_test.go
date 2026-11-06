// Pins the circuit's debit to its Rust twin over a shared vector.

package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

type debitNote struct {
	Owner  int64  `json:"owner"`
	Asset  int64  `json:"asset"`
	Amount uint64 `json:"amount"`
	Ring   bool   `json:"ring"`
}

type debitRow struct {
	Owner int64  `json:"owner"`
	Asset int64  `json:"asset"`
	Debit uint64 `json:"debit"`
}

type debitCase struct {
	Name    string      `json:"name"`
	Inputs  []debitNote `json:"inputs"`
	Outputs []debitNote `json:"outputs"`
	Debits  []debitRow  `json:"debits"`
}

func (c debitCase) world(limit uint64) ringpolicy.World {
	w := ringpolicy.Four()
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: limit}}
	for _, input := range c.Inputs {
		w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: input.Owner, Asset: input.Asset, Amount: input.Amount})
		if input.Owner != ringpolicy.Sender {
			w.CoOwners = append(w.CoOwners, input.Owner)
		}
	}
	w.Slots = nil
	for _, output := range c.Outputs {
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: output.Owner, Asset: output.Asset, Amount: output.Amount, Exit: !output.Ring})
	}
	return w
}

// Each row is the largest debit of its case, the key settles at the row's cap and refuses one below.
func TestDebitVector(t *testing.T) {
	const sender, other, payee, asset = ringpolicy.Sender, ringpolicy.Bob, ringpolicy.Alice, ringpolicy.AssetA
	cases := []debitCase{
		{"single owner pays", []debitNote{{sender, asset, 300, true}}, []debitNote{{payee, asset, 200, true}, {sender, asset, 100, true}}, []debitRow{{sender, asset, 200}}},
		{"an exit to the owner leaves the ring", []debitNote{{sender, asset, 300, true}}, []debitNote{{sender, asset, 200, false}, {sender, asset, 100, true}}, []debitRow{{sender, asset, 200}}},
		{"credits stay with their owner", []debitNote{{sender, asset, 300, true}, {other, asset, 100, true}}, []debitNote{{other, asset, 400, true}}, []debitRow{{sender, asset, 300}, {other, asset, 0}}},
		{"two owners pay one payee", []debitNote{{sender, asset, 250, true}, {other, asset, 150, true}}, []debitNote{{payee, asset, 400, true}}, []debitRow{{sender, asset, 250}, {other, asset, 150}}},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			largest := uint64(0)
			for _, row := range tc.Debits {
				largest = max(largest, row.Debit)
			}
			requireSolved(t, tc.world(largest).Build(t))
			b := tc.world(largest - 1).Build(t)
			ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), outflow)
		})
	}
	ringtest.PinVector(t, "policy/debit.json", map[string]any{
		"description": "debit(owner, asset) = max(0, owned inputs - ring outputs returned to that owner), keyed by owner identity, an exit reads ring false and counts as leaving, a credit never moves between owners. Each case's largest debit settles at a cap of itself and refuses at one below in the transfer circuit. owner and asset are decimal identities of the fixture. Produced by prover/circuits/policy/debit_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases":       cases,
	})
}
