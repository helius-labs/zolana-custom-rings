// Refusals of the guard totals and the outflow quantities at the cap and one below, rows out of order, and the shared vector pinning them to Rust.

package policy_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

const (
	s     = ringpolicy.Sender
	bob   = ringpolicy.Bob
	alice = ringpolicy.Alice
	mintA = ringpolicy.AssetA
	mintB = ringpolicy.AssetB
)

func slot(owner int64, amount uint64) ringpolicy.Slot {
	return ringpolicy.Slot{Owner: owner, Asset: mintA, Amount: amount}
}

func exit(owner int64, amount uint64) ringpolicy.Slot {
	return ringpolicy.Slot{Owner: owner, Asset: mintA, Amount: amount, Exit: true}
}

// guarded lists nobody, a positive guard past threshold reads the allow list.
func guarded(threshold uint64) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Outputs = 4
	w.Table.Limits = nil
	w.Table.Rules[0].Guard, w.Table.Rules[0].Threshold = policy.GuardAboveAmount, threshold
	for _, member := range []int64{s, bob, alice} {
		w.Own[member] = ringpolicy.Record{Lists: 0}
	}
	return w
}

func TestReceiptTable(t *testing.T) {
	const threshold = 1000
	cases := []struct {
		name    string
		inputs  []ringpolicy.Slot
		outputs []ringpolicy.Slot
		public  []ringpolicy.PublicSlot
		settles bool
	}{
		{"a large holder pays little", []ringpolicy.Slot{slot(s, 10_000)}, []ringpolicy.Slot{slot(bob, 100), slot(s, 9900)}, nil, true},
		{"another owner funds a same-owner receipt", []ringpolicy.Slot{slot(bob, 5000), slot(s, 100)}, []ringpolicy.Slot{slot(s, 5100)}, nil, false},
		{"a deposit to an unlisted owner", nil, []ringpolicy.Slot{slot(alice, 1_000_000)}, []ringpolicy.PublicSlot{{Asset: mintA, Amount: 1_000_000}}, false},
		{"a default note entering to another owner", []ringpolicy.Slot{exit(s, 1_000_000)}, []ringpolicy.Slot{slot(alice, 1_000_000)}, nil, false},
		{"a default note entering to its own owner", []ringpolicy.Slot{exit(s, 1_000_000)}, []ringpolicy.Slot{slot(s, 1_000_000)}, nil, false},
		{"an exit to an unlisted owner", []ringpolicy.Slot{slot(s, 10_000)}, []ringpolicy.Slot{exit(alice, 10_000)}, nil, false},
		{"a merged note pays under the threshold", []ringpolicy.Slot{slot(s, 1600)}, []ringpolicy.Slot{slot(bob, 600), slot(s, 1000)}, nil, true},
		{"split receipts sum to the threshold", []ringpolicy.Slot{slot(s, 1000)}, []ringpolicy.Slot{slot(bob, 400), slot(bob, 600)}, nil, true},
		{"split receipts pass the threshold", []ringpolicy.Slot{slot(s, 1001)}, []ringpolicy.Slot{slot(bob, 400), slot(bob, 601)}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := guarded(threshold)
			w.Inputs, w.Slots, w.Public = tc.inputs, tc.outputs, tc.public
			for _, input := range tc.inputs {
				if input.Owner != s {
					w.CoOwners = append(w.CoOwners, input.Owner)
				}
			}
			if tc.settles {
				requireSolved(t, w.Build(t))
				return
			}
			requireRefusedIn(t, w, "policy.assertPaymentRules")
			for _, member := range []int64{s, bob, alice} {
				w.Own[member] = ringpolicy.Record{Lists: ringregistry.AllowBit}
			}
			requireSolved(t, w.Build(t))
		})
	}
}

// Same-owner change adds no receipt to the asset's sum, a merged note does not strand.
func TestAssetGuardNetsChange(t *testing.T) {
	w := guarded(1_000_000)
	rule := ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)
	rule.Guard, rule.Threshold = policy.GuardAboveAmount, 100
	w.Table.Rules = append(w.Table.Rules, rule)
	w.Inputs = []ringpolicy.Slot{slot(s, 160)}
	w.Slots = []ringpolicy.Slot{slot(bob, 60), slot(s, 100)}
	requireSolved(t, w.Build(t))
	w.Slots = []ringpolicy.Slot{slot(bob, 101), slot(s, 59)}
	requireRefusedIn(t, w, "policy.assertPaymentRules")
}

// outflowWorld holds limit as the cap of AssetA over the rows of inputs.
func outflowWorld(inputs, outputs []ringpolicy.Slot, public []ringpolicy.PublicSlot, limit uint64) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Outputs = 4
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: mintA, Cap: limit}}
	w.Inputs, w.Slots, w.Public = inputs, outputs, public
	if inputs == nil {
		w.Inputs = []ringpolicy.Slot{}
	}
	for _, input := range inputs {
		if input.Owner != s && !slices.Contains(w.CoOwners, input.Owner) {
			w.CoOwners = append(w.CoOwners, input.Owner)
		}
	}
	return w
}

func TestOutflowSettlesAtItselfAndRefusesOneBelow(t *testing.T) {
	deposit := func(net int64, gross uint64) []ringpolicy.PublicSlot {
		return []ringpolicy.PublicSlot{{Asset: mintA, Amount: net, Gross: gross}}
	}
	zeroKey := slot(s, 1000)
	zeroKey.ZeroKey = true
	cases := []struct {
		name    string
		inputs  []ringpolicy.Slot
		outputs []ringpolicy.Slot
		public  []ringpolicy.PublicSlot
		outflow uint64
	}{
		{"a deposit funds the return of a spent note that exits", []ringpolicy.Slot{slot(s, 1000)}, []ringpolicy.Slot{slot(s, 1000), exit(alice, 1000)}, deposit(1000, 0), 1000},
		{"a zero key changes nothing", []ringpolicy.Slot{zeroKey}, []ringpolicy.Slot{slot(s, 1000), exit(alice, 1000)}, deposit(1000, 0), 1000},
		{"a deposit funds the return of a withdrawal", []ringpolicy.Slot{slot(s, 1000)}, []ringpolicy.Slot{slot(s, 1001)}, deposit(1, 999), 999},
		{"a withdrawal with change", []ringpolicy.Slot{slot(s, 200)}, []ringpolicy.Slot{slot(s, 50)}, deposit(-150, 150), 150},
		{"a withdrawal no output shares", []ringpolicy.Slot{slot(s, 200)}, nil, deposit(-200, 200), 200},
		{"a same-owner exit with no deposit", []ringpolicy.Slot{slot(s, 200)}, []ringpolicy.Slot{exit(s, 200)}, nil, 200},
		{"an owner who kept its funds is not charged", []ringpolicy.Slot{slot(s, 1000), slot(bob, 1000)}, []ringpolicy.Slot{slot(s, 1000), exit(alice, 1000)}, nil, 1000},
		{"public funds passing through charge only held funds", []ringpolicy.Slot{slot(s, 1000)}, []ringpolicy.Slot{slot(s, 1000), exit(alice, 5000)}, deposit(5000, 0), 1000},
		{"attribution halves an even share", []ringpolicy.Slot{slot(s, 100), slot(bob, 100)}, []ringpolicy.Slot{slot(s, 100), slot(bob, 100), exit(alice, 100)}, deposit(100, 0), 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireSolved(t, outflowWorld(tc.inputs, tc.outputs, tc.public, tc.outflow).Build(t))
			requireRefusedIn(t, outflowWorld(tc.inputs, tc.outputs, tc.public, tc.outflow-1), outflow)
			swapped := slices.Clone(tc.inputs)
			slices.Reverse(swapped)
			requireSolved(t, outflowWorld(swapped, tc.outputs, tc.public, tc.outflow).Build(t))
		})
	}
}

// The intended composition cost, A's net outflow is zero and its charged outflow is 100.
func TestReturnedSpendBesideAPublicWithdrawalIsCharged(t *testing.T) {
	// A spends 100 and receives 100 back, B's public deposit of 100 funds a public withdrawal of 100.
	inputs, outputs := []ringpolicy.Slot{slot(s, 100)}, []ringpolicy.Slot{slot(s, 100)}
	public := []ringpolicy.PublicSlot{{Asset: mintA, Amount: 0, Gross: 100}}
	requireSolved(t, outflowWorld(inputs, outputs, public, 100).Build(t))
	requireRefusedIn(t, outflowWorld(inputs, outputs, public, 99), outflow)
}

// One owner past the cap refuses the transfer whichever row holds it, a lower row cannot hide it.
func TestOwnerPastTheCapBesideOneUnderIt(t *testing.T) {
	for name, inputs := range map[string][]ringpolicy.Slot{
		"the first row past the cap":  {slot(s, 1000), slot(bob, 100)},
		"the second row past the cap": {slot(s, 100), slot(bob, 1000)},
	} {
		t.Run(name, func(t *testing.T) {
			outputs := []ringpolicy.Slot{slot(alice, 1100)}
			requireSolved(t, outflowWorld(inputs, outputs, nil, 1000).Build(t))
			requireRefusedIn(t, outflowWorld(inputs, outputs, nil, 999), outflow)
			// The lower owner's outflow as the peak clears the cap and matches a row, its gap to the higher owner leaves the range.
			b := outflowWorld(inputs, outputs, nil, 500).Build(t)
			witness, err := frontend.NewWitness(b.Assignment(), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			hintattack.RequireConstraintRejection(t, ringkey.Compile(t, b.Assignment()).IsSolved(witness, hintattack.SkipMissingLookupQueries(t), solver.OverrideHint(solver.GetHintID(policy.PeakHint), secondLargest)))
		})
	}
}

func secondLargest(_ *big.Int, inputs, outputs []*big.Int) error {
	sorted := slices.SortedFunc(slices.Values(inputs), func(a, b *big.Int) int { return b.Cmp(a) })
	outputs[0].Set(sorted[1])
	return nil
}

func TestOutflowWithNothingLeaving(t *testing.T) {
	const limit = 1
	t.Run("a deposit-funded payment to another owner", func(t *testing.T) {
		requireSolved(t, outflowWorld([]ringpolicy.Slot{slot(s, 1000)}, []ringpolicy.Slot{slot(s, 1000), slot(bob, 500)}, []ringpolicy.PublicSlot{{Asset: mintA, Amount: 500}}, limit).Build(t))
	})
	t.Run("a no-spend deposit and exit charges nobody", func(t *testing.T) {
		requireSolved(t, outflowWorld(nil, []ringpolicy.Slot{exit(alice, 500)}, []ringpolicy.PublicSlot{{Asset: mintA, Amount: 500}}, limit).Build(t))
	})
	t.Run("a mixed spend and deposit proves", func(t *testing.T) {
		w := outflowWorld([]ringpolicy.Slot{slot(s, 100), slot(bob, 100)}, []ringpolicy.Slot{slot(alice, 250)}, []ringpolicy.PublicSlot{{Asset: mintA, Amount: 50}}, 100)
		requireSolved(t, w.Build(t))
	})
	t.Run("another asset's deposit changes nothing", func(t *testing.T) {
		w := outflowWorld([]ringpolicy.Slot{slot(s, 100), slot(bob, 100)}, []ringpolicy.Slot{slot(alice, 200)}, []ringpolicy.PublicSlot{{Asset: mintB, Amount: 50}}, 100)
		requireSolved(t, w.Build(t))
	})
}

func TestRowsAscend(t *testing.T) {
	const ascending = "policy.assertRowsAscending"
	twoOwners := func() ringpolicy.World {
		return outflowWorld([]ringpolicy.Slot{slot(s, 100), slot(bob, 100)}, []ringpolicy.Slot{slot(alice, 200)}, nil, 100)
	}
	refused := func(t *testing.T, mutate func(ringpolicy.Witness)) {
		t.Helper()
		b := twoOwners().Build(t)
		mutate(b)
		b.Rebind(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), ascending)
	}
	swapRows := func(b ringpolicy.Witness, i, j int) {
		b.Circuit.Senders[i], b.Circuit.Senders[j] = b.Circuit.Senders[j], b.Circuit.Senders[i]
		b.Policy().SenderEntries[i], b.Policy().SenderEntries[j] = b.Policy().SenderEntries[j], b.Policy().SenderEntries[i]
	}
	requireSolved(t, twoOwners().Build(t))
	t.Run("rows out of order", func(t *testing.T) {
		refused(t, func(b ringpolicy.Witness) { swapRows(b, 0, 1) })
	})
	t.Run("a zero row before a live row", func(t *testing.T) {
		refused(t, func(b ringpolicy.Witness) { swapRows(b, 1, 2) })
	})
	t.Run("a repeated row", func(t *testing.T) {
		refused(t, func(b ringpolicy.Witness) {
			b.Circuit.Senders[1], b.Policy().SenderEntries[1] = b.Circuit.Senders[0], b.Policy().SenderEntries[0]
		})
	})
	t.Run("the authority rail reads no order", func(t *testing.T) {
		w := twoOwners()
		w.Delegate = true
		b := w.Build(t)
		swapRows(b, 0, 1)
		b.Rebind(t)
		requireSolved(t, b)
	})
}

type quantityNote struct {
	Owner  int64  `json:"owner"`
	Asset  int64  `json:"asset"`
	Amount uint64 `json:"amount"`
	Ring   bool   `json:"ring"`
}

type quantityRow struct {
	Owner          int64  `json:"owner"`
	Asset          int64  `json:"asset"`
	Debit          uint64 `json:"debit"`
	Kept           uint64 `json:"kept"`
	Charge         uint64 `json:"charge"`
	ChargedOutflow uint64 `json:"charged_outflow"`
}

type guardRow struct {
	Owner int64  `json:"owner"`
	Asset int64  `json:"asset"`
	Guard uint64 `json:"guard"`
}

type assetGuardRow struct {
	Asset int64  `json:"asset"`
	Guard uint64 `json:"guard"`
}

type publicRow struct {
	Asset int64  `json:"asset"`
	Gross uint64 `json:"gross"`
}

type thresholdRow struct {
	Asset               int64  `json:"asset"`
	CosignAbove         uint64 `json:"cosign_above"`
	WithdrawalThreshold uint64 `json:"withdrawal_threshold"`
}

// quantityCase is one transfer, Rows holds the nonzero outflows by ascending owner then asset, every other row reads no debit and no charge.
type quantityCase struct {
	Name        string          `json:"name"`
	Inputs      []quantityNote  `json:"inputs,omitempty"`
	Outputs     []quantityNote  `json:"outputs,omitempty"`
	Withdrawals []quantityNote  `json:"withdrawals,omitempty"`
	Public      []publicRow     `json:"public,omitempty"`
	Rows        []quantityRow   `json:"rows,omitempty"`
	Guards      []guardRow      `json:"guards,omitempty"`
	AssetGuards []assetGuardRow `json:"asset_guards,omitempty"`
	Thresholds  []thresholdRow  `json:"thresholds,omitempty"`
	Mask        uint8           `json:"mask,omitempty"`
}

const quantityRows = 4

type noteWires struct{ Owner, Asset, Amount, Ring, Exit frontend.Variable }

func (n noteWires) output() shared.Output {
	return shared.Output{UtxoWires: shared.UtxoWires{OwnerPkHash: n.Owner, Asset: n.Asset, Amount: n.Amount}, Utxo: 1, Ring: n.Ring, Exit: n.Exit}
}

type quantityExpect struct {
	Asset                               frontend.Variable
	Debit, Charge, ChargedOutflow, Held []frontend.Variable
}

type quantityCircuit struct {
	Rows         []frontend.Variable
	Inputs       []noteWires
	Outputs      []noteWires
	Withdrawals  []noteWires
	PublicAssets []frontend.Variable
	Gross        []frontend.Variable
	Expect       []quantityExpect
	OwnerGuards  []frontend.Variable
	AssetGuards  []frontend.Variable
}

func (c *quantityCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	inputs, outputs := make([]shared.Output, len(c.Inputs)), make([]shared.Output, len(c.Outputs))
	payments := make([]policy.Payment, 0, len(c.Outputs)+len(c.Withdrawals))
	for i, note := range c.Inputs {
		inputs[i] = note.output()
	}
	for o, note := range c.Outputs {
		outputs[o] = note.output()
		payments = append(payments, policy.Payment{Owner: note.Owner, Asset: note.Asset, Amount: note.Amount, Active: 1, Ring: note.Ring})
	}
	for _, note := range c.Withdrawals {
		payments = append(payments, policy.Payment{Owner: note.Owner, Asset: note.Asset, Amount: note.Amount, Active: 1, Ring: 0})
	}
	for _, expect := range c.Expect {
		for j, flow := range policy.RowFlows(api, rc, c.Rows, inputs, outputs, c.PublicAssets, c.Gross, expect.Asset) {
			api.AssertIsEqual(flow.Debit, expect.Debit[j])
			api.AssertIsEqual(flow.Charge, expect.Charge[j])
			api.AssertIsEqual(flow.ChargedOutflow, expect.ChargedOutflow[j])
			api.AssertIsEqual(api.Add(flow.Debit, flow.Kept), expect.Held[j])
		}
	}
	owner, asset := policy.PaymentGuards(api, rc, payments, inputs)
	for p := range payments {
		api.AssertIsEqual(owner[p], c.OwnerGuards[p])
		api.AssertIsEqual(asset[p], c.AssetGuards[p])
	}
	return nil
}

func (tc quantityCase) notes(notes []quantityNote) []noteWires {
	wires := make([]noteWires, len(notes))
	for i, note := range notes {
		wires[i] = noteWires{Owner: note.Owner, Asset: note.Asset, Amount: note.Amount, Ring: ringtest.Bit(note.Ring), Exit: ringtest.Bit(!note.Ring)}
	}
	return wires
}

func (tc quantityCase) circuit(t *testing.T) *quantityCircuit {
	t.Helper()
	owners := []int64{}
	for _, input := range tc.Inputs {
		owners = append(owners, input.Owner)
	}
	slices.Sort(owners)
	owners = slices.Compact(owners)
	if len(owners) > quantityRows {
		t.Fatalf("%d owners", len(owners))
	}
	c := &quantityCircuit{Inputs: tc.notes(tc.Inputs), Outputs: tc.notes(tc.Outputs), Withdrawals: tc.notes(tc.Withdrawals)}
	for j := range quantityRows {
		if j < len(owners) {
			c.Rows = append(c.Rows, owners[j])
		} else {
			c.Rows = append(c.Rows, 0)
		}
	}
	for _, public := range tc.Public {
		c.PublicAssets, c.Gross = append(c.PublicAssets, public.Asset), append(c.Gross, public.Gross)
	}
	assets := []int64{}
	for _, note := range slices.Concat(tc.Inputs, tc.Outputs) {
		assets = append(assets, note.Asset)
	}
	for _, public := range tc.Public {
		assets = append(assets, public.Asset)
	}
	slices.Sort(assets)
	for _, asset := range slices.Compact(assets) {
		expect := quantityExpect{Asset: asset}
		for j := range quantityRows {
			var want quantityRow
			held := uint64(0)
			if j < len(owners) {
				if at := slices.IndexFunc(tc.Rows, func(r quantityRow) bool { return r.Owner == owners[j] && r.Asset == asset }); at >= 0 {
					want = tc.Rows[at]
				}
				for _, input := range tc.Inputs {
					if input.Owner == owners[j] && input.Asset == asset {
						held += input.Amount
					}
				}
			}
			expect.Debit, expect.Charge = append(expect.Debit, want.Debit), append(expect.Charge, want.Charge)
			expect.ChargedOutflow, expect.Held = append(expect.ChargedOutflow, want.ChargedOutflow), append(expect.Held, held)
		}
		c.Expect = append(c.Expect, expect)
	}
	for _, note := range slices.Concat(tc.Outputs, tc.Withdrawals) {
		owner := slices.IndexFunc(tc.Guards, func(g guardRow) bool { return g.Owner == note.Owner && g.Asset == note.Asset })
		asset := slices.IndexFunc(tc.AssetGuards, func(g assetGuardRow) bool { return g.Asset == note.Asset })
		if owner < 0 || asset < 0 {
			t.Fatalf("%s: no guard row for %d of %d", tc.Name, note.Owner, note.Asset)
		}
		c.OwnerGuards, c.AssetGuards = append(c.OwnerGuards, tc.Guards[owner].Guard), append(c.AssetGuards, tc.AssetGuards[asset].Guard)
	}
	return c
}

// world holds the case's thresholds on the full section, the mask is the one the proof reaches.
func (tc quantityCase) world() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Outputs, w.WithdrawalCapacity = 4, 2
	w.Table.Rules, w.Table.Limits, w.Slots = nil, nil, nil
	w.Approval = uint64(tc.Mask)
	for _, input := range tc.Inputs {
		w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: input.Owner, Asset: input.Asset, Amount: input.Amount, Exit: !input.Ring})
		if input.Owner != w.Sender && !slices.Contains(w.CoOwners, input.Owner) {
			w.CoOwners = append(w.CoOwners, input.Owner)
		}
	}
	if w.Inputs == nil {
		w.Inputs = []ringpolicy.Slot{}
	}
	for _, output := range tc.Outputs {
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: output.Owner, Asset: output.Asset, Amount: output.Amount, Exit: !output.Ring})
	}
	for _, withdrawal := range tc.Withdrawals {
		w.Withdrawals = append(w.Withdrawals, ringpolicy.Slot{Owner: withdrawal.Owner, Asset: withdrawal.Asset, Amount: withdrawal.Amount})
	}
	for _, public := range tc.Public {
		w.Public = append(w.Public, ringpolicy.PublicSlot{Asset: public.Asset, Gross: public.Gross})
	}
	for _, threshold := range tc.Thresholds {
		w.Table.Limits = append(w.Table.Limits, ringpolicy.OutflowLimit{Asset: threshold.Asset, CosignAbove: threshold.CosignAbove})
		w.Own[threshold.Asset] = ringpolicy.Record{WithdrawalThreshold: threshold.WithdrawalThreshold}
	}
	return w
}

// quantityCases pins the rounding, program-libs/policy/tests/quantities_vector.rs reads the same file.
func quantityCases() []quantityCase {
	note := func(owner int64, amount uint64) quantityNote { return quantityNote{owner, mintA, amount, true} }
	out := func(owner int64, amount uint64) quantityNote { return quantityNote{owner, mintA, amount, false} }
	row := func(owner int64, debit, kept, charge uint64) quantityRow {
		return quantityRow{owner, mintA, debit, kept, charge, debit + charge}
	}
	guard := func(owner int64, amount uint64) guardRow { return guardRow{owner, mintA, amount} }
	asset := func(amount uint64) []assetGuardRow { return []assetGuardRow{{mintA, amount}} }
	gross := func(amount uint64) []publicRow { return []publicRow{{mintA, amount}} }
	return []quantityCase{
		{Name: "a payment and change", Inputs: []quantityNote{note(s, 10_000)}, Outputs: []quantityNote{note(bob, 100), note(s, 9900)},
			Rows: []quantityRow{row(s, 100, 9900, 0)}, Guards: []guardRow{guard(bob, 100), guard(s, 0)}, AssetGuards: asset(100)},
		{Name: "another owner funds a same-owner receipt", Inputs: []quantityNote{note(s, 100), note(bob, 5000)}, Outputs: []quantityNote{note(s, 5100)},
			Rows: []quantityRow{row(bob, 5000, 0, 0)}, Guards: []guardRow{guard(s, 5000)}, AssetGuards: asset(5000)},
		{Name: "a default note counts as held and as a receipt", Inputs: []quantityNote{out(s, 1000)}, Outputs: []quantityNote{note(s, 600), note(bob, 400)},
			Rows: []quantityRow{row(s, 400, 600, 0)}, Guards: []guardRow{guard(s, 600), guard(bob, 400)}, AssetGuards: asset(1000)},
		{Name: "an exit and a withdrawal stay gross", Inputs: []quantityNote{note(s, 500)}, Outputs: []quantityNote{out(s, 200)}, Withdrawals: []quantityNote{out(s, 300)}, Public: gross(300),
			Rows: []quantityRow{row(s, 500, 0, 0)}, Guards: []guardRow{guard(s, 500)}, AssetGuards: asset(500)},
		{Name: "a deposit funds the return of funds that exit", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1000), out(alice, 1000)},
			Rows: []quantityRow{row(s, 0, 1000, 1000)}, Guards: []guardRow{guard(s, 0), guard(alice, 1000)}, AssetGuards: asset(1000)},
		{Name: "a deposit funds the return of a withdrawal", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1001)}, Withdrawals: []quantityNote{out(alice, 999)}, Public: gross(999),
			Rows: []quantityRow{row(s, 0, 1000, 999)}, Guards: []guardRow{guard(s, 1), guard(alice, 999)}, AssetGuards: asset(1000)},
		{Name: "an even share", Inputs: []quantityNote{note(s, 100), note(bob, 100)}, Outputs: []quantityNote{note(s, 100), note(bob, 100), out(alice, 100)},
			Rows: []quantityRow{row(s, 0, 100, 50), row(bob, 0, 100, 50)}, Guards: []guardRow{guard(s, 0), guard(bob, 0), guard(alice, 100)}, AssetGuards: asset(100)},
		{Name: "rounding telescopes to the amount", Inputs: []quantityNote{note(s, 2), note(bob, 1)}, Outputs: []quantityNote{note(s, 2), note(bob, 1), out(alice, 2)},
			Rows: []quantityRow{row(s, 0, 2, 1), row(bob, 0, 1, 1)}, Guards: []guardRow{guard(s, 0), guard(bob, 0), guard(alice, 2)}, AssetGuards: asset(2)},
		{Name: "rounding over three rows", Inputs: []quantityNote{note(s, 1), note(bob, 1), note(alice, 1)}, Outputs: []quantityNote{note(s, 1), note(bob, 1), note(alice, 1), out(s, 2)},
			Rows: []quantityRow{row(alice, 0, 1, 1), row(bob, 0, 1, 1)}, Guards: []guardRow{guard(s, 2), guard(bob, 0), guard(alice, 0)}, AssetGuards: asset(2)},
		{Name: "an owner who kept its funds is not charged", Inputs: []quantityNote{note(s, 1000), note(bob, 1000)}, Outputs: []quantityNote{note(s, 1000), out(alice, 1000)},
			Rows: []quantityRow{row(bob, 1000, 0, 0)}, Guards: []guardRow{guard(s, 0), guard(alice, 1000)}, AssetGuards: asset(1000)},
		{Name: "public funds passing through charge only held funds", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1000), out(alice, 5000)},
			Rows: []quantityRow{row(s, 0, 1000, 1000)}, Guards: []guardRow{guard(s, 0), guard(alice, 5000)}, AssetGuards: asset(5000)},
		{Name: "a no-spend deposit and exit charges nobody", Outputs: []quantityNote{out(alice, 500)},
			Guards: []guardRow{guard(alice, 500)}, AssetGuards: asset(500)},
		{Name: "a deposit-funded payment with nothing leaving", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1000), note(bob, 500)},
			Guards: []guardRow{guard(s, 0), guard(bob, 500)}, AssetGuards: asset(500)},
		{Name: "a mixed spend and deposit", Inputs: []quantityNote{note(s, 100), note(bob, 100)}, Outputs: []quantityNote{note(alice, 250)},
			Rows: []quantityRow{row(s, 100, 0, 0), row(bob, 100, 0, 0)}, Guards: []guardRow{guard(alice, 250)}, AssetGuards: asset(250)},
		{Name: "the outflow bit reads the charge", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1001)}, Withdrawals: []quantityNote{out(alice, 999)}, Public: gross(999),
			Rows: []quantityRow{row(s, 0, 1000, 999)}, Guards: []guardRow{guard(s, 1), guard(alice, 999)}, AssetGuards: asset(1000),
			Thresholds: []thresholdRow{{mintA, 100, 0}}, Mask: policy.ApprovalOutflow},
		{Name: "the withdrawal bit reads the gross with no debit", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(s, 1000)}, Public: gross(1000),
			Rows: []quantityRow{row(s, 0, 1000, 1000)}, Guards: []guardRow{guard(s, 0)}, AssetGuards: asset(0),
			Thresholds: []thresholdRow{{mintA, 0, 999}}, Mask: policy.ApprovalWithdrawal},
		{Name: "both bits", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(bob, 500)}, Withdrawals: []quantityNote{out(bob, 500)}, Public: gross(500),
			Rows: []quantityRow{row(s, 1000, 0, 0)}, Guards: []guardRow{guard(bob, 1000)}, AssetGuards: asset(1000),
			Thresholds: []thresholdRow{{mintA, 999, 499}}, Mask: policy.ApprovalOutflow | policy.ApprovalWithdrawal},
		{Name: "bounds at the amount set no bit", Inputs: []quantityNote{note(s, 1000)}, Outputs: []quantityNote{note(bob, 500)}, Withdrawals: []quantityNote{out(bob, 500)}, Public: gross(500),
			Rows: []quantityRow{row(s, 1000, 0, 0)}, Guards: []guardRow{guard(bob, 1000)}, AssetGuards: asset(1000),
			Thresholds: []thresholdRow{{mintA, 1000, 500}}},
	}
}

func TestQuantitiesVector(t *testing.T) {
	cases := quantityCases()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			c := tc.circuit(t)
			if err := test.IsSolved(c, c, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			w := tc.world()
			requireSolved(t, w.Build(t))
			if tc.Mask != 0 {
				w.Approval = 0
				requireRefusedIn(t, w, sectionDefine)
			}
			for _, row := range tc.Rows {
				c := tc.circuit(t)
				for a := range c.Expect {
					for j := range c.Expect[a].Charge {
						if c.Expect[a].Asset == row.Asset && c.Rows[j] == row.Owner {
							c.Expect[a].Charge[j] = row.Charge + 1
						}
					}
				}
				if test.IsSolved(c, c, ecc.BN254.ScalarField()) == nil {
					t.Fatalf("a charge off by one solved for owner %d", row.Owner)
				}
			}
		})
	}
	ringtest.PinVector(t, "policy/quantities.json", map[string]any{
		"description": "Output 5 quantities per owner and asset. An input with ring false is a default-ring note, held and no same-ring input. An output with ring false is an exit. A withdrawal is gross. public holds the statement-bound gross per asset. rows holds nonzero outflows by ascending owner then asset, outflow = debit + charge, every other row reads no debit and no charge. guards holds guard(owner, asset) and asset_guards its sum over distinct owners. mask is the proven approval mask, bit 1 outflow past cosign_above, bit 2 gross past withdrawal_threshold, zero meaning no threshold. Produced by prover/circuits/policy/quantities_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases":       cases,
	})
}
