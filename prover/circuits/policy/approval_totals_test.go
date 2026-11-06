// Refusals of the approval totals digest, a digest over understated values and a digest with the outflow section off.

package policy_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const approvalTotalsCheck = "policy.Screening.AssertApprovalTotals"

// totalsCase holds the commitment program-libs/policy/tests/approval_totals_vector.rs rebuilds from the quantities case of the same name.
type totalsCase struct {
	Name       string `json:"name"`
	Slots      int    `json:"slots"`
	Blinder    string `json:"blinder"`
	Commitment string `json:"commitment"`
}

func peakAndSum(tc quantityCase, asset int64, read func(quantityRow) uint64) (peak, sum uint64) {
	for _, row := range tc.Rows {
		if row.Asset == asset {
			peak, sum = max(peak, read(row)), sum+read(row)
		}
	}
	return peak, sum
}

// layout is the fixed field order of ApprovalTotals::commitment, outside the circuit.
func (tc quantityCase) layout(slots int) []*big.Int {
	field := func(value uint64) *big.Int { return new(big.Int).SetUint64(value) }
	fields := make([]*big.Int, 0, 3*slots+4*transaction.NPublicSlots)
	for o := range slots {
		if o >= len(tc.Outputs) {
			fields = append(fields, field(0), field(0), field(0))
			continue
		}
		peak, sum := peakAndSum(tc, tc.Outputs[o].Asset, func(row quantityRow) uint64 { return row.ChargedOutflow })
		fields = append(fields, big.NewInt(tc.Outputs[o].Asset), field(peak), field(sum))
	}
	for k := range transaction.NPublicSlots {
		if k >= len(tc.Public) {
			fields = append(fields, field(0), field(0), field(0), field(0))
			continue
		}
		peak, sum := peakAndSum(tc, tc.Public[k].Asset, func(row quantityRow) uint64 { return row.Debit })
		fields = append(fields, big.NewInt(tc.Public[k].Asset), field(peak), field(sum), field(tc.Public[k].Gross))
	}
	return fields
}

func commitTotals(t testing.TB, blinder *big.Int, layout []*big.Int) *big.Int {
	t.Helper()
	return spptest.MustHashChain4(t, append([]*big.Int{big.NewInt(shared.ApprovalTotalsDomain), blinder}, layout...))
}

func disclosed(t *testing.T, w ringpolicy.World, blinder *big.Int, layout []*big.Int) ringpolicy.Witness {
	t.Helper()
	b := w.Build(t)
	b.Circuit.ApprovalBlinder, b.Circuit.ApprovalTotals = blinder, commitTotals(t, blinder, layout)
	b.Rebind(t)
	return b
}

func TestApprovalTotalsBindTheProvedOutflow(t *testing.T) {
	blinder := big.NewInt(0x51)
	var vector []totalsCase
	for _, tc := range quantityCases() {
		t.Run(tc.Name, func(t *testing.T) {
			w := tc.world()
			layout := tc.layout(w.Outputs)
			b := disclosed(t, w, blinder, layout)
			requireSolved(t, b)
			vector = append(vector, totalsCase{Name: tc.Name, Slots: w.Outputs, Blinder: ringtest.FieldHex(blinder), Commitment: ringtest.FieldHex(ringtest.AsBigInt(b.Circuit.ApprovalTotals))})
			for i := range layout {
				false_ := append([]*big.Int{}, layout...)
				false_[i] = new(big.Int).Add(layout[i], big.NewInt(1))
				ringtest.RequireRefused(t, solveWitness(disclosed(t, w, blinder, false_)), approvalTotalsCheck)
			}
		})
	}
	ringtest.PinVector(t, "policy/approval_totals.json", map[string]any{
		"description": "HashChain4(CRAO, blinder, layout) over each policy/quantities.json case. The layout is asset, peak and charged outflow per output slot, then asset, peak of debits, sum of debits and gross per public slot, zeros past the live slots. Produced by prover/circuits/policy/approval_totals_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases":       vector,
	})
}

// Private assets no public slot names read under their output slots.
func TestApprovalTotalsCoverPrivateAssets(t *testing.T) {
	note := func(owner, asset int64, amount uint64) quantityNote { return quantityNote{owner, asset, amount, true} }
	tc := quantityCase{
		Name:    "two private assets",
		Inputs:  []quantityNote{note(s, mintA, 100), note(s, mintB, 50)},
		Outputs: []quantityNote{note(bob, mintA, 100), note(alice, mintB, 50)},
		Rows:    []quantityRow{{s, mintA, 100, 0, 0, 100}, {s, mintB, 50, 0, 0, 50}},
	}
	w := tc.world()
	requireSolved(t, disclosed(t, w, big.NewInt(0x51), tc.layout(w.Outputs)))
	dropped := tc.layout(w.Outputs)
	dropped[3], dropped[4], dropped[5] = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	ringtest.RequireRefused(t, solveWitness(disclosed(t, w, big.NewInt(0x51), dropped)), approvalTotalsCheck)
}

func solveWitness(b ringpolicy.Witness) error {
	return test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
}

// A commitment that reads the lower owner as the peak needs a peak the range check refuses.
func TestApprovalTotalsCannotUnderstateOutflow(t *testing.T) {
	inputs := []ringpolicy.Slot{slot(s, 1000), slot(bob, 100)}
	outputs := []ringpolicy.Slot{slot(alice, 1100)}
	const limit = 2000
	understated := []*big.Int{big.NewInt(mintA), big.NewInt(100), big.NewInt(1100)}
	for range 3 {
		understated = append(understated, big.NewInt(0), big.NewInt(0), big.NewInt(0))
	}
	for range transaction.NPublicSlots {
		understated = append(understated, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
	}
	blinder := big.NewInt(0x51)
	b := disclosed(t, outflowWorld(inputs, outputs, nil, limit), blinder, understated)
	ringtest.RequireRefused(t, solveWitness(b), approvalTotalsCheck)
	witness, err := frontend.NewWitness(b.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	hintattack.RequireConstraintRejection(t, ringkey.Compile(t, b.Assignment()).IsSolved(witness, hintattack.SkipMissingLookupQueries(t), solver.OverrideHint(solver.GetHintID(policy.PeakHint), secondLargest)))
}

// Off the outflow section the gross reads zero and a charge would read short.
func TestApprovalTotalsNeedTheOutflowSection(t *testing.T) {
	for name, set := range map[string]func(*ringpolicy.World){
		"no own registry": func(w *ringpolicy.World) { w.NoOwnRegistry = true },
		"the delegate":    func(w *ringpolicy.World) { w.Delegate = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := outflowWorld([]ringpolicy.Slot{slot(s, 100)}, []ringpolicy.Slot{slot(alice, 100)}, nil, 0)
			w.Unscreened = true
			set(&w)
			requireSolved(t, w.Build(t))
			b := w.Build(t)
			b.Circuit.ApprovalTotals = 7
			b.Rebind(t)
			ringtest.RequireRefused(t, solveWitness(b), approvalTotalsCheck)
		})
	}
}
