package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type outputTotals struct {
	byOwner, byAsset, byOwnerAndAsset frontend.Variable
}

func (p *PolicyInputs) assertRules(api frontend.API, cmp comparator, table tableView, resolved subjects, outputs []utxoView) {
	// 1. Every payment's guard inputs fold once.
	screen := newPaymentScreen(api, cmp, resolved, outputs)
	// 2. A scalar guard sums one owner's outputs, under one every UTXO output carries one asset.
	assertScalarAssets(api, outputs, table.scalarOwner)
	// 3. Every active rule holds for its subjects, the sender once and each live output owner or asset.
	for r, rule := range table.rules {
		// The one sender meets every sender rule, with or without a spent input.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(table.ruleActive[r], rule.onSender), V: rule.refuses(api, resolved.sender.onList)})
		screen.assert(api, rule, api.Mul(table.ruleActive[r], api.Add(rule.onOwner, rule.onAsset)))
	}
}

type paymentScreen struct {
	cmp                    comparator
	resolved               subjects
	outputs                []utxoView
	liveOwner, assetExempt []frontend.Variable
	totals                 []outputTotals
}

func newPaymentScreen(api frontend.API, cmp comparator, resolved subjects, outputs []utxoView) paymentScreen {
	// 1. A zero owner carries no obligation, an asset needs no such gate since SPP refuses a UTXO of asset 0.
	liveOwner := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		liveOwner[o] = api.Mul(out.utxo, ringgadget.IsNonZero(api, out.ownerPkHash))
	}
	// 2. An asset guard exempts an owner whose outputs of one asset stay within the asset's inline limit.
	totals := sumOutputs(api, outputs, liveOwner)
	assetExempt := make([]frontend.Variable, len(outputs))
	for o := range outputs {
		assetExempt[o] = cmp.atMost(api, totals[o].byOwnerAndAsset, resolved.mintPolicies[o].threshold)
	}
	return paymentScreen{cmp: cmp, resolved: resolved, outputs: outputs, liveOwner: liveOwner, assetExempt: assetExempt, totals: totals}
}

// assert holds one rule for every live payment while onOutput is set.
func (s paymentScreen) assert(api frontend.API, rule ruleFields, onOutput frontend.Variable) {
	for o := range s.outputs {
		enabled := api.Mul(onOutput, api.Select(rule.onAsset, s.outputs[o].utxo, s.liveOwner[o]))
		refused := rule.refuses(api, subjectLists(api, rule.onAsset, s.resolved.assets[o], s.resolved.owners[o]))
		// An asset guarded rule needs an inline limit for the output's asset.
		transaction.AssertWhen(api, api.Mul(enabled, rule.assetGuard), ringgadget.IsNonZero(api, s.resolved.mintPolicies[o].threshold))
		total := api.Select(rule.onAsset, s.totals[o].byAsset, s.totals[o].byOwner)
		scalar := api.Mul(rule.scalarGuard, s.cmp.atMost(api, total, rule.threshold))
		exempt := api.Or(scalar, api.Mul(rule.assetGuard, s.assetExempt[o]))
		// A subject the lists refuse needs its amounts within the rule's guard.
		transaction.AssertWhen(api, api.Mul(enabled, refused), exempt)
	}
}

func assertScalarAssets(api frontend.API, outputs []utxoView, enabled frontend.Variable) {
	var asset, seen frontend.Variable = 0, 0
	for _, out := range outputs {
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(enabled, seen, out.utxo), A: asset, B: out.asset})
		asset = api.Select(out.utxo, out.asset, asset)
		seen = api.Or(seen, out.utxo)
	}
}

// sumOutputs gives each output the totals of every output sharing its owner, its asset or both.
func sumOutputs(api frontend.API, outputs []utxoView, liveOwner []frontend.Variable) []outputTotals {
	ownerAmounts, assetAmounts := make([]frontend.Variable, len(outputs)), make([]frontend.Variable, len(outputs))
	totals := make([]outputTotals, len(outputs))
	for o, out := range outputs {
		ownerAmounts[o], assetAmounts[o] = api.Mul(liveOwner[o], out.amount), api.Mul(out.utxo, out.amount)
		totals[o] = outputTotals{byOwner: ownerAmounts[o], byAsset: assetAmounts[o], byOwnerAndAsset: ownerAmounts[o]}
	}
	for i := range outputs {
		for j := range outputs[:i] {
			sameOwner := api.IsZero(api.Sub(outputs[i].ownerPkHash, outputs[j].ownerPkHash))
			sameAsset := api.IsZero(api.Sub(outputs[i].asset, outputs[j].asset))
			for _, pair := range [2][2]int{{i, j}, {j, i}} {
				into, from := pair[0], pair[1]
				owned := api.Mul(sameOwner, ownerAmounts[from])
				totals[into].byOwner = api.Add(totals[into].byOwner, owned)
				totals[into].byAsset = api.Add(totals[into].byAsset, api.Mul(sameAsset, assetAmounts[from]))
				totals[into].byOwnerAndAsset = api.Add(totals[into].byOwnerAndAsset, api.Mul(sameAsset, owned))
			}
		}
	}
	return totals
}

// refuses is set when no list admits the subject, neither a present list it is on nor an absent list it is off.
func (r ruleFields) refuses(api frontend.API, onList [NSources]frontend.Variable) frontend.Variable {
	admitting := r.admitBase
	for i, on := range onList {
		admitting = api.Add(admitting, api.Mul(on, r.admitWeight[i]))
	}
	// Each list adds 0, 1 or 2, the count is zero exactly when no list admits the subject.
	return api.IsZero(admitting)
}

func subjectLists(api frontend.API, onAsset frontend.Variable, asset, owner subjectView) [NSources]frontend.Variable {
	var onList [NSources]frontend.Variable
	for i := range onList {
		onList[i] = api.Select(onAsset, asset.onList[i], owner.onList[i])
	}
	return onList
}
