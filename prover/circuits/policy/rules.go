// Holds every sender, payment and spent asset to the table's rules, over the list bits subjects.go resolved.
//
// SPP moves any note its signer authorizes. A ring's rule names a subject, a sender, an output owner or an
// asset, and a set of lists that admit it, optionally only above an amount guard. Senders and inputs are
// private and a payment's owner and amount may be too, so the program cannot apply a rule.
//
// A guard reads totals and never one slot, per owner and asset for an owner rule and per asset for an asset
// rule. Splitting one payment across slots stays inside the same total. Change returned to its sender nets
// out, a sender paying itself receives nothing. Funds entering from the default ring stay a receipt, and an
// exit or a withdrawal stays gross. The totals mirror GuardScope in program-libs/policy/src/quantities.rs.
//
// Read after policy/subjects.go, policy/table.go, policy/withdrawals.go. Read before policy/comparator.go,
// policy/outflow.go.
//
// Properties:
// 1. Every live row meets every sender rule, a sender rule takes no guard.
// 2. Every live payment's nonzero owner meets every owner rule, and its asset every asset rule, unless the rule's guard exempts its total.
// 3. A scalar guard exempts a total at most the rule's threshold, a per asset guard an owner's total at most the mint's threshold, and an unguarded rule exempts nothing.
// 4. Every live input's asset meets every unguarded asset rule, a zero value input included.
// 5. A rule admits a subject on one of its present lists or off one of its absent lists.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Payment is an output slot or a withdrawal leg as the policy screens it, inactive on a dummy or past the count, Ring set on a same-ring output.
type Payment struct{ Owner, Asset, Amount, Active, Ring frontend.Variable }

func slotPayments(slots []shared.Output) []Payment {
	payments := make([]Payment, len(slots))
	for i, slot := range slots {
		payments[i] = Payment{Owner: slot.OwnerPkHash, Asset: slot.Asset, Amount: slot.Amount, Active: slot.Utxo, Ring: slot.Ring}
	}
	return payments
}

func screenedRules(api frontend.API, screened frontend.Variable, table tableView) []frontend.Variable {
	active := make([]frontend.Variable, len(table.rules))
	for r := range table.rules {
		active[r] = api.Mul(screened, table.ruleActive[r])
	}
	return active
}

// assertSenderRules holds every screened sender to every sender rule, with or without a spent input or an output.
func assertSenderRules(api frontend.API, active []frontend.Variable, table tableView, resolved subjects) {
	assertSubjectsAdmitted(api, active, table, resolved.senders, resolved.liveSenders, func(rule ruleFields) frontend.Variable { return rule.onSender })
}

// assertSubjectsAdmitted holds every live subject to the active rules selects sets, a key with no such subject carries no gate.
func assertSubjectsAdmitted(api frontend.API, active []frontend.Variable, table tableView, views []subjectView, live []frontend.Variable, selects func(ruleFields) frontend.Variable) {
	if len(views) == 0 {
		return
	}
	for r, rule := range table.rules {
		screened := api.Mul(active[r], selects(rule))
		for j, view := range views {
			// A zero row reads no lists, its one extra admission keeps it out of every rule.
			admitting := api.Add(rule.admitting(api, view.onList), api.Sub(1, live[j]))
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: screened, V: api.IsZero(admitting)})
		}
	}
}

// assertPaymentRules holds every live payment's owner and asset to every rule on them, inputs net same-ring receipts.
func assertPaymentRules(api frontend.API, cmp comparator, active []frontend.Variable, table tableView, resolved subjects, payments []Payment, inputs []shared.Output) {
	screen := newPaymentScreen(api, cmp, resolved, payments, inputs)
	for r, rule := range table.rules {
		screen.assert(api, rule, api.Mul(active[r], api.Add(rule.onOwner, rule.onAsset)))
	}
}

type paymentGuard struct{ owner, asset frontend.Variable }

type paymentScreen struct {
	cmp                    comparator
	resolved               subjects
	payments               []Payment
	liveOwner, assetExempt []frontend.Variable
	guards                 []paymentGuard
}

func newPaymentScreen(api frontend.API, cmp comparator, resolved subjects, payments []Payment, inputs []shared.Output) paymentScreen {
	// 1. A zero owner carries no obligation, an asset needs no such gate since SPP refuses a UTXO of asset 0.
	liveOwner := make([]frontend.Variable, len(payments))
	for o, pay := range payments {
		liveOwner[o] = api.Mul(pay.Active, ringgadget.IsNonZero(api, pay.Owner))
	}
	// 2. A mint without a threshold reads zero, a positive guard then needs the lists.
	guards := paymentGuards(api, cmp, payments, inputs)
	assetExempt := make([]frontend.Variable, len(payments))
	for o := range payments {
		assetExempt[o] = cmp.atMost(api, guards[o].owner, resolved.mintPolicies[o].threshold)
	}
	return paymentScreen{cmp: cmp, resolved: resolved, payments: payments, liveOwner: liveOwner, assetExempt: assetExempt, guards: guards}
}

func (s paymentScreen) assert(api frontend.API, rule ruleFields, onPayment frontend.Variable) {
	for o := range s.payments {
		// An asset rule reads every live payment, an owner rule only a nonzero owner.
		enabled := api.Mul(onPayment, api.Select(rule.onAsset, s.payments[o].Active, s.liveOwner[o]))
		refused := rule.refuses(api, subjectLists(api, rule.onAsset, s.resolved.assets[o], s.resolved.owners[o]))
		total := api.Select(rule.onAsset, s.guards[o].asset, s.guards[o].owner)
		scalar := api.Mul(rule.scalarGuard, s.cmp.atMost(api, total, rule.threshold))
		// An unguarded rule clears both tags and exempts nothing.
		exempt := api.Or(scalar, api.Mul(rule.assetGuard, s.assetExempt[o]))
		// A subject the lists refuse needs its amounts within the rule's guard.
		transaction.AssertWhen(api, api.Mul(enabled, refused), exempt)
	}
}

// paymentGuards gives each payment receipt + exit + paid of its owner and asset, and the sum of that over its asset's distinct owners.
func paymentGuards(api frontend.API, cmp comparator, payments []Payment, inputs []shared.Output) []paymentGuard {
	n := len(payments)
	// 1. Ring amounts net against same-ring inputs, an exit or a withdrawal stays gross.
	ringAmounts, grossAmounts := make([]frontend.Variable, n), make([]frontend.Variable, n)
	received, passing, repeats := make([]frontend.Variable, n), make([]frontend.Variable, n), make([]frontend.Variable, n)
	sameAsset := make([][]frontend.Variable, n)
	for p, pay := range payments {
		amount := api.Mul(pay.Active, pay.Amount)
		ringAmounts[p] = api.Mul(pay.Ring, amount)
		grossAmounts[p] = api.Sub(amount, ringAmounts[p])
		received[p], passing[p], repeats[p] = ringAmounts[p], grossAmounts[p], 0
		sameAsset[p] = make([]frontend.Variable, n)
		sameAsset[p][p] = 1
	}
	// 2. Each pair folds once, repeats counts the earlier live payments of one owner and asset.
	for p := range payments {
		for q := range payments[:p] {
			sameAsset[p][q] = IsSame(api, payments[p].Asset, payments[q].Asset)
			sameAsset[q][p] = sameAsset[p][q]
			samePair := api.Mul(sameAsset[p][q], IsSame(api, payments[p].Owner, payments[q].Owner))
			received[p] = api.Add(received[p], api.Mul(samePair, ringAmounts[q]))
			received[q] = api.Add(received[q], api.Mul(samePair, ringAmounts[p]))
			passing[p] = api.Add(passing[p], api.Mul(samePair, grossAmounts[q]))
			passing[q] = api.Add(passing[q], api.Mul(samePair, grossAmounts[p]))
			repeats[p] = api.Add(repeats[p], api.Mul(samePair, payments[q].Active))
		}
	}
	// 3. A default-ring input reads no Ring flag, entry funding stays a receipt.
	guards := make([]paymentGuard, n)
	for p, pay := range payments {
		spent := frontend.Variable(0)
		for _, input := range inputs {
			held := api.Mul(input.Ring, IsSame(api, input.OwnerPkHash, pay.Owner), IsSame(api, input.Asset, pay.Asset))
			spent = api.Add(spent, api.Mul(held, input.Amount))
		}
		guards[p].owner = api.Add(cmp.saturatingSub(api, received[p], spent), passing[p])
	}
	// 4. Only the first payment of an owner and asset counts toward the asset's sum. Every payment of the pair holds the same owner guard, a second count would inflate the asset's total.
	for p := range payments {
		guards[p].asset = 0
		for q, pay := range payments {
			first := api.Mul(pay.Active, api.IsZero(repeats[q]))
			guards[p].asset = api.Add(guards[p].asset, api.Mul(sameAsset[p][q], first, guards[q].owner))
		}
	}
	return guards
}

// assertInputAssetRules holds every live input's asset to every unconditional asset rule, a ring note and a default ring note alike.
//
// A payment screens the asset it moves, and SPP's balance keeps a funded input's asset among the output and public assets. A zero value input can name any asset with nothing paid in it, the one spend the payment section never reads, and it would move a delisted note past the rules.
//
// A guarded rule stays out. Its obligation reads the payment totals, an input adds nothing to them, and a total of zero sits within every threshold. A guarded rule can then refuse only at a payment of the asset, and the payment section already holds that one.
func assertInputAssetRules(api frontend.API, active []frontend.Variable, table tableView, resolved subjects) {
	assertSubjectsAdmitted(api, active, table, resolved.inputAssets, resolved.liveInputs, func(rule ruleFields) frontend.Variable {
		// The guard tags exclude each other, the difference reads GuardAlways.
		return api.Mul(rule.onAsset, api.Sub(1, api.Add(rule.scalarGuard, rule.assetGuard)))
	})
}

// refuses is set when no list admits the subject, neither a present list it is on nor an absent list it is off.
func (r ruleFields) refuses(api frontend.API, onList [NSources]frontend.Variable) frontend.Variable {
	return api.IsZero(r.admitting(api, onList))
}

// Each list adds 0, 1 or 2 so no sum wraps to zero.
func (r ruleFields) admitting(api frontend.API, onList [NSources]frontend.Variable) frontend.Variable {
	admitting := r.admitBase
	for i, on := range onList {
		admitting = api.Add(admitting, api.Mul(on, r.admitWeight[i]))
	}
	return admitting
}

func subjectLists(api frontend.API, onAsset frontend.Variable, asset, owner subjectView) [NSources]frontend.Variable {
	var onList [NSources]frontend.Variable
	for i := range onList {
		onList[i] = api.Select(onAsset, asset.onList[i], owner.onList[i])
	}
	return onList
}
