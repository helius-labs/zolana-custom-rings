// The entry point of the policy, one Screen call runs every section once over the slots transfer opened.
//
// A ring statement carries a proven approval mask and an optional digest of the totals. SPP has neither.
// The program demands a co-signer per mask bit and derives no threshold itself, so a wrong mask would
// silently drop an approval.
//
// Read after policy/policy.go, transfer/owners.go. Read before policy/withdrawals.go, policy/table.go,
// policy/subjects.go, policy/rules.go, policy/outflow.go.
//
// Properties:
// 1. Withdrawal legs join the payments only once WithdrawalHash binds them.
// 2. The rule sections run over one payment list.
// 3. The rows ascend strictly with zero rows last, off the authority rail.
// 4. A nonzero approval totals digest opens to the outflow section's values, it refuses while the section is off.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Senders follow the rail's owner predicates.
type Spend struct {
	Senders []frontend.Variable
	Inputs  []shared.Output
	// Tracking binds each owner's salt.
	Tracking TrackingPool
}

// ApprovalMask reads zero while Outflow is off.
type Screening struct {
	ApprovalMask frontend.Variable
	// Asset, peak and outflow per output slot, then asset, peak, outflow and gross per public slot, mirrored by ApprovalTotals in program-libs/policy/src/approval_totals.rs.
	totals  []frontend.Variable
	outflow frontend.Variable
	// SaltedPayees is set while every live payee reads its tracking row for a salted list.
	SaltedPayees frontend.Variable
}

// Screen holds a spend to the policy, withdrawal legs join the payments only once their hash binds them.
func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, g Gates, spend Spend, outputs []shared.Output) Screening {
	cmp := newComparator(rc)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	resolved := p.screenPayments(api, cmp, g, spend, payments)
	// The outflow section binds on a ring with an own registry, with or without a policy hash.
	screening := p.constrainOutflow(api, cmp, g.Outflow, spend, outputs, resolved)
	screening.SaltedPayees = resolved.saltedPayees
	return screening
}

// screenPayments runs the rule sections over one flow.
func (p *Policy) screenPayments(api frontend.API, cmp comparator, g Gates, spend Spend, payments []Payment) subjects {
	// 1. While Screened, the table is the one the program hashed at policy_hash. A clear table binds nothing because every rule below reads through the same gate.
	table := p.Table.decodeWhen(api, cmp.rc, g.Screened, p.PolicyHash)
	// 2. Every subject now holds list bits its registry's root authenticates, so the rule sections can trust a view without reading a proof.
	resolved := p.resolveSubjects(api, table, g, spend, payments)
	active := screenedRules(api, g.Screened, table)
	// 3. The rows are strictly ascending with zero rows last, and every live row meets every sender rule. Attribution in the outflow section relies on the order, a repeated row would count its funds twice.
	assertRowsAscending(api, g.Rows, spend.Senders, resolved.liveSenders)
	assertSenderRules(api, active, table, resolved)
	// 4. Every live payment's owner and asset meet their rules within the guard totals, the only section where amounts decide a rule.
	assertPaymentRules(api, cmp, active, table, resolved, payments, spend.Inputs)
	// 5. Every live input's asset meets the unconditional asset rules, list bits alone decide and no amount enters a total.
	assertInputAssetRules(api, active, table, resolved)
	return resolved
}

// AssertApprovalTotals binds a nonzero commitment to the totals, a co-signer opens it off chain and zero discloses nothing.
//
// A co-signer that approves exact amounts needs totals the chain must not read. The statement carries the digest alone, and the co-signer receives the totals and the blinder off chain and rehashes them. The hash reads the values the outflow section computed, a total understated to the co-signer opens another digest. A digest with no blinder would let anyone test guessed totals against the chain, so the blinder enters the hash and no statement.
func (s Screening) AssertApprovalTotals(api frontend.API, commitment, blinder frontend.Variable) {
	disclosed := ringgadget.IsNonZero(api, commitment)
	hash := gadget.HashChain4(api, append([]frontend.Variable{shared.ApprovalTotalsDomain, blinder}, s.totals...))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: disclosed, A: commitment, B: hash})
	// Off the outflow section the gross reads zero, a charge would read short.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, s.outflow), V: disclosed})
}
