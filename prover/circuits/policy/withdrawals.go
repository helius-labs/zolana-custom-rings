// Opens the public withdrawal legs for the payment rules.
//
// SPP publishes one signed net per public slot and leaves the destination to settlement, so its
// statement names neither a leg's owner nor its gross. A rule on a recipient needs both. The program
// reads each leg from its settlement accounts and hashes the list, the proof opens the same list.
// Without the binding a withdrawal to a blocked owner would read as a leg to anyone.
//
// Read after policy/screen.go. Read before policy/rules.go.
//
// Properties:
// 1. WithdrawalHash opens to WithdrawalCount legs, the program's policy_withdrawal_hash over them in order.
// 2. A live leg holds a nonzero asset and a nonzero amount below 2^64, a leg past the count is zero.
// 3. Every leg reads as a payment with Ring clear, so the rules see it gross and no input nets it.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// WithdrawalWires feeds the payment rules alone, the charged outflow reads the statement's gross.
type WithdrawalWires struct{ Owner, Asset, Amount frontend.Variable }

func (p *PolicyInputs) openWithdrawals(api frontend.API, rc frontend.Rangechecker) []Payment {
	count := ringgadget.SelectCount(api, p.WithdrawalCount, 0, len(p.Withdrawals)+1)
	fields := []frontend.Variable{shared.WithdrawalsDomain, p.WithdrawalCount}
	payments := make([]Payment, len(p.Withdrawals))
	for i, w := range p.Withdrawals {
		active := count.Active[i]
		rc.Check(w.Amount, 64)
		// A live leg is one the program builds, a nonzero amount of a nonzero asset as the rules assume of a live UTXO.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: active, V: api.IsZero(w.Amount)})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: active, V: api.IsZero(w.Asset)})
		// An inactive leg is zero, the zero padding paddedWithdrawalHash reads.
		for _, v := range []frontend.Variable{w.Owner, w.Asset, w.Amount} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: v})
		}
		fields = append(fields, w.Owner, w.Asset, w.Amount)
		payments[i] = Payment{Owner: w.Owner, Asset: w.Asset, Amount: w.Amount, Active: active, Ring: 0}
	}
	api.AssertIsEqual(p.WithdrawalHash, paddedWithdrawalHash(api, fields, count.OneHot))
	return payments
}

// paddedWithdrawalHash mirrors policy_withdrawal_hash in program-libs/interface/src/instructions/withdrawals.rs, the chain head at block i is the hash of i legs and the one set flag keeps it.
// The count sits in the first block, two lists that agree over trailing zeros hash apart.
func paddedWithdrawalHash(api frontend.API, fields, counts []frontend.Variable) frontend.Variable {
	head, selected := frontend.Variable(fields[0]), frontend.Variable(0)
	for i, active := range counts {
		group := []frontend.Variable{head, 0, 0, 0}
		start := 1 + 3*i
		copy(group[1:], fields[start:min(start+3, len(fields))])
		// Inactive withdrawal fields supply the selected block's zero padding.
		head = gadget.PoseidonHash(api, group)
		selected = api.Add(selected, api.Mul(active, head))
	}
	return selected
}
