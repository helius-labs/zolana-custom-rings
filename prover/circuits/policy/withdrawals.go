package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// WithdrawalWires names the screened owner, asset and gross amount of a public leg.
// These payments do not enter private_tx_hash, escrow or net outflow a second time.
type WithdrawalWires struct{ Owner, Asset, Amount frontend.Variable }

func (p *PolicyInputs) openWithdrawals(api frontend.API, rc frontend.Rangechecker) []utxoView {
	count := ringgadget.SelectCount(api, p.WithdrawalCount, 0, len(p.Withdrawals)+1)
	fields := []frontend.Variable{shared.WithdrawalsDomain, p.WithdrawalCount}
	payments := make([]utxoView, len(p.Withdrawals))
	for i, w := range p.Withdrawals {
		active := count.Active[i]
		rc.Check(w.Amount, 64)
		// A live leg is one the program builds, a nonzero amount of a nonzero asset as the rules assume of a live UTXO.
		api.AssertIsEqual(api.Mul(active, api.IsZero(w.Amount)), 0)
		api.AssertIsEqual(api.Mul(active, api.IsZero(w.Asset)), 0)
		// An inactive leg is zero, the zero padding paddedWithdrawalHash reads.
		for _, v := range []frontend.Variable{w.Owner, w.Asset, w.Amount} {
			api.AssertIsEqual(api.Mul(api.Sub(1, active), v), 0)
		}
		fields = append(fields, w.Owner, w.Asset, w.Amount)
		payments[i] = utxoView{ownerPkHash: w.Owner, asset: w.Asset, amount: w.Amount, utxo: active}
	}
	api.AssertIsEqual(p.WithdrawalHash, paddedWithdrawalHash(api, fields, count.OneHot))
	return payments
}

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
