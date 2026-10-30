// Counts how much of each token a transfer sends away from the sender,
// withdrawals included, and holds it within the token's cap. A transfer above
// the co-sign limit is marked as needing co-signer approval.
//
// Read after policy/rules.go, policy/subjects.go. Read before policy/member.go.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type mintPolicyWires struct{ threshold, cap, cosignAbove frontend.Variable }

type publicAsset struct {
	asset, active frontend.Variable
	policy        mintPolicyWires
}

// Every output and public asset opens its own record, including absence. The
// transaction, rather than a sender-supplied list of limits, determines coverage.
func (p *PolicyInputs) constrainOutflow(api frontend.API, cmp comparator, sender frontend.Variable, outputs []utxoView, resolved subjects) frontend.Variable {
	leaving := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		change := api.Mul(api.IsZero(api.Sub(out.ownerPkHash, sender)), api.IsZero(api.Sub(out.ringProgramID, p.RingProgramID)))
		leaving[o] = api.Mul(out.utxo, api.Sub(1, change), out.amount)
	}
	approval := frontend.Variable(0)
	check := func(asset, active frontend.Variable, policy mintPolicyWires) {
		others, net := frontend.Variable(0), frontend.Variable(0)
		for o, out := range outputs {
			others = api.Add(others, api.Mul(api.IsZero(api.Sub(out.asset, asset)), leaving[o]))
		}
		// SPP's distinct u64 public slots keep net within u64 magnitude, the bound atMost needs.
		for k, publicAsset := range p.PublicAssets {
			net = api.Add(net, api.Mul(api.IsZero(api.Sub(publicAsset, asset)), p.PublicAmounts[k]))
		}
		limited := api.Mul(active, api.Or(ringgadget.IsNonZero(api, policy.cap), ringgadget.IsNonZero(api, policy.cosignAbove)))
		// Only a limited asset needs a nonnegative outflow, an unlimited asset may take any public deposit.
		transaction.AssertWhen(api, limited, cmp.atMost(api, net, others))
		outflow := api.Sub(others, net)
		transaction.AssertWhen(api, api.Mul(active, ringgadget.IsNonZero(api, policy.cap)), cmp.atMost(api, outflow, policy.cap))
		cosigned := api.Mul(active, ringgadget.IsNonZero(api, policy.cosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, cmp.atMost(api, outflow, policy.cosignAbove))))
	}
	for o, out := range outputs {
		check(out.asset, out.utxo, resolved.mintPolicies[o])
	}
	for _, public := range resolved.publicAssets {
		check(public.asset, public.active, public.policy)
	}
	return approval
}
