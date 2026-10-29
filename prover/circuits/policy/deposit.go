package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type DepositAssets struct {
	Table        Table
	AssetRecords []registry.QuadOpening
}

// DepositSlot is zero past the deposit count.
type DepositSlot struct{ Owner, Asset, Amount, Active frontend.Variable }

func NewDepositAssets(capacity int) DepositAssets {
	return DepositAssets{AssetRecords: make([]registry.QuadOpening, capacity)}
}

// Assert screens nothing under a zero policyHash, the program binds zero off a policy ring.
func (d DepositAssets) Assert(api frontend.API, rc frontend.Rangechecker, policyHash, ownRoot frontend.Variable, deposits []DepositSlot) {
	// 1. A nonzero policy_hash fixes the table the rules read.
	screened := ringgadget.IsNonZero(api, policyHash)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: screened, A: policyHash, B: d.Table.hash(api)})
	table := d.Table.view(api, rc)
	// 2. A deposit opens no curator root, an active asset rule on a curator list refuses it.
	for r, rule := range table.rules {
		reads := frontend.Variable(0)
		for i, foreign := range table.sources.foreign {
			reads = api.Add(reads, api.Mul(foreign, api.Add(rule.listBits[i], rule.altBits[i])))
		}
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(table.ruleActive[r], rule.onAsset), V: reads})
	}
	// 3. Each deposited asset opens its record, or its absence, under own_root.
	resolved := subjects{assets: make([]subjectView, len(deposits)), mintPolicies: make([]mintPolicyWires, len(deposits))}
	payments := make([]utxoView, len(deposits))
	for i, deposit := range deposits {
		active := api.Mul(screened, deposit.Active)
		// The comparator width holds for u64 amounts only.
		rc.Check(deposit.Amount, 64)
		lists, _, mintPolicy, _ := d.AssetRecords[i].Resolve(api, active, ownRoot, deposit.Asset)
		resolved.assets[i] = subjectView{onList: sourceLists(api, lists), escrowKey: 0}
		resolved.mintPolicies[i] = decodeMintPolicy(api, mintPolicy)
		payments[i] = utxoView{ownerPkHash: deposit.Owner, asset: deposit.Asset, amount: deposit.Amount, utxo: active}
	}
	// Only asset rules reach a deposit, the owner lists stay unread.
	resolved.owners = resolved.assets
	// 4. Every active asset rule holds for each deposit as for a transfer output.
	screen := newPaymentScreen(api, newComparator(rc, len(deposits)), resolved, payments)
	for r, rule := range table.rules {
		screen.assert(api, rule, api.Mul(table.ruleActive[r], rule.onAsset))
	}
}
