// Applies the ring's token rules to a deposit. A deposit has no separate policy
// proof, so the deposit proof runs these checks itself.
//
// Read after policy/rules.go, registry/opening.go. Read before deposit.go.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type DepositAssets struct {
	Table               Table
	AssetRecords        []registry.QuadOpening
	CuratorRoot         frontend.Variable
	CuratorAssetRecords []registry.QuadOpening
}

// DepositSlot is zero past the deposit count.
type DepositSlot struct{ Owner, Asset, Amount, Active frontend.Variable }

func NewDepositAssets(capacity int) DepositAssets {
	return DepositAssets{AssetRecords: make([]registry.QuadOpening, capacity), CuratorAssetRecords: make([]registry.QuadOpening, capacity)}
}

// Assert screens nothing under a zero policyHash, the program binds zero off a policy ring.
func (d DepositAssets) Assert(api frontend.API, rc frontend.Rangechecker, policyHash, ownRoot frontend.Variable, deposits []DepositSlot) {
	// 1. A nonzero policy_hash fixes the table the rules read.
	screened := ringgadget.IsNonZero(api, policyHash)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: screened, A: policyHash, B: d.Table.hash(api)})
	table := d.Table.view(api, rc)
	// 2. Each deposited asset opens its record, or its absence, under own_root and under curator_root when a source names the curator.
	resolved := subjects{assets: make([]subjectView, len(deposits)), mintPolicies: make([]mintPolicyWires, len(deposits))}
	payments := make([]utxoView, len(deposits))
	for i, deposit := range deposits {
		active := api.Mul(screened, deposit.Active)
		// The comparator width holds for u64 amounts only.
		rc.Check(deposit.Amount, 64)
		lists, _, mintPolicy, _ := d.AssetRecords[i].Resolve(api, active, ownRoot, deposit.Asset)
		curated, _, _, _ := d.CuratorAssetRecords[i].Resolve(api, api.Mul(active, table.sources.anyForeign), d.CuratorRoot, deposit.Asset)
		resolved.assets[i] = subjectView{onList: table.sources.lists(api, sourceLists(api, lists), sourceLists(api, curated)), escrowKey: 0}
		resolved.mintPolicies[i] = decodeMintPolicy(api, mintPolicy)
		payments[i] = utxoView{ownerPkHash: deposit.Owner, asset: deposit.Asset, amount: deposit.Amount, utxo: active}
	}
	// Only asset rules reach a deposit, the owner lists stay unread.
	resolved.owners = resolved.assets
	// 3. Every active asset rule holds for each deposit as for a transfer output.
	screen := newPaymentScreen(api, newComparator(rc, len(deposits)), resolved, payments)
	for r, rule := range table.rules {
		screen.assert(api, rule, api.Mul(table.ruleActive[r], rule.onAsset))
	}
}
