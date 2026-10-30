// Finds the lists and limits of the sender, every recipient and every token.
// Lists can come from a curator's registry, but limits and escrow keys always
// come from the ring's own registry.
//
// Read after policy/record_pool.go, policy/table.go. Read before
// policy/rules.go, policy/outflow.go.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type subjectView struct {
	// onList[i] is set when the subject is on list i+1 in the registry serving the list.
	onList [NSources]frontend.Variable
	// escrowKey is the own record's escrow key, zero for an absent member.
	escrowKey frontend.Variable
}

type subjects struct {
	sender         subjectView
	owners, assets []subjectView
	mintPolicies   []mintPolicyWires
	publicAssets   []publicAsset
}

func (p *Policy) resolveSubjects(api frontend.API, table tableView, sender frontend.Variable, payments []utxoView) subjects {
	own := openSubjectPool(api, openRecordPool(api, 1, p.OwnRoot, p.OwnRecords, p.OwnProof), p.OwnSubjects)
	var curator subjectPool
	if !p.OwnOnly {
		curator = openSubjectPool(api, openRecordPool(api, table.sources.anyForeign, p.CuratorRoot, p.CuratorRecords, p.CuratorProof), p.CuratorSubjects)
	}
	resolve := func(entry PoolEntry, active, member frontend.Variable) (subjectView, mintPolicyWires) {
		record := own.resolve(api, recordQuery{active: active, member: member, index: entry.Own})
		view := subjectView{onList: record.onList, escrowKey: record.escrowKey}
		if !p.OwnOnly {
			curated := curator.resolve(api, recordQuery{active: api.Mul(active, table.sources.anyForeign), member: member, index: entry.Curator[0]})
			view.onList = table.sources.lists(api, record.onList, curated.onList)
		}
		return view, record.mintPolicy
	}
	resolved := subjects{owners: make([]subjectView, len(payments)), assets: make([]subjectView, len(payments)), mintPolicies: make([]mintPolicyWires, len(payments))}
	resolved.sender, _ = resolve(p.SenderEntry, 1, sender)
	for i, pay := range payments {
		resolved.owners[i], _ = resolve(p.OwnerEntries[i], pay.utxo, pay.ownerPkHash)
		resolved.assets[i], resolved.mintPolicies[i] = resolve(p.AssetEntries[i], pay.utxo, pay.asset)
	}
	for k, index := range p.PublicAssetEntries {
		asset := p.PublicAssets[k]
		active := ringgadget.IsNonZero(api, asset)
		record := own.resolve(api, recordQuery{active: active, member: asset, index: index})
		resolved.publicAssets = append(resolved.publicAssets, publicAsset{asset: asset, active: active, policy: record.mintPolicy})
	}
	return resolved
}

func (p *PolicyInputs) assertEscrow(api frontend.API, keyEscrow frontend.Variable, owners []subjectView, outputs []utxoView) {
	for o, out := range outputs {
		escrowed := api.Mul(out.utxo, keyEscrow)
		key := registry.EscrowKey(api, out.nullifierPk, p.Outputs[o].CtHash)
		// The owner's record escrows Poseidon(nullifier_pk, ct_hash), an absent owner resolves zero and never matches.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: owners[o].escrowKey, B: key})
	}
}

func (p *PolicyInputs) assertOwnOnly(api frontend.API) {
	if !p.OwnOnly {
		return
	}
	// The own-only key reads every list from own_root, a curator source or root would be screened against the wrong registry.
	api.AssertIsEqual(p.CuratorRoot, 0)
	for _, source := range p.Sources {
		api.AssertIsEqual(source.Registry, 0)
	}
}
