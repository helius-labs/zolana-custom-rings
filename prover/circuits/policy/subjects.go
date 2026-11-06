// Gives every subject of a transfer its list bits, and derives the gates that switch the sections on.
//
// SPP reads no list. A rule needs to know whether a private owner or asset sits on a list, and the answer
// must come from a registry root the program read live, never from the prover. Each subject
// turns into list bits by way of the record pools, so the rule sections trust a view and read no proof.
// An owner reads every list at the lookup key Poseidon(CRPL, owner, salt). A public list reads at salt zero,
// a key anyone derives from the owner. A private list reads at the owner's enrolled salt, a key the chain
// cannot tie to the owner. An asset reads at its own field.
//
// Read after policy/table.go, policy/record_pool.go, policy/tracking.go. Read before policy/rules.go,
// policy/outflow.go.
//
// Properties:
// 1. The gates follow from statement values alone, no prover bit clears a section. Screened is a nonzero policy_hash off the authority rail. Outflow is a nonzero own root.
// 2. Each read goes through a pool under the bound root of its source, own or curator per list, present or proven absent.
// 3. An owner reads each public list at its zero salt key, an enrolled owner each private list at the one key its tracking row fixes.
// 4. An owner proven absent under the tracking root reads off every private list.
// 5. A padded row, a dummy, an unused payment and an unused public slot close their gates and read zeros.
// 6. A live input's asset reads its lists under Screened alone and decodes no mint policy.
// 7. A mint policy reads from the own record alone, an asset with no record reads no limit.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type subjectView struct {
	// onList[i] is set when the subject is on list i+1 in the registry serving the list.
	onList [NSources]frontend.Variable
}

type subjects struct {
	senders        []subjectView
	liveSenders    []frontend.Variable
	owners, assets []subjectView
	// inputAssets[i] is the asset of input slot i, liveInputs[i] is set on a spent note.
	inputAssets  []subjectView
	liveInputs   []frontend.Variable
	mintPolicies []mintPolicyWires
	publicAssets []publicAsset
}

// Rail is what the statement and the key fix about a transfer's rail, the one source of every section gate.
type Rail struct {
	// ThresholdsActive is set on a ring with an own policy registry off the authority rail, independent of policy_hash.
	ThresholdsActive frontend.Variable
	// Delegate is the authority rail, it bypasses the rules, the caps and the approval.
	Delegate frontend.Variable
}

// Gates switch the policy sections on, derived once from the rail and policy_hash.
type Gates struct {
	// Screened is set when policy_hash is nonzero off the authority rail, the table and the rules then bind.
	Screened frontend.Variable
	// Outflow switches the caps, the approval mask and the own root read of both.
	Outflow frontend.Variable
	// Rows holds the owner rows ascending, off the authority rail.
	Rows frontend.Variable
}

func (r Rail) Gates(api frontend.API, policyHash frontend.Variable) Gates {
	// The authority rail reads a zero own root, the bit would leave its proof unsolvable.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: r.Delegate, V: r.ThresholdsActive})
	offAuthority := api.Sub(1, r.Delegate)
	return Gates{
		Screened: api.Mul(ringgadget.IsNonZero(api, policyHash), offAuthority),
		Outflow:  r.ThresholdsActive,
		Rows:     offAuthority,
	}
}

// resolveSubjects opens one record per subject the gates activate, an inactive query reads zeros, the gates activate a pool and an active query needs an active pool.
func (p *Policy) resolveSubjects(api frontend.API, table tableView, g Gates, spend Spend, payments []Payment) subjects {
	senders := spend.Senders
	// 1. Each pool authenticates its records under its own root and answers a query by member, present or proven absent. Every read below goes through the pools, no prover list bit reaches a rule.
	ownActive := api.Or(g.Screened, g.Outflow)
	own := openSubjectPool(api, openRecordPool(api, ownActive, p.OwnRoot, p.OwnRecords, p.OwnProof, ownColumns), p.OwnSubjects)
	curated := api.Mul(g.Screened, table.sources.anyForeign)
	curator := openSubjectPool(api, openRecordPool(api, curated, p.CuratorRoot, p.CuratorRecords, p.CuratorProof, curatorColumns), p.CuratorSubjects)
	resolve := func(entry PoolEntry, active, curatedRead, member frontend.Variable) (subjectView, pooledRecord) {
		record := pooledRecordAt(own.resolve(api, recordQuery{active: active, member: member, index: entry.Own}))
		foreign := curator.resolve(api, recordQuery{active: api.Mul(active, curatedRead), member: member, index: entry.Curator[0]})
		return subjectView{onList: table.sources.lists(api, record.onList, [NSources]frontend.Variable(foreign))}, record
	}
	// 2. An owner reads each list at the zero salt key or at its salted key as the table's salted mask sets, the tracking row forces the salt once the owner has enrolled.
	//
	// registry/register_key.go refuses a zero salt, so an enrolled salt never names the public key.
	// A private list holds an owner at ListKey(owner, salt). A free salt would pick an empty key, and a blocked owner would prove itself off its list. The row's ListTag commits to the one salt enrollment fixed, registry/register_key.go seals that salt to the auditor, a list writer needs it to name the key, and a rotation keeps the tag.
	//
	// The tracking floor closes the skip for an owner a private write names. An owner absent under the tracking root has no salt to read under, so it reads off every private list, an allow list refuses it and a block list admits it. An old root could prove a blocked owner unenrolled, and no constraint here can see the root's age.
	// A private write proves the owner's row under the tracking root it names, registry/apply_records.go, and the program raises the source's floor to that root's revision. The program refuses a tracking root below a salted source's floor in LiveRoots::tracking, program-libs/interface/src/accounts/state.rs, and refuses a salted source pinned to another tracking registry in RingPolicy::check_source_pair. Every root at or above the floor holds the row, a row stays under every later root.
	anySalted := api.Or(table.sources.saltedOwn, table.sources.saltedCurated)
	ownerCurated := api.Mul(curated, table.sources.publicForeign)
	resolveOwner := func(entry OwnerEntry, active, member frontend.Variable) subjectView {
		view, _ := resolve(entry.PoolEntry, active, ownerCurated, shared.ListKey(api, member, 0))
		// A proven absent tracking row is the one skip, a present row forces its salt and so its key.
		row := spend.Tracking.Row(api, api.Mul(active, anySalted), member, entry.Tracking)
		enrolled := ringgadget.IsNonZero(api, row.NullifierPk)
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: enrolled, A: shared.ListTag(api, entry.ListSalt), B: row.ListTag})
		key := shared.ListKey(api, member, entry.ListSalt)
		salted := pooledRecordAt(own.resolve(api, recordQuery{active: api.Mul(enrolled, table.sources.saltedOwn), member: key, index: entry.OwnSalted})).onList
		curatedSalted := curator.resolve(api, recordQuery{active: api.Mul(enrolled, table.sources.saltedCurated), member: key, index: entry.CuratorSalted[0]})
		salted = table.sources.lists(api, salted, [NSources]frontend.Variable(curatedSalted))
		view.onList = table.sources.owner(api, view.onList, salted)
		return view
	}
	resolved := subjects{owners: make([]subjectView, len(payments)), assets: make([]subjectView, len(payments)), mintPolicies: make([]mintPolicyWires, len(payments))}
	resolved.senders, resolved.liveSenders = make([]subjectView, len(senders)), make([]frontend.Variable, len(senders))
	// 3. A padded row and a dummy or unused payment close their gates and read zeros, the rule sections skip them on the same bits.
	for j, sender := range senders {
		// A zero identity pads the list and carries no rule.
		resolved.liveSenders[j] = ringgadget.IsNonZero(api, sender)
		resolved.senders[j] = resolveOwner(p.SenderEntries[j], api.Mul(g.Screened, resolved.liveSenders[j]), sender)
	}
	// A mint record serves the rules under a policy and the thresholds on a ring with an own registry.
	mintRead := api.Or(g.Screened, g.Outflow)
	for i, pay := range payments {
		resolved.owners[i] = resolveOwner(p.OwnerEntries[i], api.Mul(pay.Active, g.Screened), pay.Owner)
		var record pooledRecord
		resolved.assets[i], record = resolve(p.AssetEntries[i], api.Mul(pay.Active, mintRead), curated, pay.Asset)
		resolved.mintPolicies[i] = decodeMintPolicy(api, record.mintPolicy)
	}
	for k, index := range p.PublicAssetEntries {
		asset := p.PublicAssets[k]
		active := api.Mul(ringgadget.IsNonZero(api, asset), mintRead)
		record := pooledRecordAt(own.resolve(api, recordQuery{active: active, member: asset, index: index}))
		resolved.publicAssets = append(resolved.publicAssets, publicAsset{limitedAsset: limitedAsset{asset: asset, active: active, policy: decodeMintPolicy(api, record.mintPolicy)}, withdrawalThreshold: record.withdrawalThreshold})
	}
	// 4. Every live input's asset reads its lists like a payment's, off the slot SPP spends, and a repeated asset can share one subject row. Only the rules read it, so the outflow gate opens no query here and no mint policy decodes. The authority rail clears Screened and spends with no read.
	resolved.inputAssets, resolved.liveInputs = make([]subjectView, len(spend.Inputs)), make([]frontend.Variable, len(spend.Inputs))
	for i, input := range spend.Inputs {
		resolved.liveInputs[i] = input.Utxo
		resolved.inputAssets[i], _ = resolve(p.AssetEntries[len(payments)+i], api.Mul(input.Utxo, g.Screened), curated, input.Asset)
	}
	return resolved
}

// IsSame reads one on two equal identities, an owner or an asset.
func IsSame(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
