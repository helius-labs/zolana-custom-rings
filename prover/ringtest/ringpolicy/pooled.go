package ringpolicy

import (
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type recordCollector struct {
	tree           *ringregistry.Registry
	records        []circuitregistry.Record
	leafIndices    []uint64
	indices        map[uint64]int
	subjects       []policy.PoolSubject
	subjectIndices map[string]int
}

// OwnRecord is the own pool record entry resolves to.
func (b Witness) OwnRecord(entry policy.PoolEntry) *circuitregistry.Record {
	policyWitness := b.Policy()
	subject := policyWitness.OwnSubjects[ringtest.AsBigInt(entry.Own).Int64()]
	return &policyWitness.OwnRecords[ringtest.AsBigInt(subject.RecordIndex).Int64()]
}

// FillPools opens each live subject and record once and fills the pools cyclically to capacity.
func FillPools(t testing.TB, policyWitness *policy.Policy, outputs, inputs []shared.UtxoWires, senders []frontend.Variable, ownTree, curatorTree *ringregistry.Registry, tracking *ringregistry.Tracking) {
	t.Helper()
	own, curator := newCollector(ownTree), newCollector(curatorTree)
	foreign, saltedOwn, saltedCurated := false, false, false
	saltedLists := ringtest.AsBigInt(policyWitness.Salted)
	for i, source := range policyWitness.Sources {
		curated := ringtest.AsBigInt(source.Registry).Sign() != 0
		foreign = foreign || curated
		if saltedLists.Bit(i) == 1 {
			saltedOwn, saltedCurated = saltedOwn || !curated, saltedCurated || curated
		}
	}
	entry := func(member frontend.Variable, active bool) policy.PoolEntry {
		return policy.PoolEntry{Own: own.add(member, active), Curator: [1]frontend.Variable{curator.add(member, active && foreign)}}
	}
	owner := func(member frontend.Variable, active bool) policy.OwnerEntry {
		identity := ringtest.AsBigInt(member)
		ownerEntry := policy.OwnerEntry{PoolEntry: entry(ringregistry.PublicKey(t, identity), active), Tracking: 0, ListSalt: 0, OwnSalted: 0, CuratorSalted: [1]frontend.Variable{0}}
		if !active || !(saltedOwn || saltedCurated) || !tracking.Opening(identity).Present {
			return ownerEntry
		}
		salt := ListSaltOf(t, identity)
		key := ringregistry.ListKey(t, identity, salt)
		ownerEntry.ListSalt = salt
		ownerEntry.OwnSalted = own.add(key, saltedOwn)
		ownerEntry.CuratorSalted[0] = curator.add(key, saltedCurated)
		return ownerEntry
	}
	for j, sender := range senders {
		policyWitness.SenderEntries[j] = owner(sender, ringtest.AsBigInt(sender).Sign() != 0)
	}
	for i, out := range outputs {
		active := ringtest.AsBigInt(out.Domain).Int64() == transaction.UtxoDomain
		policyWitness.OwnerEntries[i], policyWitness.AssetEntries[i] = owner(out.OwnerPkHash, active), entry(out.Asset, active)
	}
	for i, out := range policyWitness.Withdrawals {
		active := int64(i) < ringtest.AsBigInt(policyWitness.WithdrawalCount).Int64()
		index := len(outputs) + i
		policyWitness.OwnerEntries[index], policyWitness.AssetEntries[index] = owner(out.Owner, active), entry(out.Asset, active)
	}
	for i := range policyWitness.PublicAssetEntries {
		asset := policyWitness.PublicAssets[i]
		policyWitness.PublicAssetEntries[i] = own.add(asset, ringtest.AsBigInt(asset).Sign() != 0)
	}
	for i, input := range inputs {
		policyWitness.AssetEntries[len(policyWitness.OwnerEntries)+i] = entry(input.Asset, ringtest.AsBigInt(input.Domain).Int64() == transaction.UtxoDomain)
	}
	if len(curator.records) == 0 {
		curator.add(slices.Concat(senders, []frontend.Variable{0})[0], true)
	}
	policyWitness.OwnProof = own.fill(t, policyWitness.OwnRecords, policyWitness.OwnSubjects)
	policyWitness.CuratorProof = curator.fill(t, policyWitness.CuratorRecords, policyWitness.CuratorSubjects)
}

func newCollector(tree *ringregistry.Registry) *recordCollector {
	return &recordCollector{tree: tree, indices: map[uint64]int{}, subjectIndices: map[string]int{}}
}

func (c *recordCollector) add(member frontend.Variable, active bool) int {
	if !active {
		return 0
	}
	subjectKey := ringtest.AsBigInt(member).String()
	if index, ok := c.subjectIndices[subjectKey]; ok {
		return index
	}
	opening := c.tree.Opening(ringtest.AsBigInt(member))
	key := opening.Path.Index
	recordIndex, ok := c.indices[key]
	if !ok {
		recordIndex = len(c.records)
		c.indices[key] = recordIndex
		c.records = append(c.records, opening.Record.Wires())
		c.leafIndices = append(c.leafIndices, opening.Path.Index)
	}
	index := len(c.subjects)
	c.subjectIndices[subjectKey] = index
	c.subjects = append(c.subjects, policy.PoolSubject{Member: member, RecordIndex: recordIndex})
	return index
}

func (c *recordCollector) fill(t testing.TB, target []circuitregistry.Record, subjects []policy.PoolSubject) circuitregistry.SharedQuadProof {
	t.Helper()
	if len(c.records) > len(target) {
		t.Fatalf("pool needs %d records with capacity %d", len(c.records), len(target))
	}
	if len(c.subjects) > len(subjects) {
		t.Fatalf("pool needs %d subjects with capacity %d", len(c.subjects), len(subjects))
	}
	for i := range subjects {
		subjects[i] = c.subjects[i%len(c.subjects)]
	}
	indices := make([]uint64, len(target))
	for i := range target {
		target[i] = c.records[i%len(c.records)]
		indices[i] = c.leafIndices[i%len(c.leafIndices)]
	}
	proof, err := c.tree.SharedProof(indices)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
