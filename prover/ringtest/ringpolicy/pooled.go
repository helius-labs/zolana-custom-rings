package ringpolicy

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
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
	p := b.Policy()
	subject := p.OwnSubjects[ringtest.AsBigInt(entry.Own).Int64()]
	return &p.OwnRecords[ringtest.AsBigInt(subject.RecordIndex).Int64()]
}

// pool opens every live subject once, each record once, and fills the pools cyclically to capacity.
func (b Witness) pool(t testing.TB, ownTree, curatorTree *ringregistry.Registry) {
	t.Helper()
	p := b.Policy()
	own, curator := newCollector(ownTree), newCollector(curatorTree)
	foreign := false
	for _, source := range p.Sources {
		foreign = foreign || ringtest.AsBigInt(source.Registry).Sign() != 0
	}
	entry := func(member frontend.Variable, active bool) policy.PoolEntry {
		e := policy.PoolEntry{Own: own.add(member, active)}
		if !p.OwnOnly {
			e.Curator = []frontend.Variable{curator.add(member, active && foreign)}
		}
		return e
	}
	p.SenderEntry = entry(p.SenderPkHash, true)
	for i, out := range p.Outputs {
		active := ringtest.AsBigInt(out.Domain).Int64() == transaction.UtxoDomain
		p.OwnerEntries[i], p.AssetEntries[i] = entry(out.OwnerPkHash, active), entry(out.Asset, active)
	}
	for i, out := range p.Withdrawals {
		active := int64(i) < ringtest.AsBigInt(p.WithdrawalCount).Int64()
		index := len(p.Outputs) + i
		p.OwnerEntries[index], p.AssetEntries[index] = entry(out.Owner, active), entry(out.Asset, active)
	}
	for i := range p.PublicAssetEntries {
		asset := p.PublicAssets[i]
		p.PublicAssetEntries[i] = own.add(asset, ringtest.AsBigInt(asset).Sign() != 0)
	}
	if len(curator.records) == 0 && !p.OwnOnly {
		curator.add(p.SenderPkHash, true)
	}
	p.OwnProof = own.fill(t, p.OwnRecords, p.OwnSubjects)
	if !p.OwnOnly {
		p.CuratorProof = curator.fill(t, p.CuratorRecords, p.CuratorSubjects)
	}
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
