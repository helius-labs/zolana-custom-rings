package ringpolicy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

func ListSaltIn(t testing.TB, owner, ringID *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, new(big.Int).Add(owner, big.NewInt(4)), ringID)
}

func ListSaltOf(t testing.TB, owner *big.Int) *big.Int {
	t.Helper()
	return ListSaltIn(t, owner, big.NewInt(ringID))
}

// Enroll applies owner's leaf, the fields no owner predicate reads derive from it.
func Enroll(t testing.TB, tree *ringregistry.Tracking, owner, nullifierPk *big.Int) {
	t.Helper()
	derived := func(offset int64) *big.Int { return new(big.Int).Add(owner, big.NewInt(offset)) }
	tree.Apply(t, ringregistry.TrackingEntry{Member: owner, NullifierPk: nullifierPk, CtHash: derived(1), ListTag: ringregistry.ListTag(t, ListSaltOf(t, owner))})
}

// FillTracking opens each live member once and fills the pool cyclically.
func FillTracking(t testing.TB, target *policy.Tracking, tree *ringregistry.Tracking, rows, outputs []frontend.Variable, p *policy.Policy, payments []frontend.Variable) {
	t.Helper()
	var (
		records     []circuitregistry.TrackingRecord
		indices     []uint64
		subjects    []policy.PoolSubject
		seenRecords = map[uint64]int{}
		seenMembers = map[string]int{}
	)
	add := func(member frontend.Variable) int {
		identity := ringtest.AsBigInt(member)
		if entry, ok := seenMembers[identity.String()]; ok {
			return entry
		}
		opening := tree.Opening(identity)
		record, ok := seenRecords[opening.Path.Index]
		if !ok {
			record = len(records)
			seenRecords[opening.Path.Index] = record
			records = append(records, opening.Record.Wires())
			indices = append(indices, opening.Path.Index)
		}
		seenMembers[identity.String()] = len(subjects)
		subjects = append(subjects, policy.PoolSubject{Member: member, RecordIndex: record})
		return len(subjects) - 1
	}
	entry := func(member frontend.Variable) frontend.Variable {
		if ringtest.AsBigInt(member).Sign() == 0 {
			return 0
		}
		return add(member)
	}
	for j, member := range rows {
		target.RowEntries[j] = entry(member)
	}
	for o, member := range outputs {
		target.OutputEntries[o] = entry(member)
	}
	if p != nil {
		for j := range rows {
			p.SenderEntries[j].Tracking = target.RowEntries[j]
		}
		for o := range payments {
			p.OwnerEntries[o].Tracking = 0
			if ringtest.AsBigInt(p.Salted).Sign() != 0 {
				p.OwnerEntries[o].Tracking = entry(payments[o])
			}
		}
	}
	// The sentinel fills a pool nothing live opened.
	if len(subjects) == 0 {
		add(big.NewInt(0))
	}
	if len(subjects) > len(target.TrackingSubjects) {
		t.Fatalf("tracking needs %d subjects with capacity %d", len(subjects), len(target.TrackingSubjects))
	}
	target.TrackingRoot = tree.Root()
	filled := make([]uint64, len(target.TrackingRecords))
	for i := range target.TrackingRecords {
		filled[i] = indices[i%len(indices)]
		target.TrackingRecords[i] = records[i%len(records)]
	}
	for i := range target.TrackingSubjects {
		target.TrackingSubjects[i] = subjects[i%len(subjects)]
	}
	proof, err := tree.SharedProof(filled)
	if err != nil {
		t.Fatal(err)
	}
	target.TrackingProof = proof
}
