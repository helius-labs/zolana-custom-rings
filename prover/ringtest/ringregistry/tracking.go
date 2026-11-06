package ringregistry

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type TrackingRecord struct {
	Member, Next, NullifierPk, CtHash, ListTag *big.Int
}

func (r TrackingRecord) Hash(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.TrackingLeafDomain), r.Member, r.Next, r.NullifierPk, r.CtHash, r.ListTag)
}

func (r TrackingRecord) Wires() registry.TrackingRecord {
	return registry.TrackingRecord{Member: copied(r.Member), Next: copied(r.Next), NullifierPk: copied(r.NullifierPk), CtHash: copied(r.CtHash), ListTag: copied(r.ListTag)}
}

type TrackingEntry struct {
	Member, NullifierPk, CtHash, ListTag *big.Int
}

func (e TrackingEntry) Hash(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.TrackingEntryDomain), e.Member, e.NullifierPk, e.CtHash, e.ListTag)
}

func (e TrackingEntry) Wires() registry.TrackingEntry {
	return registry.TrackingEntry{Member: e.Member, NullifierPk: e.NullifierPk, CtHash: e.CtHash, ListTag: e.ListTag}
}

// ListTag mirrors shared.ListTag.
func ListTag(t testing.TB, listSalt *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListTagDomain), listSalt)
}

func ListKey(t testing.TB, owner, listSalt *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListKeyDomain), owner, listSalt)
}

type TrackingPath struct {
	Index    uint64
	Siblings [registry.TrackingHeight][registry.Arity - 1]*big.Int
}

func (p TrackingPath) Wires() registry.TrackingPath {
	w := registry.TrackingPath{Index: p.Index}
	for level, siblings := range p.Siblings {
		for k, sibling := range siblings {
			w.Siblings[level][k] = new(big.Int).Set(sibling)
		}
	}
	return w
}

type TrackingOpening struct {
	Present bool
	Record  TrackingRecord
	Path    TrackingPath
}

func (o TrackingOpening) Wires() registry.TrackingOpening {
	w := registry.TrackingOpening{Present: 0, Record: o.Record.Wires(), Path: o.Path.Wires()}
	if o.Present {
		w.Present = 1
	}
	return w
}

type TrackingWrite struct {
	Entry   TrackingEntry
	Slot    TrackingPath
	Low     TrackingRecord
	LowPath TrackingPath
}

func (w TrackingWrite) Wires() registry.EnrollmentWrite {
	return registry.EnrollmentWrite{Entry: w.Entry.Wires(), Slot: w.Slot.Wires(), Low: w.Low.Wires(), LowSlot: w.LowPath.Wires()}
}

func ZeroTrackingWrite() TrackingWrite {
	zero := big.NewInt(0)
	record := TrackingRecord{}
	path := TrackingPath{}
	for level := range path.Siblings {
		for k := range path.Siblings[level] {
			path.Siblings[level][k] = zero
		}
	}
	return TrackingWrite{Entry: TrackingEntry{Member: zero, NullifierPk: zero, CtHash: zero, ListTag: zero}, Slot: path, Low: record, LowPath: path}
}

// Tracking keeps the sentinel at index 0 and appends every insert.
type Tracking struct {
	records []TrackingRecord
	tree    quadTree
}

func NewTracking(t testing.TB) *Tracking {
	t.Helper()
	r := &Tracking{tree: newQuadTree(t, registry.TrackingHeight)}
	zero := big.NewInt(0)
	r.set(t, 0, TrackingRecord{Member: zero, Next: fieldMax, NullifierPk: zero, CtHash: zero, ListTag: zero})
	return r
}

func (r *Tracking) Root() *big.Int {
	return r.tree.root()
}

func (r *Tracking) NextIndex() uint64 {
	return uint64(len(r.records))
}

func (r *Tracking) Opening(member *big.Int) TrackingOpening {
	index, present := r.find(member)
	return TrackingOpening{Present: present, Record: r.records[index], Path: r.Path(index)}
}

func (r *Tracking) Apply(t testing.TB, e TrackingEntry) TrackingWrite {
	t.Helper()
	if e.Member.Sign() <= 0 || e.Member.Cmp(fieldMax) >= 0 {
		t.Fatalf("ringregistry: the program never chains %+v", e)
	}
	index, present := r.find(e.Member)
	if present {
		t.Fatalf("ringregistry: an owner enrolls once, %+v", e)
	}
	low, next := r.records[index], r.NextIndex()
	w := TrackingWrite{Entry: e, Low: low, LowPath: r.Path(index)}
	relinked := low
	relinked.Next = e.Member
	r.set(t, index, relinked)
	w.Slot = r.Path(next)
	r.set(t, next, entryRecord(e, low.Next))
	return w
}

func (r *Tracking) SharedProof(indices []uint64) (registry.SharedQuadProof, error) {
	proof, err := registry.NewTrackingProof(len(indices))
	if err != nil {
		return registry.SharedQuadProof{}, err
	}
	depth := len(proof.Paths[0].Siblings)
	for i := range proof.Canopy {
		proof.Canopy[i] = new(big.Int).Set(r.tree.node(depth, uint64(i)))
	}
	for i, index := range indices {
		path := r.Path(index).Wires()
		proof.Paths[i].Index = index
		copy(proof.Paths[i].Siblings, path.Siblings[:])
	}
	return proof, nil
}

func (r *Tracking) Path(index uint64) TrackingPath {
	p := TrackingPath{Index: index}
	copy(p.Siblings[:], r.tree.siblings(index))
	return p
}

func (r *Tracking) find(member *big.Int) (uint64, bool) {
	low := uint64(0)
	for i, record := range r.records {
		switch record.Member.Cmp(member) {
		case 0:
			return uint64(i), true
		case -1:
			if record.Member.Cmp(r.records[low].Member) > 0 {
				low = uint64(i)
			}
		}
	}
	return low, false
}

func (r *Tracking) set(t testing.TB, index uint64, record TrackingRecord) {
	t.Helper()
	if index == uint64(len(r.records)) {
		r.records = append(r.records, record)
	} else {
		r.records[index] = record
	}
	r.tree.setLeaf(t, index, record.Hash(t))
}

func entryRecord(e TrackingEntry, next *big.Int) TrackingRecord {
	return TrackingRecord{Member: e.Member, Next: next, NullifierPk: e.NullifierPk, CtHash: e.CtHash, ListTag: e.ListTag}
}
