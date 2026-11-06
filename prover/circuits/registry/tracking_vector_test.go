package registry_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type rustTrackingFields struct {
	NullifierPk ringtest.Hex `json:"nullifier_pk"`
	CtHash      ringtest.Hex `json:"ct_hash"`
	ListTag     ringtest.Hex `json:"list_tag"`
}

type rustTrackingRecord struct {
	Member ringtest.Hex `json:"member"`
	Next   ringtest.Hex `json:"next"`
	rustTrackingFields
	LeafHash ringtest.Hex `json:"leaf_hash"`
}

func (r rustTrackingRecord) record(t *testing.T) ringregistry.TrackingRecord {
	t.Helper()
	return ringregistry.TrackingRecord{Member: r.Member.Int, Next: r.Next.Int, NullifierPk: r.NullifierPk.Int, CtHash: r.CtHash.Int, ListTag: r.ListTag.Int}
}

type rustTrackingEntry struct {
	Member ringtest.Hex `json:"member"`
	rustTrackingFields
	EntryHash ringtest.Hex `json:"entry_hash"`
}

func (e rustTrackingEntry) entry(t *testing.T) ringregistry.TrackingEntry {
	t.Helper()
	return ringregistry.TrackingEntry{Member: e.Member.Int, NullifierPk: e.NullifierPk.Int, CtHash: e.CtHash.Int, ListTag: e.ListTag.Int}
}

type rustTrackingPath struct {
	Index    uint64           `json:"index"`
	Siblings [][]ringtest.Hex `json:"siblings"`
}

func (p rustTrackingPath) path(t *testing.T) ringregistry.TrackingPath {
	t.Helper()
	path := ringregistry.TrackingPath{Index: p.Index}
	if len(p.Siblings) != registry.TrackingHeight {
		t.Fatalf("%d path levels", len(p.Siblings))
	}
	for level, row := range p.Siblings {
		for k, sibling := range row {
			path.Siblings[level][k] = sibling.Int
		}
	}
	return path
}

// The Rust witnesses solve the circuit and the host twin reaches every Rust root.
func TestApplyEnrollmentsMatchesRustVectors(t *testing.T) {
	var vectors struct {
		EmptyRoot    ringtest.Hex `json:"empty_root"`
		Applications []struct {
			Name          string       `json:"name"`
			OldRoot       ringtest.Hex `json:"old_root"`
			NewRoot       ringtest.Hex `json:"new_root"`
			OldNextIndex  uint64       `json:"old_next_index"`
			NewNextIndex  uint64       `json:"new_next_index"`
			ChainStart    ringtest.Hex `json:"chain_start"`
			ChainEnd      ringtest.Hex `json:"chain_end"`
			StatementHash ringtest.Hex `json:"statement_hash"`
			Writes        []struct {
				Entry   rustTrackingEntry  `json:"entry"`
				Slot    rustTrackingPath   `json:"slot"`
				Low     rustTrackingRecord `json:"low"`
				LowPath rustTrackingPath   `json:"low_path"`
			} `json:"writes"`
		} `json:"applications"`
	}
	ringtest.ReadVector(t, "registry/tracking-records.json", &vectors)
	tree := ringregistry.NewTracking(t)
	if tree.Root().Cmp(vectors.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", tree.Root(), vectors.EmptyRoot.Int)
	}
	for _, app := range vectors.Applications {
		t.Run(app.Name, func(t *testing.T) {
			entries := make([]ringregistry.TrackingEntry, len(app.Writes))
			for i, w := range app.Writes {
				entries[i] = w.Entry.entry(t)
				if entries[i].Hash(t).Cmp(w.Entry.EntryHash.Int) != 0 {
					t.Fatalf("entry %d hash differs from Rust", i)
				}
				if w.Low.record(t).Hash(t).Cmp(w.Low.LeafHash.Int) != 0 {
					t.Fatalf("write %d low leaf differs from Rust", i)
				}
			}
			b := applyEnrollments(t, tree, registry.ApplyBatch, app.ChainStart.Int, entries...)
			c := b.circuit
			for name, pair := range map[string][2]*big.Int{
				"old root":       {ringtest.AsBigInt(c.OldRoot), app.OldRoot.Int},
				"new root":       {ringtest.AsBigInt(c.NewRoot), app.NewRoot.Int},
				"old next index": {ringtest.AsBigInt(c.OldNextIndex), new(big.Int).SetUint64(app.OldNextIndex)},
				"new next index": {ringtest.AsBigInt(c.NewNextIndex), new(big.Int).SetUint64(app.NewNextIndex)},
				"chain end":      {ringtest.AsBigInt(c.ChainEnd), app.ChainEnd.Int},
				"statement":      {ringtest.AsBigInt(c.PublicInputHash), app.StatementHash.Int},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Fatalf("%s %x, Rust %x", name, pair[0], pair[1])
				}
			}
			for i, w := range app.Writes {
				c.Writes[i] = ringregistry.TrackingWrite{Entry: entries[i], Slot: w.Slot.path(t), Low: w.Low.record(t), LowPath: w.LowPath.path(t)}.Wires()
			}
			if err := solveEnrollments(t, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}
