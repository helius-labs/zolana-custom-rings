package ringregistry

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

// Vector is test-vectors/registry/ring-records.json, written by program-libs/member-registry/tests/ring_records_vector.rs.
type Vector struct {
	EmptyRoot ringtest.Hex `json:"empty_root"`
	Registry  string       `json:"registry"`
	Updates   []Update     `json:"updates"`
}

// Update is one ordered batch of the storage program's Update instruction.
type Update struct {
	Name          string         `json:"name"`
	Revision      uint64         `json:"revision"`
	Writes        []BatchWrite   `json:"writes"`
	OldRoot       ringtest.Hex   `json:"old_root"`
	NewRoot       ringtest.Hex   `json:"new_root"`
	OldNextIndex  uint64         `json:"old_next_index"`
	NewNextIndex  uint64         `json:"new_next_index"`
	ChainStart    ringtest.Hex   `json:"chain_start"`
	ChainEnd      ringtest.Hex   `json:"chain_end"`
	Count         int            `json:"count"`
	StatementHash ringtest.Hex   `json:"statement_hash"`
	ProofInputs   []AppliedWrite `json:"proof_inputs"`
	// Width is the public apply key's write capacity.
	Width int `json:"width"`
}

type VectorEntry struct {
	Member ringtest.Hex `json:"member"`
	Mask   uint64       `json:"mask"`
	Value  uint64       `json:"value"`
}

// BatchWrite's Chain is the chain after the write.
type BatchWrite struct {
	VectorEntry
	EntryHash ringtest.Hex `json:"entry_hash"`
	Chain     ringtest.Hex `json:"chain"`
}

type AppliedWrite struct {
	VectorEntry
	Exists   bool         `json:"exists"`
	OldNext  ringtest.Hex `json:"old_next"`
	OldLists uint64       `json:"old_lists"`
	Slot     VectorPath   `json:"slot"`
	Low      VectorRecord `json:"low"`
	LowPath  VectorPath   `json:"low_path"`
}

type VectorRecord struct {
	Member ringtest.Hex `json:"member"`
	Next   ringtest.Hex `json:"next"`
	Lists  uint64       `json:"lists"`
}

type VectorPath struct {
	Index    uint64           `json:"index"`
	Siblings [][]ringtest.Hex `json:"siblings"`
}

func (e VectorEntry) Entry() Entry {
	return Entry{Member: e.Member.Int, Mask: new(big.Int).SetUint64(e.Mask), Value: new(big.Int).SetUint64(e.Value)}
}

// Write is w as Apply returns it.
func (w AppliedWrite) Write(t testing.TB) Write {
	t.Helper()
	return Write{
		Entry:    w.Entry(),
		Exists:   w.Exists,
		OldNext:  w.OldNext.Int,
		OldLists: new(big.Int).SetUint64(w.OldLists),
		Slot:     w.Slot.Path(t),
		Low:      Record{Member: w.Low.Member.Int, Next: w.Low.Next.Int, Lists: new(big.Int).SetUint64(w.Low.Lists)},
		LowPath:  w.LowPath.Path(t),
	}
}

func (p VectorPath) Path(t testing.TB) Path {
	t.Helper()
	path := Path{Index: p.Index}
	if len(p.Siblings) != registry.Height {
		t.Fatalf("ring records vector holds %d path levels", len(p.Siblings))
	}
	for level, row := range p.Siblings {
		if len(row) != registry.Arity-1 {
			t.Fatalf("ring records vector holds %d siblings at level %d", len(row), level)
		}
		for k, sibling := range row {
			path.Siblings[level][k] = sibling.Int
		}
	}
	return path
}
