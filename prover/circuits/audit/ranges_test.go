package audit_test

import (
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type rangesVector struct {
	Class           int   `json:"class"`
	Outputs         int   `json:"outputs"`
	Entry           bool  `json:"entry"`
	EnvelopeBlocks  int   `json:"envelope_blocks"`
	FirstKeyCounter int   `json:"first_key_counter"`
	CapacityBlocks  int   `json:"capacity_blocks"`
	KeyCounters     []int `json:"key_start_counters"`
	EnvelopeLens    []int `json:"envelope_len_by_input_count"`
}

func TestStreamRangesAreTheSharedVector(t *testing.T) {
	var vectors struct {
		Keys []rangesVector `json:"keys"`
	}
	ringtest.ReadVector(t, "audit/ring-disclosure-ranges.json", &vectors)
	if len(vectors.Keys) == 0 {
		t.Fatal("the vector holds no key")
	}
	for _, v := range vectors.Keys {
		r := audit.StreamShape{InputClass: v.Class, Outputs: v.Outputs, Entry: v.Entry}.Ranges()
		if r.EnvelopeBlocks() != v.EnvelopeBlocks || r.KeyCounter(0) != v.FirstKeyCounter || r.CapacityBlocks() != v.CapacityBlocks {
			t.Errorf("%+v: E %d K0 %d capacity %d", v, r.EnvelopeBlocks(), r.KeyCounter(0), r.CapacityBlocks())
		}
		keys := make([]int, v.Outputs)
		for i := range keys {
			keys[i] = r.KeyCounter(i)
		}
		if !slices.Equal(keys, v.KeyCounters) {
			t.Errorf("%+v: key counters %v", v, keys)
		}
		lengths := make([]int, v.Class)
		for n := range lengths {
			lengths[n] = r.EnvelopeLen(n + 1)
		}
		if !slices.Equal(lengths, v.EnvelopeLens) {
			t.Errorf("%+v: envelope lengths %v", v, lengths)
		}
	}
}

// No two regions share a counter on these shapes.
func TestStreamRegionsHoldTheirPlaintext(t *testing.T) {
	const blockLen = 16
	if audit.KeyBlocks*blockLen != audit.KeyLen {
		t.Fatal("a region differs from its plaintext")
	}
	for _, shape := range []audit.StreamShape{{InputClass: 24, Outputs: 2}, {InputClass: 8, Outputs: 2, Entry: true}, {InputClass: 16, Outputs: 8}} {
		r := shape.Ranges()
		if r.EnvelopeLen(r.InputClass) > r.EnvelopeBlocks()*blockLen {
			t.Fatalf("%+v: the envelope overruns its region", r)
		}
		if r.KeyCounter(0) != audit.StreamFirstCounter+r.EnvelopeBlocks() || r.KeyCounter(1)-r.KeyCounter(0) != audit.KeyBlocks {
			t.Fatalf("%+v: regions overlap", r)
		}
	}
}
