package audit_test

import (
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type rangesVector struct {
	Class              int   `json:"class"`
	Outputs            int   `json:"outputs"`
	Entry              bool  `json:"entry"`
	SingleAssetPayout  bool  `json:"single_asset_payout"`
	HasData            bool  `json:"has_data"`
	EnvelopeBlocks     int   `json:"envelope_blocks"`
	FirstRecordCounter int   `json:"first_record_counter"`
	FirstTailCounter   int   `json:"first_tail_counter"`
	CapacityBlocks     int   `json:"capacity_blocks"`
	RecordCounters     []int `json:"record_start_counters"`
	TailCounters       []int `json:"tail_start_counters"`
	EnvelopeLens       []int `json:"envelope_len_by_input_count"`
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
		r := audit.StreamShape{InputClass: v.Class, Outputs: v.Outputs, Entry: v.Entry, SingleAssetPayout: v.SingleAssetPayout}.Ranges()
		// A key seals every tail, a reader of a clear has_data decrypts none.
		capacity := v.CapacityBlocks
		if !v.HasData && !v.SingleAssetPayout {
			capacity += v.Outputs * audit.TailBlocks
		}
		if r.EnvelopeBlocks() != v.EnvelopeBlocks || r.RecordCounter(0) != v.FirstRecordCounter || r.TailCounter(0) != v.FirstTailCounter || r.CapacityBlocks() != capacity {
			t.Errorf("%+v: E %d R0 %d T0 %d capacity %d", v, r.EnvelopeBlocks(), r.RecordCounter(0), r.TailCounter(0), r.CapacityBlocks())
		}
		records, tails := make([]int, v.Outputs), make([]int, v.Outputs)
		for i := range records {
			records[i], tails[i] = r.RecordCounter(i), r.TailCounter(i)
		}
		if !slices.Equal(records, v.RecordCounters) || !slices.Equal(tails, v.TailCounters) {
			t.Errorf("%+v: record counters %v, tail counters %v", v, records, tails)
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
	if audit.RecordBlocks*blockLen != audit.RecordStride || audit.RecordLen > audit.RecordStride || audit.TailBlocks*blockLen != audit.TailLen {
		t.Fatal("a region differs from its plaintext")
	}
	for _, shape := range []audit.StreamShape{{InputClass: 24, Outputs: 2}, {InputClass: 8, Outputs: 2, Entry: true}, {InputClass: 16, Outputs: 8}, {InputClass: 1, Outputs: 16, SingleAssetPayout: true}} {
		r := shape.Ranges()
		if r.RecordLen() > r.RecordStride() || r.RecordStride() != r.RecordBlocks()*blockLen {
			t.Fatalf("%+v record length differs", r)
		}
		if r.EnvelopeLen(r.InputClass) > r.EnvelopeBlocks()*blockLen {
			t.Fatalf("%+v: the envelope overruns its region", r)
		}
		if r.RecordCounter(0) != audit.StreamFirstCounter+r.EnvelopeBlocks() || r.RecordCounter(1)-r.RecordCounter(0) != r.RecordBlocks() || r.TailCounter(0) != r.RecordCounter(r.Outputs) {
			t.Fatalf("%+v: regions overlap", r)
		}
	}
}
