package ringpolicy

import (
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Rows are a table's used rows, Wires pads each list with zero rows to its capacity.
type Rows struct {
	Sources                           []policy.SourceWires
	Rules, InlineAssets, InlineLimits []frontend.Variable
	Limits                            []MintLimit
}

func (r Rule) Packed() *big.Int {
	packed := new(big.Int).Lsh(new(big.Int).SetUint64(r.Alternative), 96)
	packed.Or(packed, new(big.Int).Lsh(new(big.Int).SetUint64(r.Threshold), 32))
	return packed.Or(packed, new(big.Int).SetUint64(r.Subject|r.Mode<<8|r.Mask<<16|r.Guard<<24))
}

// TableHash mirrors EncodedRuleTable::hash, PolicyTableRate fields per call beside the accumulator.
func TableHash(t testing.TB, table policy.Table) *big.Int {
	t.Helper()
	fields := ringtest.ToBigInts(table.Fields())
	accumulator := big.NewInt(0)
	for start := 0; start < len(fields); start += policy.PolicyTableRate {
		accumulator = spptest.MustPoseidon(t, policy.PolicyTableRate+2, append([]*big.Int{accumulator}, fields[start:start+policy.PolicyTableRate]...))
	}
	return accumulator
}

func (r Rows) Wires() policy.Table {
	var table policy.Table
	for i := range table.Sources {
		table.Sources[i] = pad(r.Sources, i, policy.SourceWires{ListID: 0, Registry: 0})
	}
	table.PolicyLen = len(r.Rules)
	for i := range table.Rules {
		table.Rules[i] = pad(r.Rules, i, 0)
	}
	return table
}

func (table Table) Wires() policy.Table { return table.rows().Wires() }

// rows serves the list of record bit i from source slot i, its list id i+1.
func (table Table) rows() Rows {
	sources := make([]policy.SourceWires, policy.NSources)
	for i := range sources {
		sources[i] = policy.SourceWires{ListID: 0, Registry: 0}
	}
	for _, list := range table.Lists {
		slot := bits.TrailingZeros64(list)
		registry := big.NewInt(0)
		if table.Curator[list] {
			registry = curatorRegistry
		}
		sources[slot] = policy.SourceWires{ListID: slot + 1, Registry: registry}
	}
	r := Rows{Sources: sources}
	for _, rule := range table.Rules {
		r.Rules = append(r.Rules, rule.Packed())
	}
	for _, inline := range table.Inline {
		r.InlineAssets, r.InlineLimits = append(r.InlineAssets, inline.Asset), append(r.InlineLimits, inline.Limit)
	}
	for _, limit := range table.Limits {
		r.Limits = append(r.Limits, MintLimit{Asset: limit.Asset, Cap: limit.Cap, CosignAbove: limit.CosignAbove})
	}
	return r
}

type MintLimit struct{ Asset, Cap, CosignAbove frontend.Variable }
