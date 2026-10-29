package policy

import (
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"testing"
)

func TestPooledPolicyRejectsMalformedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"missing outputs", func(p *Policy) {
			p.Outputs = nil
			p.OwnerEntries = nil
			p.AssetEntries = nil
			p.OwnRecords = p.OwnRecords[:1]
			p.OwnSubjects = p.OwnSubjects[:1]
			p.CuratorRecords = p.CuratorRecords[:1]
			p.CuratorSubjects = p.CuratorSubjects[:1]
		}},
		{"missing owner references", func(p *Policy) { p.OwnerEntries = nil }},
		{"missing asset references", func(p *Policy) { p.AssetEntries = nil }},
		{"missing own records", func(p *Policy) { p.OwnRecords = nil }},
		{"missing own subjects", func(p *Policy) { p.OwnSubjects = nil }},
		{"missing curator reference", func(p *Policy) { p.SenderEntry.Curator = nil }},
		{"oversized own pool", func(p *Policy) { p.OwnRecords = append(p.OwnRecords, p.OwnRecords[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewMemberPolicyCircuit(MemberShape{Outputs: 2})
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&c.Policy)
			if err = c.Policy.validate(transaction.NPublicSlots); err == nil {
				t.Fatal("invalid policy shape accepted")
			}
		})
	}
	t.Run("own registry with curator records", func(t *testing.T) {
		c, err := NewMemberPolicyCircuit(MemberShape{Outputs: 2, OwnOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		c.CuratorRecords = c.OwnRecords[:1]
		if err = c.Policy.validate(transaction.NPublicSlots); err == nil {
			t.Fatal("curator records accepted by own only shape")
		}
	})
	t.Run("delegate without inputs", func(t *testing.T) {
		c, err := NewDelegatePolicyCircuit(DelegateShape{Shape: transaction.NewShape(2, 2)})
		if err != nil {
			t.Fatal(err)
		}
		c.Inputs = nil
		if err := c.Define(nil); err == nil {
			t.Fatal("delegate without inputs accepted")
		}
	})
	t.Run("delegate with extra public records", func(t *testing.T) {
		c, err := NewMemberPolicyCircuit(MemberShape{Outputs: 2})
		if err != nil {
			t.Fatal(err)
		}
		c.OwnRecords = c.OwnRecords[:6]
		c.OwnSubjects = c.OwnSubjects[:5]
		delegate := DelegatePolicyCircuit{Policy: c.Policy}
		delegate.Inputs = make([]shared.UtxoWires, 2)
		if err = delegate.Define(nil); err == nil {
			t.Fatal("delegate accepted oversized record capacity")
		}
	})
}
