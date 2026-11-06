// Refusals of a malformed pool shape, before any wire is read.

package policy

import (
	"testing"

	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestPooledPolicyRejectsMalformedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"missing outputs", func(p *Policy) {
			p.Outputs = 0
			p.OwnerEntries = nil
			p.AssetEntries = nil
			p.OwnRecords = p.OwnRecords[:1]
			p.OwnSubjects = p.OwnSubjects[:1]
			p.CuratorRecords = p.CuratorRecords[:1]
			p.CuratorSubjects = p.CuratorSubjects[:1]
		}},
		{"missing owner references", func(p *Policy) { p.OwnerEntries = nil }},
		{"missing asset references", func(p *Policy) { p.AssetEntries = nil }},
		{"missing input asset references", func(p *Policy) { p.AssetEntries = p.AssetEntries[:p.Outputs] }},
		{"missing own records", func(p *Policy) { p.OwnRecords = nil }},
		{"missing own subjects", func(p *Policy) { p.OwnSubjects = nil }},
		{"missing sender references", func(p *Policy) { p.SenderEntries = nil }},
		{"oversized own pool", func(p *Policy) { p.OwnRecords = append(p.OwnRecords, p.OwnRecords[0]) }},
		{"missing public asset references", func(p *Policy) { p.PublicAssetEntries = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(InputsShape{Outputs: 2, Senders: 4, Spent: 3}.Inputs(), RecordPoolShape{}, transaction.NPublicSlots)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&p)
			if err = p.Validate(transaction.NPublicSlots); err == nil {
				t.Fatal("invalid policy shape accepted")
			}
		})
	}
}

func TestInputAssetsHaveIndependentPoolCapacity(t *testing.T) {
	shape := InputsShape{Outputs: 2, Withdrawals: 1, Senders: 4}
	base, err := NewPolicy(shape.Inputs(), RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		t.Fatal(err)
	}
	shape.Spent = 3
	spent, err := NewPolicy(shape.Inputs(), RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		t.Fatal(err)
	}
	if err = spent.Validate(transaction.NPublicSlots); err != nil {
		t.Fatal(err)
	}
	want := base.RecordPools()
	want.Own += shape.Spent
	want.Curator += shape.Spent
	want.OwnSubjects += shape.Spent
	want.CuratorSubjects += shape.Spent
	if spent.RecordPools() != want {
		t.Fatalf("pools %+v want %+v", spent.RecordPools(), want)
	}
	if len(spent.AssetEntries) != len(base.AssetEntries)+3 || len(spent.OwnerEntries) != len(base.OwnerEntries) {
		t.Fatalf("references %d and %d", len(spent.AssetEntries), len(spent.OwnerEntries))
	}
}
