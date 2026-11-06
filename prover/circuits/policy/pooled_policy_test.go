// Refusals of the pooled policy, a subject reference naming another member and a pool past its capacity.

package policy_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"testing"
)

func TestPooledPolicyModes(t *testing.T) {
	worlds := []ringpolicy.World{ringpolicy.Confidential(), ringpolicy.Anonymous(), curated(), delegate2(), withdrawalWorld()}
	for i, world := range worlds {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			witness := world.Build(t)
			if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPooledPolicyConstraintMatrix(t *testing.T) {
	for _, shape := range []ringpolicy.SectionShape{{Outputs: 2}, {Outputs: 8, Withdrawals: 32}} {
		for _, compact := range []bool{true, false} {
			shape.Records = compactPools(compact)
			c, err := ringpolicy.NewSectionCircuit(shape)
			if err != nil {
				t.Fatal(err)
			}
			cs := ringkey.Compile(t, c)
			requirePooledCompiledSolved(t, cs, poolWorld(shape, false, false).Build(t))
			if !compact {
				requirePooledCompiledSolved(t, cs, poolWorld(shape, true, false).Build(t))
			}
			t.Logf("section-%d-w%d capacity=%d/%d constraints=%d", shape.Outputs, shape.Withdrawals, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
		}
	}
	for _, width := range []int{2, 4} {
		for _, compact := range []bool{true, false} {
			shape := ringpolicy.SectionShape{Outputs: width, Records: compactPools(compact)}
			c, err := ringpolicy.NewSectionCircuit(shape)
			if err != nil {
				t.Fatal(err)
			}
			cs := ringkey.Compile(t, c)
			requirePooledCompiledSolved(t, cs, poolWorld(shape, false, true).Build(t))
			if !compact {
				requirePooledCompiledSolved(t, cs, poolWorld(shape, true, true).Build(t))
			}
			t.Logf("delegate-%dx%d capacity=%d/%d constraints=%d", width, width, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
		}
	}
}

func compactPools(compact bool) policy.RecordPoolShape {
	if compact {
		return policy.RecordPoolShape{Own: 3, Curator: 3}
	}
	return policy.RecordPoolShape{}
}

func requirePooledCompiledSolved(t *testing.T, cs constraint.ConstraintSystem, policyWitness ringpolicy.Witness) {
	t.Helper()
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Fatal("pool must keep one private commitment")
	}
	witness, err := frontend.NewWitness(policyWitness.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

func poolWorld(shape ringpolicy.SectionShape, distinct, delegate bool) ringpolicy.World {
	world := ringpolicy.Confidential()
	world.Outputs, world.WithdrawalCapacity, world.Records = shape.Outputs, shape.Withdrawals, shape.Records
	world.Table.Limits = nil
	world.Table.Rules = append(world.Table.Rules, ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit))
	world.Slots, world.Withdrawals = nil, nil
	world.Own = map[int64]ringpolicy.Record{ringpolicy.Sender: ringpolicy.Record{Lists: ringregistry.AllowBit}}
	add := func(owner, asset int64) ringpolicy.Slot {
		world.Own[owner] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		world.Own[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		return ringpolicy.Slot{Owner: owner, Asset: asset, Amount: 1}
	}
	for i := range shape.Outputs + shape.Withdrawals {
		owner, asset := int64(ringpolicy.Alice), int64(ringpolicy.AssetA)
		if distinct {
			owner = int64(10000 + 2*i)
			asset = owner + 1
			if i >= shape.Outputs {
				// Withdrawals settle through the public slots, their assets repeat the public assets.
				asset = int64(30000 + (i-shape.Outputs)%transaction.NPublicSlots)
			}
		}
		slot := add(owner, asset)
		if i < shape.Outputs {
			world.Slots = append(world.Slots, slot)
		} else {
			world.Withdrawals = append(world.Withdrawals, slot)
		}
	}
	if !delegate {
		for i := range transaction.NPublicSlots {
			asset := int64(ringpolicy.AssetA)
			if distinct {
				asset = int64(30000 + i)
			}
			world.Own[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}
			world.Public = append(world.Public, ringpolicy.PublicSlot{Asset: asset, Amount: -1})
		}
	} else {
		world.Delegate = true
	}
	world.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
	for member, record := range world.Own {
		world.Curator[member] = record
	}
	return world
}

func TestPooledPolicyBindsSubjectReferences(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*policy.Policy)
	}{
		{"sender subject", func(p *policy.Policy) { p.SenderEntries[0].Own = 1 }},
		{"owner subject", func(p *policy.Policy) { p.OwnerEntries[1].Own = 0 }},
		{"asset subject", func(p *policy.Policy) { p.AssetEntries[1].Own = 0 }},
		{"public subject", func(p *policy.Policy) { p.PublicAssetEntries[0] = 0 }},
		{"withdrawal subject", func(p *policy.Policy) { p.OwnerEntries[2].Own = 0 }},
		{"curator subject", func(p *policy.Policy) { p.OwnerEntries[1].Curator[0] = 0 }},
		{"subject member", func(p *policy.Policy) { p.OwnSubjects[1].Member = ringpolicy.Sender }},
		{"subject raw record", func(p *policy.Policy) { p.OwnSubjects[1].RecordIndex = 0 }},
		{"subject index outside pool", func(p *policy.Policy) { p.OwnerEntries[1].Own = 3 }},
		{"raw record index outside pool", func(p *policy.Policy) { p.OwnSubjects[1].RecordIndex = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			world := poolWorld(ringpolicy.SectionShape{Outputs: 2, Withdrawals: 1}, false, false)
			world.Records = policy.RecordPoolShape{Own: 3, Curator: 3}
			witness := world.Build(t)
			if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			tc.mutate(witness.Policy())
			if test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()) == nil {
				t.Fatal("forged subject reference solved")
			}
		})
	}
}

func TestPooledPolicyRejectsCapacityOverflow(t *testing.T) {
	for _, capacity := range []policy.RecordPoolShape{{Own: -1}, {Own: int(^uint(0) >> 1)}, {Curator: -1}, {Curator: int(^uint(0) >> 1)}, {OwnSubjects: -1}, {OwnSubjects: int(^uint(0) >> 1)}, {CuratorSubjects: -1}, {CuratorSubjects: int(^uint(0) >> 1)}} {
		if _, err := ringpolicy.NewSectionCircuit(ringpolicy.SectionShape{Outputs: 2, Records: capacity}); err == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
}

func TestPooledPolicySharesAbsentPredecessor(t *testing.T) {
	world := poolWorld(ringpolicy.SectionShape{Outputs: 2}, true, false)
	world.Own, world.Curator = map[int64]ringpolicy.Record{}, map[int64]ringpolicy.Record{}
	world.Table.Rules = []ringpolicy.Rule{ringpolicy.Forbid(policy.SubjectSender, ringregistry.FrozenBit), ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit), ringpolicy.Forbid(policy.SubjectAsset, ringregistry.BlockBit)}
	world.Records = policy.RecordPoolShape{Own: 1, Curator: 1, OwnSubjects: 8, CuratorSubjects: 8}
	witness := world.Build(t)
	c, err := ringpolicy.NewSectionCircuit(ringpolicy.SectionShape{Outputs: 2, Records: world.Records})
	if err != nil {
		t.Fatal(err)
	}
	cs := ringkey.Compile(t, c)
	requirePooledCompiledSolved(t, cs, witness)
}

func TestPooledPolicyDistinctWithdrawalCapacity(t *testing.T) {
	world := poolWorld(ringpolicy.SectionShape{Outputs: 2, Withdrawals: 2}, true, false)
	witness := world.Build(t)
	if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
