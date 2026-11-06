// Refusals of the withdrawal legs, a leg off the bound hash and padding that is not zero, at every capacity.

package policy_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"math"
	"testing"
)

// withdrawalCapacities are the leg capacities the padding and binding tests sweep.
var withdrawalCapacities = []int{0, 1, 2, 4, 8, 16, 32}

func withdrawalWorld() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.WithdrawalCapacity = 2
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 20}}
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -20}}
	return w
}
func TestPolicyWithdrawals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ringpolicy.World)
		valid  bool
	}{
		{"listed", func(w *ringpolicy.World) {}, true},
		{"absent owner", func(w *ringpolicy.World) { w.Withdrawals[0].Owner = ringpolicy.Carol }, false},
		{"blocked owner", func(w *ringpolicy.World) {
			w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit))
			w.Own[ringpolicy.Bob] = ringpolicy.Record{Lists: ringregistry.AllowBit | ringregistry.BlockBit}
		}, false},
		{"withdrawn asset absent", func(w *ringpolicy.World) {
			w.Table.Rules = append(w.Table.Rules, ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit))
			w.Own[ringpolicy.AssetA] = ringpolicy.Record{Lists: ringregistry.AllowBit}
			w.Withdrawals[0].Asset = ringpolicy.AssetB
		}, false},
		{"unregistered allowed withdrawal owner", func(w *ringpolicy.World) { w.Own[ringpolicy.Bob] = ringpolicy.Record{Lists: ringregistry.AllowBit} }, true},
		{"zero amount", func(w *ringpolicy.World) { w.Withdrawals[0].Amount = 0 }, false},
		{"split guard inclusive", func(w *ringpolicy.World) { guardSplit(w, 10) }, true},
		{"split guard exceeded", func(w *ringpolicy.World) { guardSplit(w, 11) }, false},
		{"deposit cannot offset guard", func(w *ringpolicy.World) { guardSplit(w, 11); w.Public[0].Amount = 300 }, false},
		{"scalar guard reads each mint apart", func(w *ringpolicy.World) { guardSplit(w, 11); w.Withdrawals[0].Asset = ringpolicy.AssetB }, true},
		{"withdrawal outflow counted once", func(w *ringpolicy.World) {
			w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 320}}
		}, true},
		{"maximum amount aggregate", func(w *ringpolicy.World) {
			w.Table.Limits = nil
			w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: math.MaxUint64}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: math.MaxUint64}}
			w.Table.Rules[0].Guard = policy.GuardAboveAmount
			w.Table.Rules[0].Threshold = math.MaxUint64
			w.Own[ringpolicy.Bob] = ringpolicy.Record{}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := withdrawalWorld()
			tc.mutate(&w)
			b := w.Build(t)
			err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
func guardSplit(w *ringpolicy.World, amount uint64) {
	w.Table.Limits = nil
	w.Table.Rules[0].Guard = policy.GuardAboveAmount
	w.Table.Rules[0].Threshold = 320
	w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: 0}
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 10}, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: amount}}
}
func TestPolicyWithdrawalBindingAndPadding(t *testing.T) {
	for _, mutate := range []func(ringpolicy.Witness){
		func(b ringpolicy.Witness) { b.Policy().Withdrawals[0].Amount = 21 },
		func(b ringpolicy.Witness) { b.Policy().Withdrawals[0].Owner = ringpolicy.Alice },
		func(b ringpolicy.Witness) { b.Policy().Withdrawals[0].Asset = ringpolicy.AssetB },
		func(b ringpolicy.Witness) { b.Policy().Withdrawals[1].Amount = 1; b.Rebind(t) },
		func(b ringpolicy.Witness) { b.Policy().WithdrawalCount = 3 },
		func(b ringpolicy.Witness) {
			b.Policy().Withdrawals[0], b.Policy().Withdrawals[1] = b.Policy().Withdrawals[1], b.Policy().Withdrawals[0]
		},
	} {
		b := withdrawalWorld().Build(t)
		mutate(b)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("tampered withdrawal solved")
		}
	}
}
func TestCuratorWithdrawalLists(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		w := withdrawalWorld()
		w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true, ringregistry.BlockBit: true}
		w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit))
		w.Curator = map[int64]ringpolicy.Record{}
		for k, v := range w.Own {
			w.Curator[k] = v
		}
		if blocked {
			w.Curator[ringpolicy.Bob] = ringpolicy.Record{Lists: ringregistry.AllowBit | ringregistry.BlockBit}
		}
		b := w.Build(t)
		if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); (err == nil) == blocked {
			t.Fatalf("blocked %v: %v", blocked, err)
		}
	}
}

func TestWithdrawalCapacitiesBindEveryLeg(t *testing.T) {
	for _, capacity := range withdrawalCapacities {
		w := withdrawalWorld()
		w.WithdrawalCapacity = capacity
		w.Withdrawals = nil
		for range capacity {
			w.Withdrawals = append(w.Withdrawals, ringpolicy.Slot{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 1})
		}
		b := w.Build(t)
		if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("capacity %d: %v", capacity, err)
		}
		b.Policy().WithdrawalCount = capacity + 1
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("count exceeded capacity")
		}
	}
}
