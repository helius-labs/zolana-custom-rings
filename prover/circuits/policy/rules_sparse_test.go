package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func TestScalarOwnerGuardAcrossInactivePayments(t *testing.T) {
	for _, different := range []bool{false, true} {
		for _, withdrawal := range []bool{false, true} {
			for _, firstLive := range []bool{false, true} {
				world := ringpolicy.Confidential()
				world.Outputs = 4
				world.Table.Limits = nil
				world.Table.Rules[0].Guard = policy.GuardAboveAmount
				world.Table.Rules[0].Threshold = 1000
				world.Slots = []ringpolicy.Slot{{}, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}, {}, {Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 100}}
				if firstLive {
					world.Slots[0], world.Slots[1] = world.Slots[1], world.Slots[0]
				}
				last := &world.Slots[3]
				if withdrawal {
					world.WithdrawalCapacity = 2
					world.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
					last = &world.Withdrawals[0]
				}
				if different {
					last.Asset = ringpolicy.AssetB
				}
				witness := world.Build(t)
				err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField())
				if (err != nil) != different {
					t.Fatalf("different=%v withdrawal=%v firstLive=%v error=%v", different, withdrawal, firstLive, err)
				}
			}
		}
	}
}

func TestWithdrawalPrefixZeroPadding(t *testing.T) {
	for _, capacity := range policy.WithdrawalCapacities {
		for _, count := range []int{0, max(0, capacity-1), capacity} {
			world := ringpolicy.Confidential()
			world.OwnOnly, world.WithdrawalCapacity = true, capacity
			world.Table.Limits = nil
			for range count {
				world.Withdrawals = append(world.Withdrawals, ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 1})
			}
			witness := world.Build(t)
			if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("capacity=%d count=%d error=%v", capacity, count, err)
			}
			if count < capacity {
				witness.Member.Withdrawals[count].Asset = ringpolicy.AssetB
				if test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()) == nil {
					t.Fatalf("nonzero suffix passed at capacity=%d count=%d", capacity, count)
				}
			}
		}
	}
}
