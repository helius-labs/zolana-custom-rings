// The guard totals and the withdrawal hash at sparse payments, a dummy or a leg past the count adds nothing.

package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

// A dummy or a leg past the count adds nothing to an owner's or an asset's guard, each asset sums apart.
func TestGuardsSkipInactivePayments(t *testing.T) {
	for _, different := range []bool{false, true} {
		for _, withdrawal := range []bool{false, true} {
			for _, firstLive := range []bool{false, true} {
				world := ringpolicy.Confidential()
				world.Outputs = 4
				world.Table.Limits = nil
				world.Table.Rules[0].Guard = policy.GuardAboveAmount
				world.Table.Rules[0].Threshold = 1000
				assetRule := ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)
				assetRule.Guard, assetRule.Threshold = policy.GuardAboveAmount, 1000
				world.Table.Rules = append(world.Table.Rules, assetRule)
				dummy := ringpolicy.Slot{Asset: ringpolicy.AssetA, Amount: 5000}
				world.Slots = []ringpolicy.Slot{dummy, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}, dummy, {Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 100}}
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
				if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
					t.Fatalf("different=%v withdrawal=%v firstLive=%v error=%v", different, withdrawal, firstLive, err)
				}
			}
		}
	}
}

func TestWithdrawalPrefixZeroPadding(t *testing.T) {
	for _, capacity := range withdrawalCapacities {
		for _, count := range []int{0, max(0, capacity-1), capacity} {
			world := ringpolicy.Confidential()
			world.WithdrawalCapacity = capacity
			world.Table.Limits = nil
			for range count {
				world.Withdrawals = append(world.Withdrawals, ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 1})
			}
			witness := world.Build(t)
			if err := test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("capacity=%d count=%d error=%v", capacity, count, err)
			}
			if count < capacity {
				witness.Circuit.Withdrawals[count].Asset = ringpolicy.AssetB
				if test.IsSolved(witness.Assignment(), witness.Assignment(), ecc.BN254.ScalarField()) == nil {
					t.Fatalf("nonzero suffix passed at capacity=%d count=%d", capacity, count)
				}
			}
		}
	}
}
