package policy_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestGrossAboveU64SetsWithdrawalApproval(t *testing.T) {
	maximumLegs := make([]uint64, 16)
	for i := range maximumLegs {
		maximumLegs[i] = math.MaxUint64
	}
	for _, tc := range []struct {
		name string
		legs []uint64
	}{
		{"two to the sixty fourth", []uint64{math.MaxUint64, 1}},
		{"maximum gross with balanced public legs", maximumLegs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := watched(1)
			w.WithdrawalCapacity = 32
			w.Withdrawals = nil
			w.Own[ringpolicy.AssetA] = ringpolicy.Record{WithdrawalThreshold: math.MaxUint64}
			w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -1}}
			w.Approval = policy.ApprovalWithdrawal
			gross := new(big.Int)
			for _, amount := range tc.legs {
				w.Withdrawals = append(w.Withdrawals, ringpolicy.Slot{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: amount})
				gross.Add(gross, new(big.Int).SetUint64(amount))
			}
			build := func(mask frontend.Variable) ringpolicy.Witness {
				b := w.Build(t)
				b.Policy().PublicGross[0] = gross
				b.Circuit.ApprovalMask = mask
				b.Rebind(t)
				return b
			}
			requireSolved(t, build(policy.ApprovalWithdrawal))
			unapproved := build(0)
			ringtest.RequireRefused(t, test.IsSolved(unapproved.Assignment(), unapproved.Assignment(), ecc.BN254.ScalarField()), sectionDefine)
		})
	}
}

// The program hashes u64 settlement amounts alone, a forged leg past 2^64 opens no digest of the settlement.
func TestWithdrawalLegBindsTheSettledAmount(t *testing.T) {
	w := watched(1)
	w.Own[ringpolicy.AssetA] = ringpolicy.Record{WithdrawalThreshold: math.MaxUint64}
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: math.MaxUint64}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 1}}
	w.Approval = policy.ApprovalWithdrawal
	build := func(second *big.Int) ringpolicy.Witness {
		b := w.Build(t)
		b.Policy().Withdrawals[1].Amount = second
		b.Policy().PublicGross[0] = new(big.Int).Add(new(big.Int).SetUint64(math.MaxUint64), second)
		b.Rebind(t)
		return b
	}
	requireSolved(t, build(big.NewInt(1)))
	settledHash := build(big.NewInt(1)).Policy().WithdrawalHash
	forgedAmount := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	// The circuit range checks no leg, a digest over the forged leg solves.
	requireSolved(t, build(forgedAmount))
	// The program's digest over the settled u64 leg refuses the forged amount.
	forged := build(forgedAmount)
	forged.Policy().WithdrawalHash = settledHash
	forged.Circuit.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(forged.Circuit.Statement()))
	ringtest.RequireRefused(t, test.IsSolved(forged.Assignment(), forged.Assignment(), ecc.BN254.ScalarField()), "openWithdrawals")
}
