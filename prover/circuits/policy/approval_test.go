// Refusals of the approval mask, a bit that follows the gross, thresholds off a policy, and a delegate that clears both bits.

package policy_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

const sectionDefine = "ringpolicy.(*SectionCircuit).Define"

// watched withdraws gross of AssetA to Bob under a record threshold of 100.
func watched(gross uint64) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.WithdrawalCapacity = 2
	w.Own[ringpolicy.AssetA] = ringpolicy.Record{WithdrawalThreshold: 100}
	w.Table.Limits = nil
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: gross}}
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -int64(gross), Gross: gross}}
	return w
}

func requireMask(t *testing.T, w ringpolicy.World, mask uint64) {
	t.Helper()
	w.Approval = mask
	requireSolved(t, w.Build(t))
	for _, other := range []uint64{0, policy.ApprovalOutflow, policy.ApprovalWithdrawal, policy.ApprovalOutflow | policy.ApprovalWithdrawal} {
		if other != mask {
			w.Approval = other
			requireRefusedIn(t, w, sectionDefine)
		}
	}
}

func TestWithdrawalBitReadsTheGross(t *testing.T) {
	t.Run("at the threshold", func(t *testing.T) { requireMask(t, watched(100), 0) })
	t.Run("past the threshold", func(t *testing.T) { requireMask(t, watched(101), policy.ApprovalWithdrawal) })
	t.Run("an asset without a record has no threshold", func(t *testing.T) {
		w := watched(5000)
		delete(w.Own, ringpolicy.AssetA)
		requireMask(t, w, 0)
	})
	t.Run("a zero threshold is none", func(t *testing.T) {
		w := watched(5000)
		w.Own[ringpolicy.AssetA] = ringpolicy.Record{}
		requireMask(t, w, 0)
	})
	t.Run("gross with a zero debit sets the bit alone", func(t *testing.T) {
		w := watched(101)
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200}}
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 5000}}
		requireMask(t, w, policy.ApprovalWithdrawal)
	})
	t.Run("a deposit is not subtracted", func(t *testing.T) {
		w := watched(101)
		w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 900, Gross: 101}}
		requireMask(t, w, policy.ApprovalWithdrawal)
	})
	t.Run("a gross outside 72 bits fails while read", func(t *testing.T) {
		w := watched(100)
		w.Approval = policy.ApprovalWithdrawal
		b := w.Build(t)
		b.Policy().PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 72)
		b.Rebind(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("a gross outside 72 bits solved")
		}
	})
}

// A plain ring with an own registry holds its thresholds with a zero policy hash.
func TestThresholdsBindOffAPolicy(t *testing.T) {
	plain := func(gross uint64) ringpolicy.World {
		w := watched(gross)
		w.Unscreened = true
		w.Withdrawals, w.WithdrawalCapacity = nil, 0
		return w
	}
	t.Run("withdrawal bit", func(t *testing.T) { requireMask(t, plain(5000), policy.ApprovalWithdrawal) })
	t.Run("outflow bit", func(t *testing.T) {
		w := plain(0)
		w.Public = nil
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 100}}
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1000}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 1000}}
		requireMask(t, w, policy.ApprovalOutflow)
	})
	t.Run("a cap", func(t *testing.T) {
		w := plain(0)
		w.Public = nil
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 100}}
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1000}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 1000}}
		requireRefusedIn(t, w, outflow)
	})
	t.Run("both bits", func(t *testing.T) {
		w := plain(5000)
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 100}}
		requireMask(t, w, policy.ApprovalOutflow|policy.ApprovalWithdrawal)
	})
	t.Run("deposit funded return reads outflow", func(t *testing.T) {
		w := plain(0)
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 100}}
		w.Own[ringpolicy.AssetA] = ringpolicy.Record{}
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1000}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1001}}
		w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 1, Gross: 999}}
		requireMask(t, w, policy.ApprovalOutflow)
	})
	t.Run("a ring without an own registry holds no thresholds", func(t *testing.T) {
		w := plain(5000)
		w.NoOwnRegistry = true
		w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 100, CosignAbove: 100}}
		requireMask(t, w, 0)
	})
	t.Run("an unread gross past u64 stays unread", func(t *testing.T) {
		w := plain(100)
		w.NoOwnRegistry = true
		b := w.Build(t)
		b.Policy().PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		b.Rebind(t)
		requireSolved(t, b)
	})
}

// The authority rail bypasses every policy, the mask stays zero whatever the thresholds.
func TestDelegateClearsTheMask(t *testing.T) {
	w := watched(5000)
	w.Delegate = true
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 1, CosignAbove: 1}}
	w.Own[ringpolicy.Bob] = ringpolicy.Record{}
	w.Own[ringpolicy.Alice] = ringpolicy.Record{}
	w.Withdrawals, w.WithdrawalCapacity = nil, 0
	requireMask(t, w, 0)
	t.Run("reads no table", func(t *testing.T) {
		b := w.Build(t)
		b.Policy().Rules[0] = ringpolicy.Require(policy.SubjectSender, 1).Packed()
		requireSolved(t, b)
	})
	t.Run("thresholds_active set refuses", func(t *testing.T) {
		b := w.Build(t)
		b.Circuit.ThresholdsActive = 1
		b.Rebind(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("a delegate proof with thresholds_active solved")
		}
	})
	t.Run("the same witness off the authority rail is screened", func(t *testing.T) {
		off := w
		off.Delegate = false
		off.Approval = policy.ApprovalOutflow | policy.ApprovalWithdrawal
		b := off.Build(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), "policy.assertPaymentRules")
	})
}
