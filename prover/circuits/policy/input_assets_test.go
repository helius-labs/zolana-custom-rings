// Refusals of the input asset rules, a zero value delisted input and an input asset subject the root does not hold.

package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

const inputAssetRules = "policy.assertInputAssetRules"

func solve(b ringpolicy.Witness) error {
	return test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
}

// zeroValueInput pays AssetA alone and spends a zero value note of AssetB, the slot beside the funding note.
func zeroValueInput() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Limits = nil
	w.Own[ringpolicy.AssetA] = ringpolicy.Record{Lists: ringregistry.AllowBit}
	w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 500}, {Owner: ringpolicy.Sender, Asset: ringpolicy.AssetB}}
	return w
}

func requireListedAssets(w ringpolicy.World) ringpolicy.World {
	w.Table.Rules = append(w.Table.Rules, ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit))
	return w
}

// The zero value input moves nothing, so no payment reads its asset and only the input section can refuse it.
func TestZeroValueDelistedInputFailsAnUnconditionalAssetRule(t *testing.T) {
	t.Run("listed", func(t *testing.T) {
		w := requireListedAssets(zeroValueInput())
		w.Own[ringpolicy.AssetB] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		requireSolved(t, w.Build(t))
	})
	t.Run("delisted", func(t *testing.T) {
		ringtest.RequireRefused(t, solve(requireListedAssets(zeroValueInput()).Build(t)), inputAssetRules)
	})
	t.Run("default ring note delisted", func(t *testing.T) {
		w := requireListedAssets(zeroValueInput())
		w.Inputs[1].Exit = true
		ringtest.RequireRefused(t, solve(w.Build(t)), inputAssetRules)
	})
	t.Run("off every forbidden list", func(t *testing.T) {
		w := zeroValueInput()
		w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectAsset, ringregistry.BlockBit))
		requireSolved(t, w.Build(t))
	})
	t.Run("on a forbidden list", func(t *testing.T) {
		w := zeroValueInput()
		w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectAsset, ringregistry.BlockBit))
		w.Own[ringpolicy.AssetB] = ringpolicy.Record{Lists: ringregistry.BlockBit}
		ringtest.RequireRefused(t, solve(w.Build(t)), inputAssetRules)
	})
	t.Run("curator list", func(t *testing.T) {
		w := requireListedAssets(zeroValueInput())
		w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
		for _, member := range []int64{ringpolicy.Sender, ringpolicy.Alice, ringpolicy.AssetA} {
			w.Own[member] = ringpolicy.Record{Lists: 0}
			w.Curator[member] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		}
		ringtest.RequireRefused(t, solve(w.Build(t)), inputAssetRules)
		w.Curator[ringpolicy.AssetB] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		requireSolved(t, w.Build(t))
	})
}

func TestInputAssetSubjectIsAuthenticated(t *testing.T) {
	inputEntries := func(b ringpolicy.Witness) []policy.PoolEntry {
		return b.Policy().AssetEntries[len(b.Policy().OwnerEntries):]
	}
	t.Run("reference to a listed asset's subject", func(t *testing.T) {
		b := requireListedAssets(zeroValueInput()).Build(t)
		entries := inputEntries(b)
		entries[1].Own = entries[0].Own
		ringtest.RequireRefused(t, solve(b), "policy.subjectPool.read")
	})
	t.Run("forged record", func(t *testing.T) {
		b := requireListedAssets(zeroValueInput()).Build(t)
		b.OwnRecord(inputEntries(b)[1]).Lists = ringregistry.AllowBit | ringregistry.BlockBit
		ringtest.RequireRefused(t, solve(b), "registry.SharedQuadProof.AssertLeavesWhen")
	})
}

func TestInputAssetRulesSkipDummiesAndTheAuthorityRail(t *testing.T) {
	t.Run("dummy", func(t *testing.T) {
		w := requireListedAssets(zeroValueInput())
		w.Inputs[1].Owner = 0
		requireSolved(t, w.Build(t))
	})
	t.Run("delegate", func(t *testing.T) {
		w := requireListedAssets(zeroValueInput())
		w.Delegate = true
		requireSolved(t, w.Build(t))
	})
}

// guardedAssetRule leaves AssetA and AssetB delisted, a guard alone can pay AssetA.
func guardedAssetRule(guard, threshold uint64) ringpolicy.World {
	w := zeroValueInput()
	delete(w.Own, ringpolicy.AssetA)
	rule := ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)
	rule.Guard, rule.Threshold = guard, threshold
	w.Table.Rules = append(w.Table.Rules, rule)
	return w
}

// Alice's 300 is the whole total, the sender's change nets to zero against its inputs. An input amount in the total would read 800.
func TestGuardedAssetRuleKeepsItsTotals(t *testing.T) {
	t.Run("scalar guard at the total", func(t *testing.T) {
		requireSolved(t, guardedAssetRule(policy.GuardAboveAmount, 300).Build(t))
	})
	t.Run("scalar guard below the total", func(t *testing.T) {
		ringtest.RequireRefused(t, solve(guardedAssetRule(policy.GuardAboveAmount, 299).Build(t)), "policy.paymentScreen.assert")
	})
	t.Run("a larger funding input moves no total", func(t *testing.T) {
		w := guardedAssetRule(policy.GuardAboveAmount, 300)
		w.Inputs[0].Amount = 5000
		requireSolved(t, w.Build(t))
	})
	t.Run("asset guard at the total", func(t *testing.T) {
		w := guardedAssetRule(policy.GuardAboveAmountByAsset, 0)
		w.Table.Inline = []ringpolicy.InlineLimit{{Asset: ringpolicy.AssetA, Limit: 300}}
		requireSolved(t, w.Build(t))
	})
	t.Run("asset guard below the total", func(t *testing.T) {
		w := guardedAssetRule(policy.GuardAboveAmountByAsset, 0)
		w.Table.Inline = []ringpolicy.InlineLimit{{Asset: ringpolicy.AssetA, Limit: 299}}
		ringtest.RequireRefused(t, solve(w.Build(t)), "policy.paymentScreen.assert")
	})
	t.Run("zero threshold with nothing paid in the input's asset", func(t *testing.T) {
		w := guardedAssetRule(policy.GuardAboveAmount, 0)
		w.Own[ringpolicy.AssetA] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		requireSolved(t, w.Build(t))
	})
}

// Every input repeats the payment's asset, the three rows of the sender, the owner and the asset hold them all.
func TestRepeatedInputAssetsShareOneRecord(t *testing.T) {
	w := poolWorld(ringpolicy.SectionShape{Outputs: 2}, false, false)
	w.Records = policy.RecordPoolShape{Own: 3, Curator: 3}
	w.Inputs = nil
	for range 2 + len(w.Public) {
		w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1})
	}
	requireSolved(t, w.Build(t))
}

// Every payment subject is distinct, the unmatched zero value notes spend on the rows left free.
func TestUnmatchedInputAssetsTakeFreeRows(t *testing.T) {
	w := poolWorld(ringpolicy.SectionShape{Outputs: 2}, true, false)
	w.Inputs = nil
	free := 3
	for i := range free {
		asset := int64(40000 + i)
		w.Own[asset], w.Curator[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}, ringpolicy.Record{Lists: ringregistry.AllowBit}
		w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: ringpolicy.Sender, Asset: asset})
	}
	requireSolved(t, w.Build(t))
}
