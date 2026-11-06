package ringregistry

import (
	"math"
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func (e Entry) Wires() registry.RecordWrite {
	return registry.RecordWrite{
		Member: copied(e.Member), Mask: copied(e.Mask), Value: copied(e.Value),
		MintPolicy: copied(e.MintPolicy), WithdrawalThreshold: copied(e.WithdrawalThreshold), AssetLimits: e.AssetLimits.Wires(),
	}
}

func (w Write) Wires() registry.RecordWriteProofInput {
	return registry.RecordWriteProofInput{
		Entry: w.Entry.Wires(), Exists: ringtest.Bit(w.Exists),
		Old: registry.RecordBody{
			Next: copied(w.OldNext), Lists: copied(w.OldLists), MintPolicy: copied(w.OldMintPolicy),
			WithdrawalThreshold: copied(w.OldWithdrawalThreshold), AssetLimits: w.OldAssetLimits.Wires(),
		},
		Slot: w.Slot.Wires(), Low: w.Low.Wires(), LowSlot: w.LowPath.Wires(),
	}
}

// Restrictive mirrors the restrictive bit apply_records.go proves over the first count writes.
func Restrictive(writes []registry.RecordWriteProofInput, count int) int64 {
	for _, w := range writes[:count] {
		if restricts(w) {
			return 1
		}
	}
	return 0
}

func restricts(w registry.RecordWriteProofInput) bool {
	mask, value, old := ringtest.AsBigInt(w.Entry.Mask).Uint64(), ringtest.AsBigInt(w.Entry.Value).Uint64(), ringtest.AsBigInt(w.Old.Lists).Uint64()
	const grants, denies, private = AllowBit | ApprovalBit | PrivateAllowBit, BlockBit | FrozenBit | PrivateBlockBit | PrivateFrozenBit, PrivateBlockBit | PrivateAllowBit | PrivateFrozenBit
	if mask&private != 0 || old&mask&^value&grants != 0 || value&^old&denies != 0 {
		return true
	}
	policy := ringtest.AsBigInt(w.Entry.MintPolicy)
	if policy.Bit(192) == 0 {
		return false
	}
	oldPolicy := ringtest.AsBigInt(w.Old.MintPolicy)
	limb := func(packed *big.Int, k uint) uint64 {
		return new(big.Int).And(new(big.Int).Rsh(packed, 64*k), new(big.Int).SetUint64(math.MaxUint64)).Uint64()
	}
	// Zero bounds nothing, the wrap orders it above every amount.
	top := func(v uint64) uint64 { return v - 1 }
	if limb(policy, 2) < limb(oldPolicy, 2) ||
		top(limb(policy, 1)) < top(limb(oldPolicy, 1)) ||
		top(limb(policy, 0)) < top(limb(oldPolicy, 0)) ||
		top(ringtest.AsBigInt(w.Entry.WithdrawalThreshold).Uint64()) < top(ringtest.AsBigInt(w.Old.WithdrawalThreshold).Uint64()) {
		return true
	}
	for i := range w.Entry.AssetLimits {
		if ringtest.AsBigInt(w.Entry.AssetLimits[i]).Cmp(ringtest.AsBigInt(w.Old.AssetLimits[i])) != 0 {
			return true
		}
	}
	return false
}
