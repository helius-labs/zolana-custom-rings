// Refusals of the signer data counts on each rail, and the encoding's fit to every key.

package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const signerDataPredicate = "audit.SignerDataCounts.Assert"

// senderOwnedOutput moves output 0 to the fixture sender, the run's first entry.
func senderOwnedOutput(t *testing.T, w *ringtransfer.Confidential) {
	t.Helper()
	w.World = plain(w.World)
	w.Outputs = map[int]func(*ringaudit.Slot){0: func(slot *ringaudit.Slot) {
		slot.OwnerKey = ringtransfer.SenderKey()
		slot.Utxo.OwnerPkHash = ringtransfer.Sender(t)
		slot.Utxo.NullifierPk = ringtransfer.SenderNullifierPk(t)
	}}
}

func packedElement(b ringtransfer.Built) int64 {
	return ringtest.AsBigInt(b.Circuit.SignerDataCounts).Int64()
}

// A key's outputs and the signature limit fit the encoding, a later change fails here first.
func TestEveryKeyFitsTheSignerDataEncoding(t *testing.T) {
	if audit.SignerDataEntries*audit.SignerDataEntryBits > 64 {
		t.Fatal("the entries outgrow the frame's u64")
	}
	for _, shape := range transfer.Shapes {
		if shape.Outputs >= 1<<audit.SignerDataEntryBits {
			t.Errorf("%v: %d outputs do not fit one entry", shape, shape.Outputs)
		}
	}
}

func TestSignerDataCountsOnTheRails(t *testing.T) {
	t.Run("a signer's data-bearing output", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		senderOwnedOutput(t, &w)
		w.HasData = true
		b := w.Build(t)
		if got := packedElement(b); got != 1 {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("the second entry of the run", func(t *testing.T) {
		key := ringtest.Repeat(0xc1)
		identity := ringtest.MustSolanaPkField(t, key)
		w := ringtransfer.Signed(confidential2)
		w.World = plain(w.World)
		w.HasData = true
		w.CoOwners = []*big.Int{identity}
		w.Outputs = map[int]func(*ringaudit.Slot){0: func(slot *ringaudit.Slot) {
			slot.OwnerKey = key
			slot.Utxo.OwnerPkHash = identity
			slot.Utxo.NullifierPk = ringtransfer.CoOwnerKey(t, identity)
		}}
		b := w.Build(t)
		if got := packedElement(b); got != 1<<audit.SignerDataEntryBits {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("a signer's ordinary output counts nothing", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		senderOwnedOutput(t, &w)
		b := w.Build(t)
		if got := packedElement(b); got != 0 {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("a data-bearing output off the run counts nothing", func(t *testing.T) {
		w := ringtransfer.Signed(dataKey2)
		w.World = plain(w.World)
		w.HasData = true
		b := w.Build(t)
		if got := packedElement(b); got != 0 {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("the hidden owner stays out of the element", func(t *testing.T) {
		w := ringtransfer.Hidden(anonData2)
		w.HasData = true
		b := w.Build(t)
		if got := ringtest.AsBigInt(b.Circuit.SignerDataCounts).Int64(); got != 0 {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
}

func TestSignerDataCountsRefusedOnTheRails(t *testing.T) {
	built := func(t *testing.T) ringtransfer.Built {
		t.Helper()
		w := ringtransfer.Signed(confidential2)
		senderOwnedOutput(t, &w)
		w.HasData = true
		w.CoOwners = []*big.Int{coOwner}
		return w.Build(t)
	}
	t.Run("the honest element", func(t *testing.T) {
		b := built(t)
		if got := packedElement(b); got != 1 {
			t.Fatalf("packed %d", got)
		}
		requireSolved(t, b.Circuit)
	})
	for _, tt := range []struct {
		name   string
		packed int64
	}{
		{"an omitted data-bearing output", 0},
		{"the count at another signer's position", 1 << audit.SignerDataEntryBits},
		{"a nonzero entry past the run", 1 | 1<<(2*audit.SignerDataEntryBits)},
		{"a false count", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := built(t)
			b.Circuit.SignerDataCounts = tt.packed
			b.Rebind(t)
			refused(t, b.Circuit, signerDataPredicate)
		})
	}
	t.Run("a bit past the last entry", func(t *testing.T) {
		b := built(t)
		b.Circuit.SignerDataCounts = new(big.Int).Add(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), audit.SignerDataEntries*audit.SignerDataEntryBits))
		b.Rebind(t)
		refused(t, b.Circuit, "[ToBinary]", signerDataPredicate)
	})
	t.Run("a statement of another count", func(t *testing.T) {
		b := built(t)
		values := b.Values(t)
		values.SignerDataCounts = big.NewInt(0)
		b.Circuit.PublicInputHash = spptest.MustHashChain4(t, values.Elements(t))
		refused(t, b.Circuit, "transfer.(*TransferCircuit).Define")
	})
	t.Run("a nonzero element on the delegate rail", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Circuit.SignerDataCounts = 1
		b.Rebind(t)
		refused(t, b.Circuit, signerDataPredicate)
	})
}
