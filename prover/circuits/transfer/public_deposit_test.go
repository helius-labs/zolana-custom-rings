// A ring deposit is a transfer spending no note, its public leg funds the ring outputs.

package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

func publicDeposit(t *testing.T, w ringtransfer.World) ringtransfer.World {
	w.PublicFunded = true
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: 1_000}}
	return w
}

// signerDeposit empties the run, no note owner signs a deposit.
func signerDeposit(t *testing.T, edit func(*ringtransfer.World)) ringtransfer.Built {
	w := ringtransfer.Signed(confidential2)
	w.World = publicDeposit(t, w.World)
	edit(&w.World)
	b := w.Build(t)
	b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0], b.Circuit.SignerDataCounts = nil, 0, 0, 0
	b.Rebind(t)
	if !b.Values(t).NoSpend {
		t.Fatal("a deposit spent a note")
	}
	return b
}

func TestPublicDepositIntoTheRing(t *testing.T) {
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 0, 0, 1).OwnerKey)
	t.Run("a policy ring on the signer rail", func(t *testing.T) {
		b := signerDeposit(t, func(*ringtransfer.World) {})
		ringtest.RequirePublicInputBound(t, b.Circuit, b.Circuit)
	})
	t.Run("a plain ring", func(t *testing.T) {
		requireSolved(t, signerDeposit(t, func(w *ringtransfer.World) { *w = plain(*w) }).Circuit)
	})
	t.Run("a thresholds ring proves no approval", func(t *testing.T) {
		b := signerDeposit(t, func(w *ringtransfer.World) {
			w.Policy = ringtransfer.Policy{OwnRegistry: true, Cap: 1, CosignAbove: 1, WithdrawalThreshold: 1}
		})
		requireSolved(t, b.Circuit)
	})
	t.Run("the public owner rail of an anonymous ring", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		w.World = publicDeposit(t, w.World)
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0], b.Circuit.SignerDataCounts = nil, 0, 0, 0
		b.Rebind(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("a recipient key with no row", func(t *testing.T) {
		b := signerDeposit(t, func(w *ringtransfer.World) { w.Unenrolled = []*big.Int{recipient} })
		refused(t, b.Circuit, "transfer.AssertOutputOwners")
	})
	t.Run("a recipient on a salted block list", func(t *testing.T) {
		b := signerDeposit(t, func(w *ringtransfer.World) { w.SaltedBlock = []*big.Int{recipient} })
		refused(t, b.Circuit, "policy.assertPaymentRules")
	})
	t.Run("the hidden rail needs a live input", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.World = publicDeposit(t, w.World)
		refused(t, w.Build(t).Circuit, "transfer.(*TransferCircuit).hiddenOwner")
	})
}
