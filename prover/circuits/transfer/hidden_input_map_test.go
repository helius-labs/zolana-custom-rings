package transfer_test

import (
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

// The hidden rail reads the first note.
func TestHiddenOwnerRequiresAFirstNote(t *testing.T) {
	w := ringtransfer.Hidden(anonymous2)
	w.Inputs = []ringaudit.Input{senderNote(t, 51)}
	requireSolved(t, w.Build(t).Circuit)
	w.Inputs = nil
	w.PublicFunded = true
	refused(t, w.Build(t).Circuit, "transfer.(*TransferCircuit).hiddenOwner")
}
