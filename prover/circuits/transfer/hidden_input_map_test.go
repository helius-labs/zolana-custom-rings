package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestHiddenOwnerRequiresANoteInSlotZero(t *testing.T) {
	address := ringaudit.Input{Utxo: ringaudit.Dummy(0, big.NewInt(31))}
	address.Utxo.Domain = transaction.AddressDomain
	w := ringtransfer.Hidden(anonymous2)
	w.Inputs = []ringaudit.Input{senderNote(t, 51), address}
	requireSolved(t, w.Build(t).Circuit)
	w.Inputs[0], w.Inputs[1] = w.Inputs[1], w.Inputs[0]
	refused(t, w.Build(t).Circuit, "transfer.(*TransferCircuit).hiddenOwner")
}
