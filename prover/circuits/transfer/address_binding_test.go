// A delegate must retain each spent note at its SPP nullifier position.
//
// Read after transfer/input.go and transfer/transfer.go. Read before audit/input_map_test.go.
package transfer_test

import (
	"encoding/binary"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestDelegateInputMapBindsVictimClassification(t *testing.T) {
	world := onRail(confidential2, ringtransfer.Delegate)
	address := ringaudit.SpareInput(1)
	address.Domain = transaction.AddressDomain
	address.OwnerPkHash = ringtransfer.Sender(t)
	world.Inputs = []ringaudit.Input{
		senderNote(t, 51),
		{Utxo: address},
		zeroKeyNote(t, otherOwner, ringID(t), 100, 52),
	}
	built := world.Build(t)
	requireSolved(t, built.Circuit)
	plaintext := built.Audit.Keys.Open(t, built.Audit.Stream(t))
	addressStart := audit.EnvelopeKeyLen + audit.RealInputCountLen
	if plaintext[audit.EnvelopeKeyLen] != 2 || binary.BigEndian.Uint64(plaintext[addressStart:addressStart+audit.AddressInputBitsLen]) != 0b010 {
		t.Fatal("sealed input map omits the victim note")
	}
	built.Circuit.Inputs[2].Domain = transaction.AddressDomain
	refused(t, built.Circuit, "transfer.transactionBinding.bindTransaction")
}
