// SPP's address chain enters the ring as a private witness, private_tx_hash alone checks it.
//
// Read after transfer/input.go and transfer/transfer.go. Read before audit/input_map_test.go.
package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

func TestAddressChainIsBoundThroughThePrivateTransactionHash(t *testing.T) {
	world := onRail(confidential2, ringtransfer.Delegate)
	world.Inputs = []ringaudit.Input{senderNote(t, 51), zeroKeyNote(t, otherOwner, ringID(t), 100, 52)}
	world.Addresses = []*big.Int{big.NewInt(0xadd1), big.NewInt(0xadd2)}
	built := world.Build(t)
	requireSolved(t, built.Circuit)
	t.Run("another address chain", func(t *testing.T) {
		built := world.Build(t)
		built.Circuit.AddressChain = big.NewInt(0xadd3)
		refused(t, built.Circuit, "transfer.transactionBinding.bindTransaction")
	})
	// A delegate dropping a victim's note from its inputs opens another note chain than SPP spends.
	t.Run("a spent note left out", func(t *testing.T) {
		built := world.Build(t)
		built.Circuit.Inputs[1] = built.Circuit.Inputs[2]
		refused(t, built.Circuit, "transfer.transactionBinding.bindTransaction")
	})
}
