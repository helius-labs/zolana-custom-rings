package transfer_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const recipientSlot = 1

var hiddenData = transfer.Shape{Inputs: 16, Outputs: 8, Withdrawals: 4, Owners: 4}

type fixture struct {
	name    string
	outputs int
	world   func(mutate func(*ringtransfer.World)) (circuit frontend.Circuit, statement func(edit func(*ringtransfer.Statement)))
}

func fixtures(t *testing.T) []fixture {
	return []fixture{
		{"signer", confidential2.Outputs, func(mutate func(*ringtransfer.World)) (frontend.Circuit, func(func(*ringtransfer.Statement))) {
			w := ringtransfer.Signed(confidential2)
			mutate(&w.World)
			b := w.Build(t)
			return b.Circuit, func(edit func(*ringtransfer.Statement)) {
				values := b.Values(t)
				edit(&values)
				b.Circuit.PublicInputHash = spptest.MustHashChain4(t, values.Elements(t))
			}
		}},
		{"hidden sender with data", hiddenData.Outputs, func(mutate func(*ringtransfer.World)) (frontend.Circuit, func(func(*ringtransfer.Statement))) {
			w := ringtransfer.Hidden(hiddenData)
			w.HasData = true
			mutate(&w.World)
			b := w.Build(t)
			return b.Circuit, func(edit func(*ringtransfer.Statement)) {
				values := b.Values(t)
				edit(&values)
				b.Circuit.PublicInputHash = spptest.MustHashChain4(t, values.Elements(t))
			}
		}},
	}
}

func unchanged(*ringtransfer.World) {}

func keyedOutputs(outputs int, owner, key *big.Int) map[int]func(*ringaudit.Slot) {
	mutations := make(map[int]func(*ringaudit.Slot), outputs)
	for i := range outputs {
		mutations[i] = func(slot *ringaudit.Slot) {
			if slot.Utxo.IsUtxo() && slot.Utxo.OwnerPkHash.Cmp(owner) == 0 {
				slot.Utxo.NullifierPk = key
			}
		}
	}
	return mutations
}

// Only the statement over another record moves.
func TestWrongAuditorRecordFailsAtTheStatement(t *testing.T) {
	for _, f := range fixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			honest, _ := f.world(unchanged)
			requireSolved(t, honest)
			circuit, rebind := f.world(unchanged)
			rebind(func(s *ringtransfer.Statement) {
				s.Outputs[recipientSlot].Record = append([]byte{}, s.Outputs[recipientSlot].Record...)
				s.Outputs[recipientSlot].Record[0] ^= 1
			})
			err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField())
			ringtest.RequireRefused(t, err, "[assertIsEqual]")
			// Every failure's stack names Define, only the statement equality has no gadget above it.
			if frames := strings.Split(err.Error(), "\n"); len(frames) < 2 || strings.TrimSpace(frames[1]) != "transfer.(*TransferCircuit).Define" {
				t.Fatalf("refused inside a gadget: %v", err)
			}
		})
	}
}

// The row, its root, the commitment and the statement follow the one moved key.
func TestWrongTrackingKeyFailsAtItsPredicate(t *testing.T) {
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 1, 1, 1).OwnerKey)
	other := ringtransfer.CoOwnerKey(t, big.NewInt(0x0e0e))
	enrolled := func(owner *big.Int, w *ringtransfer.World) {
		w.Enrolled = map[string]*big.Int{owner.String(): other}
	}
	for _, f := range fixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			t.Run("the output under the row's key solves", func(t *testing.T) {
				circuit, _ := f.world(func(w *ringtransfer.World) {
					enrolled(recipient, w)
					w.Outputs = keyedOutputs(f.outputs, recipient, other)
				})
				requireSolved(t, circuit)
			})
			t.Run("the output under another key", func(t *testing.T) {
				circuit, _ := f.world(func(w *ringtransfer.World) { enrolled(recipient, w) })
				refused(t, circuit, "transfer.AssertOutputOwners")
			})
			t.Run("the spent note under another key", func(t *testing.T) {
				sender := ringtransfer.Sender(t)
				circuit, _ := f.world(func(w *ringtransfer.World) {
					enrolled(sender, w)
					// The sender's outputs follow the row, the input alone stays off it.
					w.Outputs = keyedOutputs(f.outputs, sender, other)
				})
				refused(t, circuit, "transfer.OwnerRows.AssertInputOwners")
			})
		})
	}
}
