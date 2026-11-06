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

var payoutShape = transfer.Shape{Inputs: 1, Outputs: 16, Owners: 1, SingleAssetPayout: true}

func TestSingleAssetPayoutSolvesAndOpensEveryRecipient(t *testing.T) {
	world := ringtransfer.Signed(payoutShape)
	world.SaltedBlock = []*big.Int{}
	world.Outputs = make(map[int]func(*ringaudit.Slot), payoutShape.Outputs)
	for i := range payoutShape.Outputs {
		owner := ringtest.Repeat(0x40 + byte(i))
		nullifier := spptest.MustNullifierPk(t, big.NewInt(40+int64(i)))
		world.Outputs[i] = func(slot *ringaudit.Slot) {
			slot.OwnerKey = owner
			slot.Utxo.OwnerPkHash = ringtest.MustSolanaPkField(t, owner)
			slot.Utxo.NullifierPk = nullifier
		}
	}
	built := world.Build(t)
	requireSolved(t, built.Circuit)
	stream := built.Audit.Stream(t)
	if len(stream.Envelope(1)) != 73 || stream.Ranges.RecordCounter(0) != 7 || len(stream.Ciphertext) != 1360 {
		t.Fatal("payout stream layout differs")
	}
	for i, output := range built.Audit.Outputs {
		if len(stream.Record(i)) != 73 {
			t.Fatal("payout record length differs")
		}
		note, err := built.Audit.Reader().Read(t, stream, i, output.Utxo.Hash(t))
		if err != nil || note == nil || note.Mint != ringaudit.FixtureMint || note.Amount != output.Utxo.Amount {
			t.Fatalf("recipient %d did not open %v", i, err)
		}
	}
}

func TestSingleAssetPayoutRefusesOtherAssetsAndSlots(t *testing.T) {
	for name, change := range map[string]func(*ringtransfer.Confidential){
		"output asset": func(w *ringtransfer.Confidential) {
			w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) {
				slot.Mint = ringtest.Repeat(0x35)
				slot.Utxo.Asset = ringtest.AssetField(t, slot.Mint)
			}}
		},
		"exit": func(w *ringtransfer.Confidential) { w.Exits = []int{0} },
		"dummy": func(w *ringtransfer.Confidential) {
			w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) {
				slot.Utxo = ringaudit.Dummy(slot.Utxo.TreeID, slot.Utxo.Blinding)
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			world := ringtransfer.Signed(payoutShape)
			change(&world)
			refused(t, world.Build(t).Circuit, "OpenSlots")
		})
	}
}

func TestSingleAssetPayoutRefusesOtherRailsAndPublicLegs(t *testing.T) {
	for name, change := range map[string]func(*transfer.TransferCircuit){
		"input asset":    func(c *transfer.TransferCircuit) { c.Inputs[0].Asset = big.NewInt(123) },
		"hidden owner":   func(c *transfer.TransferCircuit) { c.Hidden = 1 },
		"in proof owner": func(c *transfer.TransferCircuit) { c.InProof = 1 },
		"delegate":       func(c *transfer.TransferCircuit) { c.Delegate = 1 },
		"public asset":   func(c *transfer.TransferCircuit) { c.PublicAssets[0] = big.NewInt(123) },
		"public amount":  func(c *transfer.TransferCircuit) { c.PublicAmounts[0] = 1 },
		"public gross":   func(c *transfer.TransferCircuit) { c.PublicGross[0] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			built := ringtransfer.Signed(payoutShape).Build(t)
			change(built.Circuit)
			refused(t, built.Circuit, "assertSingleAssetPayout")
		})
	}
}

func TestSingleAssetPayoutPinsItsDisclosureFormat(t *testing.T) {
	for name, change := range map[string]func(*transfer.TransferCircuit){
		"standard format": func(c *transfer.TransferCircuit) { c.Layout = 0 },
		"data":            func(c *transfer.TransferCircuit) { c.Layout = audit.LayoutSingleAssetPayout | audit.LayoutHasData },
		"entry":           func(c *transfer.TransferCircuit) { c.Layout = audit.LayoutSingleAssetPayout | audit.LayoutEntry },
	} {
		t.Run(name, func(t *testing.T) {
			built := ringtransfer.Signed(payoutShape).Build(t)
			change(built.Circuit)
			refused(t, built.Circuit, "DecodeLayout")
		})
	}
	built := ringtransfer.Signed(payoutShape).Build(t)
	built.Circuit.OutputCount = 15
	refused(t, built.Circuit, "OpenSlots")
}

func TestSingleAssetPayoutBindsTheCommonMintCiphertext(t *testing.T) {
	built := ringtransfer.Signed(payoutShape).Build(t)
	statement := built.Values(t)
	statement.Head.Envelope = append([]byte(nil), statement.Head.Envelope...)
	statement.Head.Envelope[41] ^= 1
	built.Circuit.PublicInputHash = spptest.MustHashChain4(t, statement.Elements(t))
	refused(t, built.Circuit)
}

func TestSingleAssetPayoutAllowsSenderOwnedOutput(t *testing.T) {
	world := ringtransfer.Signed(payoutShape)
	senderOwnedOutput(t, &world)
	requireSolved(t, world.Build(t).Circuit)
}
