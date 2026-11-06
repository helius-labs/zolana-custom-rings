package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Transfer is the part of a ring transfer every audit statement opens with.
type Transfer struct {
	Keys           Keys
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	Salt           [16]byte
	// Seed is CRBS(tx_viewing_sk, salt), SPP's BlindingSeed.
	Seed    *big.Int
	SeedOut *big.Int
}

// newTransfer is the fixture transfer of the default keys in the ring of program address 0x90..90.
func newTransfer(t testing.TB) Transfer {
	t.Helper()
	ringProgram := ringtest.Repeat(0x90)
	tr := Transfer{
		FirstNullifier: big.NewInt(0x1f1f),
		RingProgramID:  ringtest.HashBytes(t, ringProgram[:]),
	}
	for i := range tr.Salt {
		tr.Salt[i] = 0xa0 + byte(i)
	}
	return tr.WithKeys(t, DefaultKeys(t))
}

// WithKeys rederives Seed and SeedOut, the CRBS blinding seed follows tx_viewing_sk.
func (tr Transfer) WithKeys(t testing.TB, keys Keys) Transfer {
	t.Helper()
	tr.Keys = keys
	tr.Seed = ringprotocol.BlindingSeed(t, tr.Keys.txViewingSk, tr.Salt)
	seedOut, err := protocol.OutputBlindingSeed(tr.FirstNullifier, tr.Seed)
	tr.SeedOut = spptest.MustHash(t, seedOut, err)
	return tr
}

// PrivateTxBlinding is the TXPB blinding SPP derives from Seed, the last preimage element of private_tx_hash.
func (tr Transfer) PrivateTxBlinding(t testing.TB) *big.Int {
	t.Helper()
	blinding, err := protocol.PrivateTxBlinding(tr.FirstNullifier, tr.Seed)
	return spptest.MustHash(t, blinding, err)
}

// WithUnrelatedKey seals under a key whose seed differs from the one the slots were built over.
func (tr Transfer) WithUnrelatedKey(t testing.TB) Transfer {
	t.Helper()
	return tr.WithKeys(t, tr.Keys.WithRawTxScalar(t, ringprotocol.Clamped(ringtest.Scalar(0x44))))
}

// Blinding is the TXOB blinding SPP derives for slot i of the transfer.
func (tr Transfer) Blinding(t testing.TB, i int) *big.Int {
	t.Helper()
	return ringprotocol.OutputBlinding(t, tr.FirstNullifier, tr.SeedOut, i)
}

// Wires are the audit wires of the transfer under layout.
func (tr Transfer) Wires(layout int64) audit.AuditWires {
	w := audit.AuditWires{FirstNullifier: tr.FirstNullifier, RingProgramID: tr.RingProgramID, Layout: layout}
	ringtest.SetBytes(w.TxViewingSk[:], tr.Keys.txViewingSk[:])
	ringtest.SetBytes(w.AuditorPk[:], tr.Keys.auditorPk[:])
	ringtest.SetBytes(w.Salt[:], tr.Salt[:])
	return w
}

// NewRingOutput pays slot's recipient under the TXOB blinding of its index, with no data.
func (tr Transfer) NewRingOutput(t testing.TB, slot DeliverySlot) Slot {
	t.Helper()
	return Slot{
		Utxo: Utxo{
			Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, slot.OwnerKey),
			NullifierPk: slot.NullifierPk, Asset: ringtest.AssetField(t, slot.AssetAddress), Amount: slot.Amount,
			Blinding: tr.Blinding(t, slot.Index), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: tr.RingProgramID,
		},
		OwnerKey: slot.OwnerKey, Mint: slot.AssetAddress,
	}
}

// ExitOwnerKey owns every fixture exit.
var ExitOwnerKey = ringtest.Repeat(0xe5)

// NewExit leaves the ring for the default ring, its owner published by SPP.
func (tr Transfer) NewExit(t testing.TB, i int) Slot {
	t.Helper()
	return Slot{
		Utxo: Utxo{
			Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, ExitOwnerKey),
			NullifierPk: spptest.MustNullifierPk(t, big.NewInt(23)), Asset: ringtest.AssetField(t, [32]byte{}), Amount: 40,
			Blinding: tr.Blinding(t, i), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		},
		OwnerKey: ExitOwnerKey,
	}
}

// NewDummy pads a slot, every record byte reads zero.
func (tr Transfer) NewDummy(t testing.TB, i int) Slot {
	t.Helper()
	return Slot{Utxo: Dummy(OutputTreeID, tr.Blinding(t, i))}
}

// DeliverySlot names the recipient and the opening of one ring output.
type DeliverySlot struct {
	Index        int
	OwnerKey     [32]byte
	NullifierPk  *big.Int
	AssetAddress [32]byte
	Amount       uint64
}

// Recipient is fixture recipient n, every key derived from n.
func Recipient(t testing.TB, n byte, index int, amount uint64) DeliverySlot {
	t.Helper()
	return DeliverySlot{
		Index:        index,
		OwnerKey:     ringtest.Repeat(0xb2 + n),
		NullifierPk:  spptest.MustNullifierPk(t, big.NewInt(20+int64(n))),
		AssetAddress: ringtest.Repeat(0x0a),
		Amount:       amount,
	}
}

// OutputTreeID is the fixture tree every output is appended to.
const OutputTreeID = 9
