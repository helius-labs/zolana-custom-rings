package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
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
	SeedOut        *big.Int
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

// WithKeys rederives SeedOut, the CRBS blinding seed follows tx_viewing_sk.
func (tr Transfer) WithKeys(t testing.TB, keys Keys) Transfer {
	t.Helper()
	tr.Keys = keys
	seedOut, err := protocol.OutputBlindingSeed(tr.FirstNullifier, ringprotocol.BlindingSeed(t, tr.Keys.txViewingSk, tr.Salt))
	tr.SeedOut = spptest.MustHash(t, seedOut, err)
	return tr
}

// Blinding is the TXOB blinding SPP derives for slot i of the transfer.
func (tr Transfer) Blinding(t testing.TB, i int) *big.Int {
	t.Helper()
	return ringprotocol.OutputBlinding(t, tr.FirstNullifier, tr.SeedOut, i)
}

// DeliveredSlotSecret is the CRDS secret of slot i keyed to the recipient u.
func (tr Transfer) DeliveredSlotSecret(t testing.TB, u [32]byte, i int) *big.Int {
	t.Helper()
	return ringprotocol.DeliveredSlotSecret(t, tr.Keys.txViewingSk, u, tr.Salt, i, tr.FirstNullifier)
}

// AuditHead is the statement head the program builds for the transfer under layout.
func (tr Transfer) AuditHead(t testing.TB, layout Layout) AuditHead {
	t.Helper()
	head := tr.Keys.AuditHead(t, tr.FirstNullifier, tr.RingProgramID, tr.Salt)
	head.Layout = layout.Value()
	return head
}

// seedOut is SeedOut when the layout discloses it.
func (tr Transfer) seedOut(layout Layout) []*big.Int {
	if layout.Exits {
		return []*big.Int{tr.SeedOut}
	}
	return nil
}

func (tr Transfer) wires(layout Layout) audit.AuditWires {
	w := audit.AuditWires{FirstNullifier: tr.FirstNullifier, RingProgramID: tr.RingProgramID, Layout: layout.Value()}
	ringtest.SetBytes(w.TxViewingSk[:], tr.Keys.txViewingSk[:])
	ringtest.SetBytes(w.EphSk[:], tr.Keys.ephSk[:])
	ringtest.SetBytes(w.AuditorPk[:], tr.Keys.auditorPk[:])
	ringtest.SetBytes(w.Salt[:], tr.Salt[:])
	return w
}

// DeliveredOutput is one delivered slot, the host twin of audit.DeliveryWires.
type DeliveredOutput struct {
	Utxo         Utxo
	RecipientKey [32]byte
	OwnerKey     [32]byte
	Body         [shared.BodyLen]byte
}

// NewRingOutput delivers slot to its recipient key.
func (tr Transfer) NewRingOutput(t testing.TB, slot DeliverySlot) DeliveredOutput {
	t.Helper()
	utxo := tr.ringUtxo(t, slot)
	return DeliveredOutput{
		Utxo:         utxo,
		RecipientKey: slot.RecipientKey,
		OwnerKey:     slot.OwnerKey,
		Body:         ringprotocol.SealBody(t, tr.DeliveredSlotSecret(t, slot.RecipientKey, slot.Index), utxo.Blinding, slot.Amount),
	}
}

// ringUtxo is slot's ring output under the TXOB blinding of its index, with no ring data.
func (tr Transfer) ringUtxo(t testing.TB, slot DeliverySlot) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, slot.OwnerKey),
		NullifierPk: slot.NullifierPk, Asset: ringtest.AssetField(t, slot.AssetAddress), Amount: slot.Amount,
		Blinding: tr.Blinding(t, slot.Index), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: tr.RingProgramID,
	}
}

// ExitOwnerKey owns every fixture exit.
var ExitOwnerKey = ringtest.Repeat(0xe5)

// NewExit leaves the ring for the default ring, its owner published by SPP.
func (tr Transfer) NewExit(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	return DeliveredOutput{Utxo: Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, ExitOwnerKey),
		NullifierPk: spptest.MustNullifierPk(t, big.NewInt(23)), Asset: ringtest.AssetField(t, [32]byte{}), Amount: 40,
		Blinding: tr.Blinding(t, i), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}}
}

// newDummy pads a slot with arbitrary key and body bytes.
func (tr Transfer) newDummy(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	d := DeliveredOutput{Utxo: Dummy(OutputTreeID, tr.Blinding(t, i)), RecipientKey: ringtest.Repeat(0xd1 + byte(i))}
	for j := range d.Body {
		d.Body[j] = 0xd0 + byte(j)
	}
	return d
}

// DeliverySlot names the recipient and the opening of one ring output.
type DeliverySlot struct {
	Index        int
	RecipientKey [32]byte
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
		RecipientKey: ringprotocol.XPublicKey(t, ringtest.Scalar(0x55+n)),
		OwnerKey:     ringtest.Repeat(0xb2 + n),
		NullifierPk:  spptest.MustNullifierPk(t, big.NewInt(20+int64(n))),
		AssetAddress: ringtest.Repeat(0x0a),
		Amount:       amount,
	}
}

// OutputTreeID is the fixture tree every output is appended to.
const OutputTreeID = 9

func (o DeliveredOutput) wires() audit.DeliveryWires {
	w := audit.DeliveryWires{Output: o.Utxo.Wires()}
	ringtest.SetBytes(w.RecipientKey[:], o.RecipientKey[:])
	ringtest.SetBytes(w.OwnerKey[:], o.OwnerKey[:])
	ringtest.SetBytes(w.Body[:], o.Body[:])
	return w
}

func (o DeliveredOutput) statementOutput(t testing.TB) StatementOutput {
	t.Helper()
	return StatementOutput{Hash: o.Utxo.Hash(t), Exit: o.Utxo.isExit(), U: o.RecipientKey, Body: o.Body[:]}
}

// slotBytes mirrors audit slotDisclosure.
func (o DeliveredOutput) slotBytes(t testing.TB, ringTail []byte) []byte {
	t.Helper()
	out := make([]byte, 32+len(ringTail))
	switch {
	case o.Utxo.isRingOutput():
		copy(out, slices.Concat(o.OwnerKey[:], ringTail))
	case o.Utxo.isExit():
		asset := spptest.MustFieldBytes(t, o.Utxo.Asset)
		copy(out, binary.BigEndian.AppendUint64(asset[:], o.Utxo.Amount))
	}
	return out
}
