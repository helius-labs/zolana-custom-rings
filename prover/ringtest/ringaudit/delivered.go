package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// DeliveredAudit is a delivered confidential audit witness with every derived value explicit.
type DeliveredAudit struct {
	Transfer
	Outputs []DeliveredOutput
	Layout  Layout
}

// NewDeliveredAudit fills capacity slots with ring outputs, then one exit and one dummy.
func NewDeliveredAudit(t testing.TB, capacity int) DeliveredAudit {
	t.Helper()
	return DeliveredAuditOf(t, capacity, capacity-2)
}

// DeliveredAuditOf delivers ring outputs to every slot but the exits and a last dummy.
func DeliveredAuditOf(t testing.TB, capacity int, exits ...int) DeliveredAudit {
	t.Helper()
	d := DeliveredAudit{Transfer: newTransfer(t), Outputs: make([]DeliveredOutput, capacity)}
	for i := range capacity {
		switch {
		case i == capacity-1:
			d.Outputs[i] = d.newDummy(t, i)
		case slices.Contains(exits, i):
			d.Outputs[i] = d.NewExit(t, i)
		default:
			d.Outputs[i] = d.NewConfidentialOutput(t, i)
		}
	}
	d.Layout.Exits = len(exits) > 0
	return d
}

// NewConfidentialOutput delivers slot i to fixture recipient i mod 3.
func (d DeliveredAudit) NewConfidentialOutput(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	return d.NewRingOutput(t, Recipient(t, byte(i%3), i, 100+uint64(i)))
}

func (d DeliveredAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return DeliveredStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), d.Disclosure(t))
}

func (d DeliveredAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(d.Outputs))
	for i, output := range d.Outputs {
		outputs[i] = output.statementOutput(t)
	}
	return outputs
}

// Disclosure is the enciphered delivered disclosure under d.Layout, slots without their 8 tail bytes on an exit-free transfer.
func (d DeliveredAudit) Disclosure(t testing.TB) []*big.Int {
	t.Helper()
	var nullifierPks []*big.Int
	var slotBytes []byte
	for _, output := range d.Outputs {
		if !d.Layout.Escrow {
			nullifierPks = append(nullifierPks, live(output.Utxo, output.Utxo.NullifierPk))
		}
		bytes := output.slotBytes(t, make([]byte, 8))
		if !d.Layout.Exits {
			bytes = bytes[:32]
		}
		slotBytes = append(slotBytes, bytes...)
	}
	return d.Keys.Disclose(t, d.Salt, slices.Concat(d.seedOut(d.Layout), nullifierPks, ringprotocol.PackDisclosure(slotBytes)))
}

// Circuit is the audit assignment proving the statement.
func (d DeliveredAudit) Circuit(t testing.TB) *audit.DeliveredAuditCircuit {
	t.Helper()
	c, err := audit.NewDeliveredAuditCircuit(len(d.Outputs))
	if err != nil {
		t.Fatal(err)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, d.Statement(t))
	c.AuditWires = d.wires(d.Layout)
	for i, output := range d.Outputs {
		c.Outputs[i] = output.wires()
	}
	return c
}

// DeliveredSenderAudit is a delivered audit of the in-proof owner rail spending two inputs of the sender.
type DeliveredSenderAudit struct {
	DeliveredAudit
	Shape             audit.DeliveredSenderShape
	SenderKey         [32]byte
	PrivateTxBlinding *big.Int
	Inputs            []Utxo
}

func NewDeliveredSenderAudit(t testing.TB, shape audit.DeliveredSenderShape) DeliveredSenderAudit {
	t.Helper()
	d := DeliveredSenderAudit{
		DeliveredAudit:    NewDeliveredAudit(t, shape.Outputs),
		Shape:             shape,
		SenderKey:         ringtest.Repeat(0xa1),
		PrivateTxBlinding: big.NewInt(0x5b1d),
		Inputs:            make([]Utxo, shape.Inputs),
	}
	for i := range d.Inputs {
		d.Inputs[i] = spareInput(i)
	}
	nullifierPk := spptest.MustNullifierPk(t, big.NewInt(7))
	d.Inputs[0] = spentUtxo(t, d.Sender(t), nullifierPk, d.RingProgramID, 100, 51)
	d.Inputs[1] = spentUtxo(t, d.Sender(t), nullifierPk, d.RingProgramID, 60, 52)
	return d
}

// Sender is the owner identity of SenderKey.
func (d DeliveredSenderAudit) Sender(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, d.SenderKey)
}

// PrivateTxHash is SPP's private transaction hash over the slots, with no address input.
func (d DeliveredSenderAudit) PrivateTxHash(t testing.TB) *big.Int {
	t.Helper()
	outputs := make([]Utxo, len(d.Outputs))
	for i, output := range d.Outputs {
		outputs[i] = output.Utxo
	}
	return spptest.MustPrivateTxHash(t, spentHashes(t, d.Inputs), spentHashes(t, outputs), nil, d.PrivateTxBlinding)
}

func (d DeliveredSenderAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return DeliveredSenderStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), d.Disclosure(t), d.PrivateTxHash(t), d.Sender(t))
}

func (d DeliveredSenderAudit) Circuit(t testing.TB) *audit.DeliveredSenderAuditCircuit {
	t.Helper()
	c, err := audit.NewDeliveredSenderAuditCircuit(d.Shape)
	if err != nil {
		t.Fatal(err)
	}
	c.DeliveredAuditCircuit = *d.DeliveredAudit.Circuit(t)
	c.PublicInputHash = spptest.MustHashChain4(t, d.Statement(t))
	c.Sender = d.Sender(t)
	c.PrivateTxHash = d.PrivateTxHash(t)
	c.PrivateTxBlinding = d.PrivateTxBlinding
	for i, input := range d.Inputs {
		c.Inputs[i] = input.Wires()
	}
	return c
}
