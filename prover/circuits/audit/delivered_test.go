package audit_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Each case changes one value of an honest transfer whose slot 0 is a ring output, slot 6 the exit and slot 7 a dummy.
func TestDeliveredAuditRefusals(t *testing.T) {
	c := compileDelivered(t, 8)
	slot := ringaudit.Recipient(t, 0, 0, 100)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.DeliveredAudit)
	}{
		{"ring output with a data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].Utxo.DataHash = big.NewInt(5) }},
		{"exit with a ring data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[6].Utxo.RingDataHash = big.NewInt(5) }},
		{"body encrypting another amount", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Body = ringprotocol.SealBody(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), d.Outputs[0].Utxo.Blinding, slot.Amount+1)
		}},
		{"ring output blinding of another slot", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Utxo.Blinding = d.Blinding(t, 1)
			d.Outputs[0].Body = ringprotocol.SealBody(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), d.Outputs[0].Utxo.Blinding, slot.Amount)
		}},
		{"exit blinding off the CRBS seed", func(d *ringaudit.DeliveredAudit) { d.Outputs[6].Utxo.Blinding = big.NewInt(0x5ec) }},
		{"owner key not the slot owner", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].OwnerKey[0] ^= 1 }},
		{"recipient key given as its high-bit alias", func(d *ringaudit.DeliveredAudit) {
			alias := slot
			alias.RecipientKey[31] |= 0x80
			d.Outputs[0] = d.NewRingOutput(t, alias)
		}},
		{"dense slots with an exit published", func(d *ringaudit.DeliveredAudit) { d.Layout.Exits = false }},
		{"SeedOut published without an exit", func(d *ringaudit.DeliveredAudit) {
			*d = ringaudit.DeliveredAuditOf(t, 8)
			d.Layout.Exits = true
		}},
		{"full openings flag on a delivered key", func(d *ringaudit.DeliveredAudit) { d.Layout.FullOpenings = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ringaudit.NewDeliveredAudit(t, 8)
			tc.mutate(&d)
			c.refuse(t, d.Circuit(t))
		})
	}

	// The program reads key escrow off the config, a disclosure without nullifier keys fails a statement that clears it.
	t.Run("nullifier keys omitted with the escrow bit clear", func(t *testing.T) {
		d := ringaudit.NewDeliveredAudit(t, 8)
		escrowed := d
		escrowed.Layout.Escrow = true
		c.refuseStatementOf(t, d.Circuit(t),
			ringaudit.DeliveredStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), escrowed.Disclosure(t)))
	})
}

// Every flag value solves at the smallest and a larger capacity, an exit-free transfer with dense slots and the reserved flag a delivered key ignores.
func TestDeliveredAuditSolvesEveryLayout(t *testing.T) {
	deliveredFlags := audit.LayoutExits | audit.LayoutEscrow | audit.LayoutReserved
	for _, capacity := range []int{2, 8} {
		c := compileDelivered(t, capacity)
		for value := range deliveredFlags + 1 {
			layout := ringaudit.Layout{Exits: value&audit.LayoutExits != 0, Escrow: value&audit.LayoutEscrow != 0, Reserved: value&audit.LayoutReserved != 0}
			t.Run(fmt.Sprintf("%d/%+v", capacity, layout), func(t *testing.T) {
				d := ringaudit.DeliveredAuditOf(t, capacity)
				if layout.Exits {
					d = ringaudit.NewDeliveredAudit(t, capacity)
				}
				d.Layout = layout
				c.requireSolved(t, d.Circuit(t))
			})
		}
	}
}

// Each case changes one value of an honest in-proof owner transfer spending two sender UTXOs.
func TestDeliveredSenderAuditRefusals(t *testing.T) {
	shape := audit.DeliveredSenderShapes[0]
	c := compileDeliveredSender(t, shape)
	other := ringtest.MustSolanaPkField(t, ringtest.Repeat(0xb2))
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *ringaudit.DeliveredSenderAudit, *audit.DeliveredSenderAuditCircuit)
	}{
		// The policy and the auditor would read a sender that owns no spent input.
		{"published sender other than the input owners", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *audit.DeliveredSenderAuditCircuit) {
			circuit.Sender = other
			circuit.PublicInputHash = spptest.MustHashChain4(t, ringaudit.DeliveredSenderStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), d.Disclosure(t), d.PrivateTxHash(t), other))
		}},
		// SPP's hidden owner would spend a note the sender does not own.
		{"second input of another owner", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *audit.DeliveredSenderAuditCircuit) {
			circuit.Inputs[1].OwnerPkHash = other
		}},
		// The statement would name no input SPP spends.
		{"no spent UTXO", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *audit.DeliveredSenderAuditCircuit) {
			d.Inputs[0], d.Inputs[1] = d.Inputs[2], d.Inputs[3]
			*circuit = *d.Circuit(t)
		}},
		// The audited inputs would be other than the ones SPP settles.
		{"private tx hash over another blinding", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *audit.DeliveredSenderAuditCircuit) {
			circuit.PrivateTxBlinding = big.NewInt(0x5b1e)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ringaudit.NewDeliveredSenderAudit(t, shape)
			circuit := d.Circuit(t)
			tc.mutate(t, &d, circuit)
			c.refuse(t, circuit)
		})
	}
}
