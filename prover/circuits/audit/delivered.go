package audit

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. The output chain covers every slot, a delivered transfer publishes no prefix.
// 3. Every UTXO is a ring output or an exit and carries no output data.
// 4. A ring output's body encrypts be32(blinding) ‖ u64be(amount) under its CRDS slot secret for the holder of its canonical recipient key and the auditor.
// 5. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 6. The disclosure opens a ring output's owner key and every UTXO's nullifier key, LayoutEscrow leaves the keys to the policy's escrow records.
// 7. Every exit discloses its full opening, SeedOut and slots of 40 bytes appear exactly when a UTXO exits.

type DeliveredAuditCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Capacity        int               `gnark:"-"`
	AuditWires
	Outputs []DeliveryWires
}

func NewDeliveredAuditCircuit(capacity int) (*DeliveredAuditCircuit, error) {
	if !slices.Contains(DeliveredAuditCapacities[:], capacity) {
		return nil, fmt.Errorf("audit: unsupported delivered audit capacity %d, want one of %v", capacity, DeliveredAuditCapacities)
	}
	return &DeliveredAuditCircuit{Capacity: capacity, Outputs: make([]DeliveryWires, capacity)}, nil
}

func (c *DeliveredAuditCircuit) Define(api frontend.API) error {
	if err := transaction.ValidateLength("output", len(c.Outputs), c.Capacity); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	// 1. The envelope seals tx_viewing_sk to the auditor and the layout flags fix the published fields.
	envelope := c.sealEnvelope(api, rc)
	layout := decodeLayout(api, c.Layout, LayoutExits|LayoutEscrow|LayoutReserved, 0)
	var hashes, bodyHashes, recipientKeys, nullifierPks []frontend.Variable
	slots := make([]outputSlot, len(c.Outputs))
	slotBytes := make([][]frontend.Variable, len(c.Outputs))
	for i, output := range c.Outputs {
		// 2. Every ring output body opens for the holder of its published recipient key.
		slots[i] = openOutput(api, output.Output)
		d := c.deliver(api, rc, envelope, output, slots[i], recipientKey(api, slots[i], output.RecipientKey), i)
		// 3. The auditor rebuilds every blinding from tx_viewing_sk, no UTXO carries ring data.
		c.assertBlinding(api, envelope, output.Output, slots[i], i)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slots[i].Utxo, V: output.Output.RingDataHash})
		hashes, bodyHashes = append(hashes, d.Hash), append(bodyHashes, d.bodyHash)
		// 4. The program rebuilds the owner tag from the published key, a ring output's key bytes are the ones ECDH bounds.
		key, notExit := shared.PackBounded(api, output.RecipientKey[:]), api.Sub(1, slots[i].exit)
		recipientKeys = append(recipientKeys, api.Mul(notExit, key[0]), api.Mul(notExit, key[1]))
		nullifierPks = append(nullifierPks, api.Mul(slots[i].live, output.Output.NullifierPk))
		slotBytes[i] = slotDisclosure(api, rc, output, d, shared.Zeros(8))
	}
	// 5. SeedOut and the exit bytes of every slot appear exactly when a UTXO exits.
	layout.assertExits(api, slots)
	// 6. Only the holder of tx_viewing_sk opens the disclosure of every slot.
	statement := c.statement(api, envelope,
		gadget.HashChain4(api, hashes),
		gadget.HashChain4(api, bodyHashes),
		c.disclosure(api, envelope, layout, nullifierPks, slotBytes),
		gadget.HashChain4(api, recipientKeys),
	)
	// 7. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, statement)
	return nil
}

// disclosure is the delivered disclosure the layout flags select, mirrored by DisclosureLayout::Delivered in program-libs/interface/src/proof/disclosure.rs.
//
//	SeedOut under LayoutExits, nullifier_pk per slot unless LayoutEscrow,
//	pack_disclosure(slot bytes per slot), 40 bytes under LayoutExits and the first 32 otherwise
func (c *DeliveredAuditCircuit) disclosure(api frontend.API, e auditEnvelope, layout auditLayout, nullifierPks []frontend.Variable, slotBytes [][]frontend.Variable) frontend.Variable {
	var wideBytes, denseBytes []frontend.Variable
	for _, bytes := range slotBytes {
		// Without an exit every dropped tail byte is zero, a ring output's tail and a dummy slot alike.
		wideBytes, denseBytes = append(wideBytes, bytes...), append(denseBytes, bytes[:32]...)
	}
	wide, dense := shared.PackDisclosure(api, wideBytes), shared.PackDisclosure(api, denseBytes)
	return e.disclose(api, layout.choices(api, LayoutExits|LayoutEscrow), func(choice layoutChoice) disclosureLayout {
		keys, slots := nullifierPks, dense
		if choice.has(LayoutEscrow) {
			keys = nil
		}
		if choice.has(LayoutExits) {
			slots = wide
		}
		return choice.fixed(slices.Concat(e.seedOut(choice), keys, slots))
	})
}

// statement is the delivered audit preimage, mirrored by AuditStatement::elements under AuditKind::Delivered in program-libs/interface/src/proof/statement.rs.
//
//	head ‖ output_chain, body_chain, disclosure_chain, recipient_key_chain
func (c *DeliveredAuditCircuit) statement(api frontend.API, e auditEnvelope, outputChain, bodyChain, disclosureChain, recipientKeyChain frontend.Variable) frontend.Variable {
	return gadget.HashChain4(api, append(e.statementHead(c.AuditWires), outputChain, bodyChain, disclosureChain, recipientKeyChain))
}
