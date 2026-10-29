package audit

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
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

type DeliveryWires struct {
	Output shared.UtxoWires
	// RecipientKey is the X25519 u the body is sealed to.
	RecipientKey [32]frontend.Variable
	OwnerKey     [32]frontend.Variable
	Body         [shared.BodyLen]frontend.Variable
}

type delivery struct {
	outputSlot
	// bodyHash is hash_bytes(body), zero on an exit.
	bodyHash frontend.Variable
	amount   []frontend.Variable
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

func recipientKey(api frontend.API, slot outputSlot, key [32]frontend.Variable) [32]frontend.Variable {
	var u [32]frontend.Variable
	for j := range u {
		// A slot without a recipient agrees with the base point, the ladder stays satisfiable on every slot.
		u[j] = api.Select(slot.ring, key[j], basepointByte(j))
	}
	return u
}

// deliver proves a ring output's body opens to its committed blinding and amount for the holder of u.
func (w AuditWires) deliver(api frontend.API, rc frontend.Rangechecker, e auditEnvelope, d DeliveryWires, slot outputSlot, u [32]frontend.Variable, i int) delivery {
	// 1. One encoding per recipient key, an alias would key the slot secret and the owner tag to bytes the recipient never derives.
	agreement := shared.AgreeCanonical(api, e.txViewingSk, u)
	// 2. be32 is the one encoding below q, the recipient decodes the committed blinding.
	blinding := ringgadget.FieldToBytesBEWith(api, rc, d.Output.Blinding)
	// 3. The agreement's ECDH bounds every byte of u and returns canonical agreement bytes.
	recipient := [2]frontend.Variable(shared.PackBounded(api, shared.Tagged(u)))
	// 4. The slot secret binds the agreement, both keys, the salt, the slot and n0, no two slots share a keystream.
	secret := shared.DeliveredSlot{
		Agreement:      [2]frontend.Variable(shared.PackBounded(api, agreement[:])),
		TxPk:           e.txPk,
		Recipient:      recipient,
		Salt:           e.salt,
		OutputIndex:    i,
		FirstNullifier: w.FirstNullifier,
	}.Secret(api)
	key, nonce := shared.AuditStreamKeySchedule(api, secret)
	// 5. A ring output's body is the encryption of its opening, the recipient and the auditor decrypt the same bytes.
	amount := ringgadget.UintBytesBE(api, d.Output.Amount, 8)
	for j, b := range aes.NewCipher(api, key).CTREncrypt(nonce, slices.Concat(blinding[:], amount)) {
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.ring, A: d.Body[j], B: b})
	}
	// 6. A ring output's owner is the identity of the key the disclosure names.
	assertOwnerKey(api, slot, d.Output, d.OwnerKey)
	return delivery{
		outputSlot: slot,
		// A ring output's body bytes are the cipher's bounded bytes, a dummy's random body binds nothing else.
		bodyHash: api.Mul(api.Sub(1, slot.exit), gadget.HashBoundedBytes(api, d.Body[:])),
		amount:   amount,
	}
}

// slotDisclosure is owner_key ‖ ringTail on a ring output, asset ‖ u64be(amount) zero padded to its width on an exit.
func slotDisclosure(api frontend.API, rc frontend.Rangechecker, o DeliveryWires, d delivery, ringTail []frontend.Variable) []frontend.Variable {
	bytes := slices.Concat(masked(api, d.ring, o.OwnerKey[:]), masked(api, d.ring, ringTail))
	// An exit discloses its asset as the one 32-byte encoding below q.
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(d.exit, o.Output.Asset))
	exit := slices.Concat(asset[:], masked(api, d.exit, d.amount))
	for j, b := range exit {
		// A ring output and an exit exclude each other, so every byte holds one layout.
		bytes[j] = api.Add(bytes[j], b)
	}
	return bytes
}

func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
