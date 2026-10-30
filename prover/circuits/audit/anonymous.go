// Proves that the auditor can see who sent an anonymous transfer and what notes
// they spent, while the chain sees neither.
//
// Read after audit/audit.go, audit/layout.go, shared/utxo.go. Read before
// prover/ring/ring.go.

package audit

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. Every output slot is published, every UTXO is a ring output or an exit and carries no data hash and no ring data.
// 3. A ring output's owner is the identity of the owner key the disclosure opens.
// 4. Every UTXO's amount lies below 2^64, the disclosure opens every UTXO's asset and amount and leaves a dummy slot zero.
// 5. Every exit discloses its full opening to the auditor, SeedOut opens the disclosure exactly when a UTXO exits.
// 6. Every spent UTXO lies below the published input count, ahead of every dummy, and belongs to the hidden sender.
// 7. A commitment key spends notes of the ring only and discloses spent UTXO 0's hash and the prefix of every other spent hash, an entry key opens every spent UTXO under one nullifier key with no data.
// 8. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 9. private_tx_hash reopens over the same slots, the sender commitment opens to the sender the inputs prove.
// 10. The sender is spent UTXO 0's owner on a commitment key and the owner of SenderKey on an entry key.

const (
	// InputPrefixLen is the byte width of a spent hash's prefix on a commitment key.
	InputPrefixLen = 16
	// InputPrefixBits bounds a prefix of a canonical hash, two of them pack below q.
	InputPrefixBits = 126
)

type AnonymousOutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
}

type AnonymousAuditCircuit struct {
	PublicInputHash frontend.Variable   `gnark:",public"`
	Shape           AnonymousAuditShape `gnark:"-"`
	AuditWires
	Outputs           []AnonymousOutputWires
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	// SenderKey is the hidden owner's Ed25519 key on an entry key, a commitment key carries none.
	SenderKey []frontend.Variable
	// InputCount equals the published nullifier count on an entry key and lies within one of it on a commitment key.
	InputCount frontend.Variable
	Inputs     []shared.UtxoWires
	// SenderCommitment is 0 on an audit-only transfer and Poseidon(CRSC, sender_pk_hash, PrivateTxBlinding) under a policy.
	SenderCommitment frontend.Variable
	// Payer, configured co-signer and withdrawal owner; absent optional parties are zero.
	PartyIdentities [3]frontend.Variable
}

type anonymousSlot struct {
	outputSlot
	// bytes is mask(ring, owner_key) ‖ be32(live * asset) ‖ u64be(live * amount), mirrored by ANONYMOUS_SLOT_BYTES in program-libs/interface/src/proof/disclosure.rs.
	bytes []frontend.Variable
}

type spentInputs struct {
	count ringgadget.Count
	// hashes are the private_tx_hash input hashes, zero off a UTXO.
	hashes []frontend.Variable
	// tail is the disclosure of the input slots, zero off a UTXO.
	tail countedTail
	// amounts are u64be(amount) of every input slot on an entry key, zero off a UTXO.
	amounts []frontend.Variable
}

func NewAnonymousAuditCircuit(shape AnonymousAuditShape) (*AnonymousAuditCircuit, error) {
	if !slices.Contains(AnonymousAuditShapes[:], shape) && !slices.Contains(AnonymousEntryShapes[:], shape) {
		return nil, fmt.Errorf("audit: unsupported anonymous audit shape %+v, want one of %v or %v", shape, AnonymousAuditShapes, AnonymousEntryShapes)
	}
	return &AnonymousAuditCircuit{
		Shape:     shape,
		Outputs:   make([]AnonymousOutputWires, shape.Outputs),
		SenderKey: make([]frontend.Variable, shape.senderKeyLen()),
		Inputs:    make([]shared.UtxoWires, shape.InputClass),
	}, nil
}

func (c *AnonymousAuditCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		shared.ValidateLength("audit", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("audit", "input", len(c.Inputs), c.Shape.InputClass),
		shared.ValidateLength("audit", "sender key byte", len(c.SenderKey), c.Shape.senderKeyLen()),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	// 1. The envelope seals tx_viewing_sk to the auditor and the layout flags fix the published fields.
	envelope := c.sealEnvelope(api, rc)
	layout := decodeLayout(api, c.Layout, LayoutExits|LayoutReserved, c.Shape.layout())
	senderPkHash := c.senderPkHash(api)
	shared.AssertAnonymousParties(api, senderPkHash, c.PartyIdentities)
	// 2. Every output slot opens its owner key, asset and amount to the auditor.
	slots := make([]outputSlot, len(c.Outputs))
	var hashes, outputHashes, nullifierPks, slotBytes []frontend.Variable
	for i, output := range c.Outputs {
		s := c.openSlot(api, rc, envelope, output, i)
		slots[i] = s.outputSlot
		hashes, outputHashes = append(hashes, s.Hash), append(outputHashes, api.Mul(s.Utxo, s.Hash))
		nullifierPks = append(nullifierPks, api.Mul(s.live, output.Output.NullifierPk))
		slotBytes = append(slotBytes, s.bytes...)
	}
	// 3. SeedOut opens the disclosure exactly when an exit needs it.
	layout.assertExits(api, slots)
	// 4. Every spent UTXO is the sender's and published.
	spent := c.spend(api, rc, senderPkHash)
	// 5. SPP's private transaction hash reopens over the same slots with no address input.
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, spent.hashes, outputHashes, nil, c.PrivateTxBlinding))
	// 6. The commitment is 0 on an audit-only transfer or opens to the sender the inputs prove, the policy proof reads it.
	commitment := shared.SenderCommitment(api, senderPkHash, c.PrivateTxBlinding)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: c.SenderCommitment, A: c.SenderCommitment, B: commitment})
	// 7. Only the holder of tx_viewing_sk opens the disclosure of every output and spent UTXO.
	statement := c.statement(api, envelope, gadget.HashChain4(api, hashes), c.disclosure(api, envelope, layout, nullifierPks, slotBytes, spent))
	// 8. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, statement)
	return nil
}

func (c *AnonymousAuditCircuit) senderPkHash(api frontend.API) frontend.Variable {
	if c.Shape.FullOpenings {
		return gadget.SolanaOwnerIdentity(api, [32]frontend.Variable(c.SenderKey))
	}
	return c.Inputs[0].OwnerPkHash
}

func (c *AnonymousAuditCircuit) openSlot(api frontend.API, rc frontend.Rangechecker, e auditEnvelope, o AnonymousOutputWires, i int) anonymousSlot {
	slot := openOutput(api, o.Output)
	c.assertBlinding(api, e, o.Output, slot, i)
	// 1. No UTXO carries ring data the auditor cannot open.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: o.Output.RingDataHash})
	// 2. The identity gadget bounds every owner key byte the disclosure packs.
	assertOwnerKey(api, slot, o.Output, o.OwnerKey)
	// 3. be32 is the one asset encoding below q, the decomposition bounds a live amount below 2^64.
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.live, o.Output.Asset))
	amount := ringgadget.UintBytesBE(api, api.Mul(slot.live, o.Output.Amount), 8)
	return anonymousSlot{outputSlot: slot, bytes: slices.Concat(masked(api, slot.ring, o.OwnerKey[:]), asset[:], amount)}
}

// spend proves every spent UTXO is the hidden sender's and lies below the published count.
func (c *AnonymousAuditCircuit) spend(api frontend.API, rc frontend.Rangechecker, senderPkHash frontend.Variable) spentInputs {
	// 1. The published field count pins the input count, up to one trailing dummy on a commitment key.
	spent := spentInputs{count: ringgadget.SelectCount(api, c.InputCount, 1, c.Shape.InputClass)}
	var openings [][]frontend.Variable
	previousUtxo := frontend.Variable(1)
	for i, input := range c.Inputs {
		// 2. Every spent UTXO lies below the count and is the hidden sender's.
		opened, hash := spentBySender(api, input, spent.count.Active[i], senderPkHash, i)
		spent.hashes = append(spent.hashes, hash)
		if !c.Shape.FullOpenings {
			// 3. A disclosed hash names a note of the ring, an audited output whose opening the auditor holds.
			abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.RingProgramID, B: c.RingProgramID})
		}
		if i > 0 {
			// 4. A UTXO follows only a UTXO as in SPP, so spent UTXO k owns nullifier k.
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: api.Sub(1, previousUtxo)})
		}
		previousUtxo = opened.Utxo
		if !c.Shape.FullOpenings {
			continue
		}
		// 5. The auditor rebuilds an entry input from its opening, under input 0's nullifier key and with no data.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.NullifierPk, B: c.Inputs[0].NullifierPk})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.DataHash})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.RingDataHash})
		spent.amounts = append(spent.amounts, ringgadget.UintBytesBE(api, api.Mul(opened.Utxo, input.Amount), 8)...)
		openings = append(openings, []frontend.Variable{api.Mul(opened.Utxo, input.Asset), api.Mul(opened.Utxo, input.Blinding)})
	}
	if c.Shape.FullOpenings {
		spent.tail = uniformTail(openings)
		return spent
	}
	// 5. Input 0 opens by its hash and names the sender, every other spent UTXO matches among the sender's notes by its prefix.
	spent.tail = countedTail{fields: commitmentTail(api, rc, spent.hashes), published: func(n int) int { return 1 + n/2 }}
	return spent
}

// disclosure is the anonymous disclosure the layout selects, mirrored by DisclosureLayout::Anonymous in program-libs/interface/src/proof/disclosure.rs.
//
//	SeedOut under LayoutExits, then on a commitment key
//	nullifier_pk per output, pack_disclosure(slot bytes per output), hash of input 0, prefix pairs of the other published inputs
//	and on an entry key
//	sender nullifier_pk, nullifier_pk per output, pack_disclosure(sender_key ‖ slot bytes per output),
//	pack_disclosure(u64be(amount) per input slot), asset and blinding per published input
func (c *AnonymousAuditCircuit) disclosure(api frontend.API, e auditEnvelope, layout auditLayout, nullifierPks, slotBytes []frontend.Variable, spent spentInputs) frontend.Variable {
	// SolanaOwnerIdentity bounds the sender key bytes, openSlot the slot bytes.
	head := slices.Concat(nullifierPks, shared.PackDisclosure(api, slices.Concat(c.SenderKey, slotBytes)))
	if c.Shape.FullOpenings {
		// Input 0 is a UTXO, its key is the key of every spent UTXO.
		head = slices.Concat([]frontend.Variable{c.Inputs[0].NullifierPk}, head, shared.PackDisclosure(api, spent.amounts))
	}
	return e.disclose(api, layout.choices(api, LayoutExits), func(choice layoutChoice) disclosureLayout {
		return choice.counted(api, slices.Concat(e.seedOut(choice), head), spent.tail, spent.count)
	})
}

// statement is the anonymous audit preimage, mirrored by AuditStatement::elements under AuditKind::Anonymous in program-libs/interface/src/proof/statement.rs.
//
//	head ‖ output_chain, disclosure_chain, private_tx_hash, sender_commitment, party0, party1, party2
func (c *AnonymousAuditCircuit) statement(api frontend.API, e auditEnvelope, outputChain, disclosureChain frontend.Variable) frontend.Variable {
	return gadget.HashChain4(api, append(e.statementHead(c.AuditWires),
		outputChain, disclosureChain, c.PrivateTxHash, c.SenderCommitment,
		c.PartyIdentities[0], c.PartyIdentities[1], c.PartyIdentities[2],
	))
}

// spentBySender holds slot i to the sender and to live, slot 0 a UTXO, and returns its spent hash, zero off a UTXO.
func spentBySender(api frontend.API, input shared.UtxoWires, live, sender frontend.Variable, i int) (shared.OpenedUtxo, frontend.Variable) {
	opened := input.Open(api)
	// An input at or past the count is no UTXO, so no spent UTXO escapes the published inputs.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, live), V: opened.Utxo})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.OwnerPkHash, B: sender})
	if i == 0 {
		// Input 0 is a UTXO, so the sender owns a real spent UTXO.
		api.AssertIsEqual(opened.Utxo, 1)
	}
	return opened, api.Mul(opened.Utxo, opened.Hash)
}

// commitmentTail is hashes[0] in full, then the prefixes of the other hashes two per field, the last half zero for an odd prefix count.
func commitmentTail(api frontend.API, rc frontend.Rangechecker, hashes []frontend.Variable) []frontend.Variable {
	prefixes := make([]frontend.Variable, 0, len(hashes))
	for _, hash := range hashes[1:] {
		// The canonical split leaves one prefix per hash, the prefix of hash + q would name another note.
		prefix, _ := ringgadget.SplitField(api, rc, hash, 8*(32-InputPrefixLen))
		prefixes = append(prefixes, prefix)
	}
	shift := new(big.Int).Lsh(big.NewInt(1), InputPrefixBits)
	tail := []frontend.Variable{hashes[0]}
	for k := 0; k < len(prefixes); k += 2 {
		second := frontend.Variable(0)
		if k+1 < len(prefixes) {
			second = prefixes[k+1]
		}
		// Both prefixes lie below 2^InputPrefixBits, the pair packs without a wrap and decodes to one pair.
		tail = append(tail, api.Add(api.Mul(prefixes[k], shift), second))
	}
	return tail
}
