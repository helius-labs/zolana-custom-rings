package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

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

// openOutput classifies every UTXO of an output slot as a ring output or an exit.
func openOutput(api frontend.API, o shared.UtxoWires) outputSlot {
	opened := o.Open(api)
	slot := classify(api, o, opened, opened.Utxo)
	// No UTXO carries a data hash, the recipient never learns one.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: o.DataHash})
	return slot
}

func assertOwnerKey(api frontend.API, slot outputSlot, o shared.UtxoWires, key [32]frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.ring, A: o.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, key)})
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
	amount := uintBytes(api, d.Output.Amount, 8)
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
