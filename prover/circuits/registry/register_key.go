// Proves that the auditor can recover the secret behind the nullifier key an owner
// enrolls and the salt behind its list tag. SPP spends a note under Poseidon(secret)
// and the secret never leaves the owner. A ring owes its auditor the owner's spends,
// each nullifier derives from that secret, and owes its private lists one fixed record
// key per owner, that key derives from the salt. Storage `Enroll` verifies the proof
// in the same instruction on the owner's first enrollment, the one proof that seals
// those two values. Without it an owner could enroll a key whose nullifiers no auditor
// can compute, or a salt a private block never reaches.
//
// Read after shared/derivation.go, shared/envelope.go. Read before registry/tracking.go,
// registry/apply_enrollments.go, policy/subjects.go, prover/ring/ring.go.

package registry

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The nullifier key is Poseidon of the nonzero 31 byte secret, the same hash nullifierPkGadget in zolana/prover/server/circuits/spp_transaction/shared/inputs.go takes a spent note's key from.
// 2. The list tag is Poseidon(CRPT, salt) of the nonzero 31 byte salt.
// 3. The ciphertext seals exactly those two values, 32 bytes each with a zero lead, to AuditorPk under CRING/nfk, so the auditor recovers both behind the enrolled key and tag.
// 4. The statement binds the ring, the member, the key, the list tag, both tagged envelope keys and the ciphertext hash.
//
// The circuit holds neither value to a wallet derivation, a wallet that seals another secret harms itself alone. It does not prove EphSk fresh, see shared/envelope.go.

type RegisterKeyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RingID          frontend.Variable
	Member          frontend.Variable
	NullifierSecret [32]frontend.Variable
	ListSalt        [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *RegisterKeyCircuit) Define(api frontend.API) error {
	// 1. A zero lead byte keeps the secret below q, the envelope's cipher bounds the other 31 bytes.
	// Below 2^248 the packed bytes are the integer itself, the sealed bytes, the key and SPP's nullifier secret name one value with no alias secret + q.
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	secret := shared.PackBounded(api, c.NullifierSecret[1:])[0]
	// Poseidon(0) is the zero key, never enrolled.
	// A transfer or deposit output under that key carries no secret and proves its owner absent from the named tracking root, a merge output reads no row, see ZeroNullifierPk in shared/derivation.go.
	api.AssertIsDifferent(secret, 0)
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secret})
	// 2. A salt the envelope does not hold would leave the owner off the auditor's list writes.
	// The tag commits to the owner's one salt. policy/subjects.go forces a present row's salt to open the tag, and so forces the key ListKey(owner, salt) a private entry sits under, with no choice left to the prover.
	// A tag cannot move for that reason. A new salt would name a key with no entry, and a privately blocked owner would read as unlisted. `Enroll` verifies the proof only at the first enrollment, a later `Enroll` carries no proof and TrackingAuthorization::rotate refuses a changed key, tag, ephemeral key or ciphertext, and ApplyEnrollmentsCircuit holds the leaf's key, tag and ciphertext hash. No instruction closes the account and no write removes the leaf, a present row stays present under every later root.
	api.AssertIsEqual(c.ListSalt[0], 0)
	salt := shared.PackBounded(api, c.ListSalt[1:])[0]
	// ListKey(owner, 0) is the owner's public key, a zero salt would put the private entries on the public record. The circuit refuses only zero, the wallet's derivation supplies the entropy.
	api.AssertIsDifferent(salt, 0)
	listTag := shared.ListTag(api, salt)
	// The cipher under CRING/nfk bounds every ciphertext byte.
	// The key and the tag hash the same wires the cipher seals, the auditor reads the values behind them. The cipher's byte tables also bound the plaintext bytes both packings above rely on.
	sealed := shared.Envelope{Plaintext: slices.Concat(c.NullifierSecret[:], c.ListSalt[:]), EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.NfKeyEncInfo}.SealStream(api)
	// 3. The statement binds the ring, member and auditor key the program supplies, and the instruction's envelope.
	// RingID and Member enter only the statement. The program computes the member from the signer and reads the ring and the auditor key from the tracking registry, a proof made for another ring, owner or auditor fails verification.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, nullifierPk, listTag, sealed)))
	return nil
}

// statement mirrors RegisterKeyStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *RegisterKeyCircuit) statement(api frontend.API, nullifierPk, listTag frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	return append([]frontend.Variable{shared.RegisterKeyDomain, c.RingID, c.Member, nullifierPk, listTag}, sealed.StatementFields(api)...)
}
