package registry

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The nullifier key is Poseidon of the 31-byte nullifier secret the envelope seals to AuditorPk, so the auditor recovers the secret behind the escrowed key.
// 2. The statement binds the member, the key, both tagged envelope keys and the ciphertext hash, and the program queues the escrow write Poseidon(nullifier_pk, ct_hash) from them.
// 3. No registry record and no UTXO owner is opened, the queue applies the write later.

type RegisterKeyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Member          frontend.Variable
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *RegisterKeyCircuit) Define(api frontend.API) error {
	// 1. A zero lead byte keeps the secret below q, the envelope's cipher bounds the other 31 bytes.
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	nullifierPk := gadget.PoseidonHash(api, shared.PackBounded(api, c.NullifierSecret[1:]))
	// 2. The envelope seals the same 32 bytes to the auditor, its cipher bounds every ciphertext byte.
	sealed := shared.Envelope{Plaintext: c.NullifierSecret[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.NfKeyEncInfo}.Seal(api)
	// 3. The statement names the member and the envelope the program reads from the instruction.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, nullifierPk, sealed)))
	return nil
}

// statement mirrors RegisterKeyStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *RegisterKeyCircuit) statement(api frontend.API, nullifierPk frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	return append([]frontend.Variable{shared.RegisterKeyDomain, c.Member, nullifierPk}, sealed.StatementFields(api)...)
}
