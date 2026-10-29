package circuits

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type depositStatementCircuit struct {
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	PolicyHash         frontend.Variable
	Assets             [MaxDeposits]frontend.Variable
	Amounts            [MaxDeposits]frontend.Variable
	Commitments        [MaxDeposits]frontend.Variable
	Ciphertext         [MaxDeposits * DepositOpeningBytes]frontend.Variable
	AuditorPubkey      [33]frontend.Variable
	EphPk              [33]frontend.Variable
}

func (c *depositStatementCircuit) Define(api frontend.API) error {
	circuit := &DepositCircuit{
		ContextHash: c.ContextHash, Count: c.Count, Anonymous: c.Anonymous, KeyEscrow: c.KeyEscrow, MemberRegistryRoot: c.MemberRegistryRoot,
		PolicyHash: c.PolicyHash, Assets: c.Assets[:], Amounts: c.Amounts[:],
	}
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, c.EphPk[:]),
		Ciphertext: c.Ciphertext[:],
	}
	statement := circuit.statement(api, ringgadget.SelectCount(api, c.Count, 1, MaxDeposits), c.Commitments[:], sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, statement))
	return nil
}

// The Rust ciphertexts are no sealed envelopes.
func TestDepositStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		Deposit struct {
			ContextHash        string   `json:"context_hash"`
			Anonymous          bool     `json:"anonymous"`
			OwnerUtxoHashes    []string `json:"owner_utxo_hashes"`
			Ciphertexts        []string `json:"ciphertexts"`
			AuditorPubkey      string   `json:"auditor_pubkey"`
			EphPk              string   `json:"eph_pk"`
			Assets             []string `json:"assets"`
			Amounts            []uint64 `json:"amounts"`
			KeyEscrow          bool     `json:"key_escrow"`
			MemberRegistryRoot *string  `json:"member_registry_root"`
			PolicyHash         *string  `json:"policy_hash"`
			PublicInputHash    string   `json:"public_input_hash"`
		} `json:"deposit"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.Deposit
	if len(v.OwnerUtxoHashes) != len(v.Ciphertexts) || len(v.OwnerUtxoHashes) != len(v.Assets) || len(v.Assets) != len(v.Amounts) || len(v.OwnerUtxoHashes) == 0 || len(v.OwnerUtxoHashes) > MaxDeposits {
		t.Fatalf("%d commitments for %d ciphertexts", len(v.OwnerUtxoHashes), len(v.Ciphertexts))
	}
	witness := &depositStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash), ContextHash: ringtest.VectorField(t, v.ContextHash),
		Count: len(v.OwnerUtxoHashes), Anonymous: ringtest.Bit(v.Anonymous), KeyEscrow: ringtest.Bit(v.KeyEscrow), MemberRegistryRoot: 0, PolicyHash: 0,
	}
	if v.MemberRegistryRoot != nil {
		witness.MemberRegistryRoot = ringtest.VectorField(t, *v.MemberRegistryRoot)
	}
	if v.PolicyHash != nil {
		witness.PolicyHash = ringtest.VectorField(t, *v.PolicyHash)
	}
	for i := range witness.Commitments {
		witness.Commitments[i], witness.Assets[i], witness.Amounts[i] = 0, 0, 0
	}
	for i, asset := range v.Assets {
		witness.Assets[i], witness.Amounts[i] = ringtest.VectorField(t, asset), v.Amounts[i]
	}
	for i := range witness.Ciphertext {
		witness.Ciphertext[i] = 0
	}
	for i, commitment := range v.OwnerUtxoHashes {
		witness.Commitments[i] = ringtest.VectorField(t, commitment)
		copy(witness.Ciphertext[i*DepositOpeningBytes:(i+1)*DepositOpeningBytes], ringtest.VectorWires(t, v.Ciphertexts[i], DepositOpeningBytes))
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphPk[:], ringtest.VectorWires(t, v.EphPk, 33))
	ringtest.RequirePublicInputBound(t, &depositStatementCircuit{}, witness)
}
