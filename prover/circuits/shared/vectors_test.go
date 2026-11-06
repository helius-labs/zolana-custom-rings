package shared_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type ringSecretVectors struct {
	TxViewingSk        string `json:"tx_viewing_secret"`
	Salt               string `json:"salt"`
	FirstNullifier     string `json:"first_nullifier"`
	BlindingSeed       string `json:"blinding_seed"`
	OutputBlindingSeed string `json:"output_blinding_seed"`
	Outputs            []struct {
		OutputIndex int    `json:"output_index"`
		Blinding    string `json:"blinding"`
	} `json:"outputs"`
	SenderKey         string `json:"sender_key"`
	SenderPkHash      string `json:"sender_pk_hash"`
	PrivateTxBlinding string `json:"private_tx_blinding"`
}

type ringSecretsCircuit struct {
	OutputIndexes      []int `gnark:"-"`
	TxViewingSk        [32]frontend.Variable
	Salt               [16]frontend.Variable
	FirstNullifier     frontend.Variable
	BlindingSeed       frontend.Variable
	OutputBlindingSeed frontend.Variable
	Outputs            []ringSecretWires
	SenderKey          [32]frontend.Variable
	SenderPkHash       frontend.Variable
	PrivateTxBlinding  frontend.Variable
}

type ringSecretWires struct {
	Blinding frontend.Variable
}

func (c *ringSecretsCircuit) Define(api frontend.API) error {
	salt := gadget.PackBytesBE(api, c.Salt[:])[0]
	seed := shared.BlindingSeed(api, [2]frontend.Variable(gadget.PackBytesBE(api, c.TxViewingSk[:])), salt)
	api.AssertIsEqual(seed, c.BlindingSeed)
	outputSeed := transaction.DeriveOutputBlindingSeed(api, c.FirstNullifier, seed)
	api.AssertIsEqual(outputSeed, c.OutputBlindingSeed)
	for k, out := range c.Outputs {
		i := c.OutputIndexes[k]
		api.AssertIsEqual(transaction.DeriveOutputBlinding(api, c.FirstNullifier, outputSeed, i), out.Blinding)
	}
	senderPkHash := gadget.SolanaOwnerIdentity(api, c.SenderKey)
	api.AssertIsEqual(senderPkHash, c.SenderPkHash)
	privateTxBlinding := transaction.DerivePrivateTxBlinding(api, c.FirstNullifier, seed)
	api.AssertIsEqual(privateTxBlinding, c.PrivateTxBlinding)
	return nil
}

// The circuit gadgets rebuild every CRBS and TXOB value of the Rust vector from tx_viewing_sk.
func TestRingSecretsMatchRustVectors(t *testing.T) {
	var vectors ringSecretVectors
	ringtest.ReadVector(t, "wallet/ring-secrets.json", &vectors)
	witness := &ringSecretsCircuit{
		FirstNullifier:     ringtest.VectorField(t, vectors.FirstNullifier),
		BlindingSeed:       ringtest.VectorField(t, vectors.BlindingSeed),
		OutputBlindingSeed: ringtest.VectorField(t, vectors.OutputBlindingSeed),
		SenderPkHash:       ringtest.VectorField(t, vectors.SenderPkHash),
		PrivateTxBlinding:  ringtest.VectorField(t, vectors.PrivateTxBlinding),
	}
	copy(witness.TxViewingSk[:], ringtest.VectorWires(t, vectors.TxViewingSk, 32))
	copy(witness.Salt[:], ringtest.VectorWires(t, vectors.Salt, 16))
	copy(witness.SenderKey[:], ringtest.VectorWires(t, vectors.SenderKey, 32))
	for _, out := range vectors.Outputs {
		witness.OutputIndexes = append(witness.OutputIndexes, out.OutputIndex)
		witness.Outputs = append(witness.Outputs, ringSecretWires{
			Blinding: ringtest.VectorField(t, out.Blinding),
		})
	}
	circuit := &ringSecretsCircuit{OutputIndexes: witness.OutputIndexes, Outputs: make([]ringSecretWires, len(witness.Outputs))}
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring secret vector rejected, %v", err)
	}
	witness.Outputs[0].Blinding = new(big.Int).Add(ringtest.VectorField(t, vectors.Outputs[0].Blinding), big.NewInt(1))
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("output blinding accepted off the TXOB derivation")
	}
}
