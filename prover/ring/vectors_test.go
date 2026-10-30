package ring

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type vectorHex []byte

func (v *vectorHex) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(s)
	*v = decoded
	return err
}

func (v vectorHex) int() *big.Int { return new(big.Int).SetBytes(v) }

func TestRingSecretsMatchTheRustVectors(t *testing.T) {
	data, err := os.ReadFile("../../test-vectors/wallet/ring-secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		TxViewingSecret       vectorHex `json:"tx_viewing_secret"`
		RecipientViewingPk    vectorHex `json:"recipient_viewing_pk"`
		Salt                  vectorHex `json:"salt"`
		FirstNullifier        vectorHex `json:"first_nullifier"`
		BlindingSeed          vectorHex `json:"blinding_seed"`
		OutputBlindingSeed    vectorHex `json:"output_blinding_seed"`
		SenderKey             vectorHex `json:"sender_key"`
		SenderPkHash          vectorHex `json:"sender_pk_hash"`
		PrivateTxBlinding     vectorHex `json:"private_tx_blinding"`
		SenderCommitment      vectorHex `json:"sender_commitment"`
		DepositBlindingSecret vectorHex `json:"deposit_blinding_secret"`
		DepositBlinding       vectorHex `json:"deposit_blinding"`
		Outputs               []struct {
			OutputIndex         int       `json:"output_index"`
			DeliveredSlotSecret vectorHex `json:"delivered_slot_secret"`
			Blinding            vectorHex `json:"blinding"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	txViewingSk, salt, firstNullifier := [32]byte(v.TxViewingSecret), [16]byte(v.Salt), v.FirstNullifier.int()
	recipient := [32]byte(v.RecipientViewingPk[1:])
	equal := func(name string, got *big.Int, want vectorHex) {
		t.Helper()
		if got.Cmp(want.int()) != 0 {
			t.Errorf("%s: got %x want %x", name, got, want)
		}
	}
	equal("blinding seed", ringprotocol.BlindingSeed(t, txViewingSk, salt), v.BlindingSeed)
	seedOut, err := protocol.OutputBlindingSeed(firstNullifier, v.BlindingSeed.int())
	equal("output blinding seed", spptest.MustHash(t, seedOut, err), v.OutputBlindingSeed)
	for _, o := range v.Outputs {
		secret := ringprotocol.DeliveredSlotSecret(t, txViewingSk, recipient, salt, o.OutputIndex, firstNullifier)
		equal("delivered slot secret", secret, o.DeliveredSlotSecret)
		equal("output blinding", ringprotocol.OutputBlinding(t, firstNullifier, v.OutputBlindingSeed.int(), o.OutputIndex), o.Blinding)
	}
	equal("sender pk hash", ringtest.MustSolanaPkField(t, [32]byte(v.SenderKey)), v.SenderPkHash)
	equal("sender commitment", ringprotocol.SenderCommitment(t, v.SenderPkHash.int(), v.PrivateTxBlinding.int()), v.SenderCommitment)
	equal("deposit blinding", ringprotocol.DepositBlinding(t, v.DepositBlindingSecret.int()), v.DepositBlinding)
}
