package ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestAnApplyProofOverAssetLimitsVerifies(t *testing.T) {
	const circuit common.CircuitType = "custom-ring-apply-records-2"
	var vector struct {
		Rows []struct {
			Member, Field ringtest.Hex
			Limits        []ringtest.Hex
			Amount        string
			EntryHash     ringtest.Hex `json:"entry_hash"`
		}
	}
	ringtest.ReadVector(t, "registry/mint-records.json", &vector)
	row := vector.Rows[len(vector.Rows)-1]
	amount, ok := new(big.Int).SetString(row.Amount, 10)
	if !ok {
		t.Fatal("amount")
	}
	write := ringregistry.Entry{
		Member: row.Member.Int, Mask: big.NewInt(0), Value: big.NewInt(0), EscrowKey: big.NewInt(0),
		MintPolicy: new(big.Int).Or(row.Field.Int, new(big.Int).Lsh(big.NewInt(1), 192)), WithdrawalThreshold: amount,
		AssetLimits: ringregistry.VectorLimits(t, row.Limits),
	}
	if write.Hash(t).Cmp(row.EntryHash.Int) != 0 {
		t.Fatal("queue entry differs from Rust")
	}
	params := (registryBatch{circuit: circuit, capacity: 2, members: ringregistry.New(t), entries: []ringregistry.Entry{write}, chainStart: big.NewInt(0)}).request(t)
	system := loadRingSystem(t, circuit)
	payload := mustMarshal(t, params)
	request := extensionOf(t, circuit).Request()
	if err := json.Unmarshal(payload, request); err != nil {
		t.Fatal(err)
	}
	proof, err := common.ExtensionProof{System: system, Request: request}.Prove()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProof(system, proof, decodePayload(t, circuit, payload)); err != nil {
		t.Fatal(err)
	}
}
