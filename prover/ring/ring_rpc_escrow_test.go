package ring

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestRingRpcEscrowFixture(t *testing.T) {
	member := os.Getenv("RING_RPC_ESCROW_MEMBER")
	if member == "" {
		t.Skip("RING_RPC_ESCROW_MEMBER is unset")
	}
	raw, err := hex.DecodeString(member)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid member identity")
	}
	params := registerKeyRequest(t, registerKey, new(big.Int).SetBytes(raw))
	system := loadRingSystem(t, registerKey)
	payload := mustMarshal(t, params)
	request := extensionOf(t, registerKey).Request()
	if err := json.Unmarshal(payload, request); err != nil {
		t.Fatal(err)
	}
	proof, err := (common.ExtensionProof{System: system, Request: request}).Prove()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProof(system, proof, decodePayload(t, registerKey, payload)); err != nil {
		t.Fatal(err)
	}
	keys := ringaudit.DefaultKeys(t)
	auditor, eph := ringprotocol.Tagged(params.AuditorPk), keys.EphPk()
	encoded, err := json.MarshalIndent(map[string]any{
		"member":      params.Member,
		"nullifierPk": fb(spptest.MustNullifierPk(t, new(big.Int).SetBytes(params.NullifierSecret[1:]))),
		"auditorPk":   Bytes(auditor[:]),
		"ephPk":       Bytes(eph[:]),
		"ciphertext":  Bytes(keys.EnvelopeCiphertext(t, params.NullifierSecret, shared.NfKeyEncInfo)),
		"proof":       proof,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../services/ring-rpc/tests/escrow_proof.json", append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
