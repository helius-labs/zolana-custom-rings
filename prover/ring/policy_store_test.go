package ring

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestPolicyStoreFixtures(t *testing.T) {
	address := os.Getenv("POLICY_STORE_REGISTRY")
	if address == "" {
		t.Skip("POLICY_STORE_REGISTRY is unset")
	}
	raw, err := hex.DecodeString(address)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid registry address")
	}
	instance := ringtest.HashBytes(t, raw)
	prove := func(circuit common.CircuitType, params any) *common.Proof {
		ps := loadRingSystem(t, circuit)
		requestJSON := mustMarshal(t, params)
		request := extensionOf(t, circuit).Request()
		if err := json.Unmarshal(requestJSON, request); err != nil {
			t.Fatal(err)
		}
		proof, err := (common.ExtensionProof{System: ps, Request: request}).Prove()
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyProof(ps, proof, decodePayload(t, circuit, requestJSON)); err != nil {
			t.Fatal(err)
		}
		return proof
	}
	vectors := map[string]any{"registry": address}
	members := ringregistry.New(t)
	for revision := range 3 {
		bob := big.NewInt(ringpolicy.Bob)
		var entries []ringregistry.Entry
		switch revision {
		case 0:
			for _, member := range []int64{ringpolicy.Sender, ringpolicy.Alice, ringpolicy.Bob} {
				entries = append(entries, ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(3), Value: big.NewInt(1), EscrowKey: big.NewInt(0)})
			}
		case 1:
			entries = []ringregistry.Entry{{Member: bob, Mask: big.NewInt(3), Value: big.NewInt(3), EscrowKey: big.NewInt(0)}}
		case 2:
			escrow := big.NewInt(ringregistry.EscrowBit)
			entries = []ringregistry.Entry{{Member: bob, Mask: escrow, Value: escrow, EscrowKey: big.NewInt(0xe5c0)}}
		}
		capacity, circuit := 1, applyKey
		if revision == 0 {
			capacity, circuit = 4, "custom-ring-apply-records-4"
		}
		request := (registryBatch{
			circuit: circuit, capacity: capacity, members: members, entries: entries,
			chainStart: spptest.MustHashChain4(t, []*big.Int{big.NewInt(shared.ApplyRecordsDomain), instance, big.NewInt(int64(revision))}),
		}).request(t)
		writes := make([]QueueEntry, len(entries))
		for i, write := range request.Writes[:len(entries)] {
			writes[i] = write.Entry
		}
		vectors["update"+big.NewInt(int64(revision)).String()] = map[string]any{
			"proof": prove(circuit, request), "root": request.NewRoot, "nextIndex": request.NewNextIndex, "writes": writes,
		}
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../programs/storage/tests/proofs.json", append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
