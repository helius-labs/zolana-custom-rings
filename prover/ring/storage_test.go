package ring

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestStorageFixtures(t *testing.T) {
	address := os.Getenv("STORAGE_REGISTRY")
	if address == "" {
		t.Skip("STORAGE_REGISTRY is unset")
	}
	raw, err := hex.DecodeString(address)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid registry address")
	}
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
				entries = append(entries, ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(3), Value: big.NewInt(1)})
			}
		case 1:
			// A block list addition retires every earlier root.
			entries = []ringregistry.Entry{{Member: bob, Mask: big.NewInt(3), Value: big.NewInt(3)}}
		case 2:
			// A list grant rotates graced, no earlier root was stricter.
			entries = []ringregistry.Entry{{Member: big.NewInt(ringpolicy.Alice), Mask: big.NewInt(ringregistry.ApprovalBit), Value: big.NewInt(ringregistry.ApprovalBit)}}
		}
		capacity, circuit := 1, applyKey
		if revision == 0 {
			capacity, circuit = 4, "custom-ring-apply-records-4"
		}
		request, restrictive := (registryBatch{
			circuit: circuit, capacity: capacity, members: members, entries: entries,
			chainStart: ringregistry.ChainStart(t, raw, uint64(revision)),
		}).request(t)
		writes := make([]RecordWrite, len(entries))
		for i, write := range request.Writes[:len(entries)] {
			writes[i] = write.Entry
		}
		update := map[string]any{
			"proof": prove(circuit, request), "root": request.NewRoot, "nextIndex": request.NewNextIndex, "writes": writes, "restrictive": restrictive,
		}
		vectors["update"+big.NewInt(int64(revision)).String()] = update
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../programs/storage/tests/proofs.json", append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
