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
		entries := []ringregistry.Entry{}
		ids := []int64{ringpolicy.Bob}
		value := int64(1)
		if revision == 0 {
			ids = []int64{ringpolicy.Sender, ringpolicy.Alice, ringpolicy.Bob}
		} else if revision == 1 {
			value = 3
		}
		for _, member := range ids {
			entries = append(entries, ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(3), Value: big.NewInt(value), EscrowKey: big.NewInt(0)})
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
	const policyKey common.CircuitType = "custom-ring-policy-member-v3-2-w0-own"
	world := ringpolicy.Confidential()
	world.OwnOnly, world.KeyEscrow = true, false
	world.Table.Lists, world.Table.Limits = []uint64{ringregistry.AllowBit, ringregistry.FrozenBit}, nil
	for member := range world.Own {
		world.Own[member] = ringpolicy.Record{Lists: ringregistry.AllowBit}
	}
	witness := world.Build(t)
	witness.Member.RingProgramID = instance
	for i := range witness.Member.Outputs {
		witness.Member.Outputs[i].RingProgramID = instance
	}
	witness.Rehash(t)
	if ringtest.AsBigInt(witness.Member.OwnRoot).Cmp(members.Root()) != 0 {
		t.Fatal("policy and update roots differ")
	}
	vectors["reader"] = map[string]any{
		"proof":  prove(policyKey, requestOf[MemberPolicyParams](t, policyKey, witness.Member)),
		"action": fb(ringtest.AsBigInt(witness.Member.PrivateTxHash)),
		"rules":  fieldsOf(ringtest.ToBigInts(witness.Member.Table.Rules[:ringtest.AsBigInt(witness.Member.Table.PolicyLen).Int64()])),
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../programs/policy-store/tests/proofs.json", append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
