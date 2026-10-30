package ring

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const ownMemberKey common.CircuitType = "custom-ring-policy-member-v3-2-w0-own"

func TestPolicyRequestsDecodeAndSolve(t *testing.T) {
	for _, own := range []bool{false, true} {
		for _, anonymous := range []bool{false, true} {
			world := ringpolicy.Confidential()
			world.OwnOnly, world.Anonymous = own, anonymous
			world.WithdrawalCapacity = 2
			world.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 1}}
			if !own {
				world.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
				world.Curator = world.Own
			}
			key := Key{Family: MemberPolicy, Outputs: 2, Withdrawals: 2, OwnOnly: own}.circuitType()
			t.Run(fmt.Sprintf("%s-anonymous%v", key, anonymous), func(t *testing.T) {
				requireRequestSolved(t, key, requestOf[MemberPolicyParams](t, key, world.Build(t).Assignment()))
			})
		}
		for _, width := range []int{2, 4} {
			key := Key{Family: DelegatePolicy, Inputs: width, Outputs: width, OwnOnly: own}.circuitType()
			t.Run(string(key), func(t *testing.T) {
				world := ringpolicy.Delegate(transaction.Shape{NInputs: width, NOutputs: width})
				world.OwnOnly = own
				if !own {
					world.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
					world.Curator = world.Own
				}
				requireRequestSolved(t, key, requestOf[DelegatePolicyParams](t, key, world.Build(t).Assignment()))
			})
		}
	}
}

func requireRequestSolved(t *testing.T, key common.CircuitType, params any) {
	t.Helper()
	if err := test.IsSolved(extensionOf(t, key).Circuit(), decodeParams(t, key, params), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func memberPayload(t testing.TB) []byte {
	t.Helper()
	world := ringpolicy.Confidential()
	world.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
	world.Curator = world.Own
	return mustMarshal(t, requestOf[MemberPolicyParams](t, memberKey, world.Build(t).Assignment()))
}

func TestPolicyRequestsRejectMalformedPayloads(t *testing.T) {
	payload := memberPayload(t)
	record := func(m map[string]any) map[string]any { return m["ownRecords"].([]any)[0].(map[string]any) }
	subject := func(m map[string]any) map[string]any { return m["ownSubjects"].([]any)[0].(map[string]any) }
	entry := func(m map[string]any) map[string]any { return m["senderEntry"].(map[string]any) }
	proof := func(m map[string]any) map[string]any { return m["ownProof"].(map[string]any) }
	path := func(m map[string]any) map[string]any { return proof(m)["paths"].([]any)[0].(map[string]any) }
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"unknown field", func(m map[string]any) { m["version"] = 3 }, "unknown field"},
		{"unknown record field", func(m map[string]any) { record(m)["present"] = true }, "unknown field"},
		{"missing common field", func(m map[string]any) { delete(m, "privateTxHash") }, "missing field"},
		{"missing record field", func(m map[string]any) { delete(record(m), "next") }, "missing field"},
		{"missing subject index", func(m map[string]any) { delete(subject(m), "recordIndex") }, "missing field"},
		{"missing curator reference", func(m map[string]any) { delete(entry(m), "curator") }, "missing field"},
		{"null record field", func(m map[string]any) { record(m)["member"] = nil }, "missing"},
		{"noncanonical member", func(m map[string]any) { record(m)["member"] = "0x01" }, "not canonical"},
		{"modulus member", func(m map[string]any) { record(m)["member"] = "0x" + ecc.BN254.ScalarField().Text(16) }, "not canonical"},
		{"negative subject index", func(m map[string]any) { subject(m)["recordIndex"] = -1 }, "uint32"},
		{"fractional subject index", func(m map[string]any) { subject(m)["recordIndex"] = 0.5 }, "uint32"},
		{"record index outside pool", func(m map[string]any) { subject(m)["recordIndex"] = len(m["ownRecords"].([]any)) }, "record index"},
		{"subject index outside pool", func(m map[string]any) { entry(m)["own"] = len(m["ownSubjects"].([]any)) }, "subject index"},
		{"curator index outside pool", func(m map[string]any) { entry(m)["curator"] = []any{len(m["curatorSubjects"].([]any))} }, "subject index"},
		{"public asset index outside pool", func(m map[string]any) { m["publicAssetEntries"].([]any)[0] = len(m["ownSubjects"].([]any)) }, "subject index"},
		{"path index outside tree", func(m map[string]any) { path(m)["index"] = registry.Capacity }, "path index"},
		{"short canopy", func(m map[string]any) { proof(m)["canopy"] = proof(m)["canopy"].([]any)[1:] }, "expected"},
		{"short path", func(m map[string]any) { path(m)["siblings"] = path(m)["siblings"].([]any)[1:] }, "expected"},
		{"short sibling row", func(m map[string]any) { rows := path(m)["siblings"].([]any); rows[0] = rows[0].([]any)[1:] }, "expected"},
		{"wrong circuit label", func(m map[string]any) { m["circuitType"] = delegateKey }, "request on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw)
			if _, err := decode(memberKey, mustMarshal(t, raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := decode(memberKey, append(payload, []byte("{}")...)); err == nil {
		t.Fatal("trailing payload accepted")
	}
	duplicate := append([]byte(`{"circuitType":"`+string(memberKey)+`",`), payload[1:]...)
	if _, err := decode(memberKey, duplicate); err == nil || !strings.Contains(err.Error(), "repeated field") {
		t.Fatalf("duplicate header accepted %v", err)
	}
}

func TestOwnPolicyRequestsRequireEmptyCuratorReferences(t *testing.T) {
	world := ringpolicy.Confidential()
	world.OwnOnly = true
	params := requestOf[MemberPolicyParams](t, ownMemberKey, world.Build(t).Assignment())
	params.SenderEntry.Curator = []uint32{0}
	if _, err := decode(ownMemberKey, mustMarshal(t, params)); err == nil {
		t.Fatal("own key accepted a curator reference")
	}
}

func TestDelegateRequestsCarryNoPublicAssetEntries(t *testing.T) {
	params := requestOf[DelegatePolicyParams](t, delegateKey, ringpolicy.Delegate(transaction.Shape{NInputs: 2, NOutputs: 2}).Build(t).Assignment())
	params.PublicAssetEntries = []uint32{0}
	if _, err := decode(delegateKey, mustMarshal(t, params)); err == nil {
		t.Fatal("delegate key accepted a public asset reference")
	}
}
