package ring

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

var (
	transferShape = transfer.Shape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4}
	entryShape    = transfer.Shape{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true}
)

// A request of every rail decodes strictly and solves on its key.
func TestTransferRequestsDecodeAndSolve(t *testing.T) {
	for _, tc := range []struct {
		name string
		rail ringtransfer.Rail
	}{{"signer", ringtransfer.Signer}, {"in-proof", ringtransfer.InProof}, {"delegate", ringtransfer.Delegate}} {
		t.Run(tc.name, func(t *testing.T) {
			w := ringtransfer.Signed(transferShape)
			w.Rail = tc.rail
			requireRequestSolved(t, transferKey, requestOf[TransferParams](t, transferKey, w.Build(t).Circuit))
		})
	}
	for _, tc := range []struct {
		name  string
		key   common.CircuitType
		shape transfer.Shape
	}{{"hidden", transferKey, transferShape}, {"entry", entryKey, entryShape}} {
		t.Run(tc.name, func(t *testing.T) {
			requireRequestSolved(t, tc.key, requestOf[TransferParams](t, tc.key, ringtransfer.Hidden(tc.shape).Build(t).Circuit))
		})
	}
}

func requireRequestSolved(t *testing.T, key common.CircuitType, params any) {
	t.Helper()
	if err := test.IsSolved(extensionOf(t, key).Circuit(), decodeParams(t, key, params), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func transferPayload(t testing.TB) []byte {
	t.Helper()
	return mustMarshal(t, requestOf[TransferParams](t, transferKey, ringtransfer.Signed(transferShape).Build(t).Circuit))
}

func TestPolicyRequestsRejectMalformedPayloads(t *testing.T) {
	payload := transferPayload(t)
	record := func(m map[string]any) map[string]any { return m["ownRecords"].([]any)[0].(map[string]any) }
	subject := func(m map[string]any) map[string]any { return m["ownSubjects"].([]any)[0].(map[string]any) }
	entry := func(m map[string]any) map[string]any { return m["senderEntries"].([]any)[0].(map[string]any) }
	proof := func(m map[string]any) map[string]any { return m["ownProof"].(map[string]any) }
	path := func(m map[string]any) map[string]any { return proof(m)["paths"].([]any)[0].(map[string]any) }
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"unknown field", func(m map[string]any) { m["other"] = 3 }, "unknown field"},
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
		{"tracking record outside pool", func(m map[string]any) {
			m["trackingSubjects"].([]any)[0].(map[string]any)["recordIndex"] = len(m["trackingRecords"].([]any))
		}, "tracking record"},
		{"tracking path outside tree", func(m map[string]any) {
			m["trackingProof"].(map[string]any)["paths"].([]any)[0].(map[string]any)["index"] = registry.TrackingCapacity
		}, "tracking path"},
		{"row entry outside pool", func(m map[string]any) { m["rowEntries"].([]any)[0] = len(m["trackingSubjects"].([]any)) }, "tracking subject"},
		{"short canopy", func(m map[string]any) { proof(m)["canopy"] = proof(m)["canopy"].([]any)[1:] }, "expected"},
		{"short path", func(m map[string]any) { path(m)["siblings"] = path(m)["siblings"].([]any)[1:] }, "expected"},
		{"short sibling row", func(m map[string]any) { rows := path(m)["siblings"].([]any); rows[0] = rows[0].([]any)[1:] }, "expected"},
		{"wrong circuit label", func(m map[string]any) { m["circuitType"] = transfer4Key }, "request on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw)
			if _, err := decode(transferKey, mustMarshal(t, raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := decode(transferKey, append(payload, []byte("{}")...)); err == nil {
		t.Fatal("trailing payload accepted")
	}
	duplicate := append([]byte(`{"circuitType":"`+string(transferKey)+`",`), payload[1:]...)
	if _, err := decode(transferKey, duplicate); err == nil || !strings.Contains(err.Error(), "repeated field") {
		t.Fatalf("duplicate header accepted %v", err)
	}
}
