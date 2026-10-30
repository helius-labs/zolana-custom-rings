package ring

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// A request names every value its circuit reads, an omitted one is never assigned zero.
func TestDecodeNamesEveryMissingValue(t *testing.T) {
	for _, key := range Keys {
		_, err := decode(key.Circuit, []byte(`{"circuitType":"`+string(key.Circuit)+`"}`))
		if err == nil || !strings.Contains(err.Error(), `missing field "publicInputHash"`) {
			t.Errorf("%s: an empty request decoded: %v", key.Circuit, err)
		}
	}
}

// Each case changes one value of an honest request.
func TestDecodeRejectsMalformedRequests(t *testing.T) {
	requests := map[common.CircuitType]any{smallDeliveredKey: hostRequest(t, keyOf(t, smallDeliveredKey)), batchKey: hostRequest(t, keyOf(t, batchKey))}
	output := func(m map[string]any) map[string]any { return m["outputs"].([]any)[0].(map[string]any) }
	write := func(m map[string]any) map[string]any { return m["writes"].([]any)[0].(map[string]any) }
	modulus := "0x" + ecc.BN254.ScalarField().Text(16)
	canonical := "not canonical lowercase 0x hex"
	for _, tc := range []struct {
		name    string
		circuit common.CircuitType
		tamper  func(map[string]any)
		want    string
	}{
		{"unknown field", smallDeliveredKey, func(m map[string]any) { m["externalDataHash"] = m["firstNullifier"] }, `unknown field "externalDataHash"`},
		{"settled away field", smallDeliveredKey, func(m map[string]any) { m["seedOut"] = m["firstNullifier"] }, `unknown field "seedOut"`},
		{"unknown nested field", smallDeliveredKey, func(m map[string]any) { output(m)["owner"] = m["firstNullifier"] }, `unknown field "owner"`},
		{"field name in another case", smallDeliveredKey, func(m map[string]any) { m["FirstNullifier"] = m["firstNullifier"]; delete(m, "firstNullifier") }, `unknown field "FirstNullifier"`},
		{"null layout", smallDeliveredKey, func(m map[string]any) { m["layout"] = nil }, "layout: null value"},
		{"missing field", smallDeliveredKey, func(m map[string]any) { delete(m, "firstNullifier") }, `missing field "firstNullifier"`},
		{"missing layout", smallDeliveredKey, func(m map[string]any) { delete(m, "layout") }, `missing field "layout"`},
		{"missing flag", batchKey, func(m map[string]any) { delete(write(m), "exists") }, `writes: [0]: missing field "exists"`},
		{"null field", smallDeliveredKey, func(m map[string]any) { m["firstNullifier"] = nil }, "FirstNullifier: missing"},
		{"field at the modulus", smallDeliveredKey, func(m map[string]any) { m["firstNullifier"] = modulus }, canonical},
		{"uppercase hex", smallDeliveredKey, func(m map[string]any) { m["auditorPk"] = strings.ToUpper(m["auditorPk"].(string)) }, canonical},
		{"short field", smallDeliveredKey, func(m map[string]any) { m["firstNullifier"] = "0x01" }, canonical},
		{"long salt", smallDeliveredKey, func(m map[string]any) { m["salt"] = m["salt"].(string) + "00" }, "Salt: expected 16 values"},
		{"layout as a string", smallDeliveredKey, func(m map[string]any) { m["layout"] = "2" }, "DeliveredAuditParams.layout of type uint8"},
		{"layout above a byte", smallDeliveredKey, func(m map[string]any) { m["layout"] = 256 }, "number 256"},
		{"an output past the capacity", smallDeliveredKey, func(m map[string]any) { m["outputs"] = append(m["outputs"].([]any), output(m)) }, "Outputs: expected 2 values"},
		{"an owner key one byte short", smallDeliveredKey, func(m map[string]any) { output(m)["ownerKey"] = output(m)["ownerKey"].(string)[:64] }, "OwnerKey: expected 32 values"},
		{"another key's request", smallDeliveredKey, func(m map[string]any) { m["circuitType"] = "custom-ring-audit-delivered-4" }, "custom-ring-audit-delivered-4 request on the custom-ring-audit-delivered-2 key"},
		{"a write past the capacity", batchKey, func(m map[string]any) { m["writes"] = append(m["writes"].([]any), write(m)) }, "Writes: expected 16 values"},
		{"a path one sibling short", batchKey, func(m map[string]any) { write(m)["path"] = write(m)["path"].([]any)[1:] }, "Writes[0].Slot.Siblings[9]: expected 3 values"},
		{"a path one sibling long", batchKey, func(m map[string]any) { write(m)["lowPath"] = append(write(m)["lowPath"].([]any), m["oldRoot"]) }, "Writes[0].Low.Siblings: expected 10 values"},
		{"lists as a string", batchKey, func(m map[string]any) { write(m)["oldLists"] = "1" }, "oldLists of type uint64"},
		{"exists as a number", batchKey, func(m map[string]any) { write(m)["exists"] = 1 }, "exists of type bool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(mustMarshal(t, requests[tc.circuit]), &raw); err != nil {
				t.Fatal(err)
			}
			tc.tamper(raw)
			if _, err := decode(tc.circuit, mustMarshal(t, raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	honest := mustMarshal(t, requests[smallDeliveredKey])
	if _, err := decode(smallDeliveredKey, append(honest, []byte("{}")...)); err == nil {
		t.Fatal("trailing data decoded")
	}
	repeated := append([]byte(`{"firstNullifier":"0x`+strings.Repeat("00", 32)+`",`), honest[1:]...)
	if _, err := decode(smallDeliveredKey, repeated); err == nil || !strings.Contains(err.Error(), `repeated field "firstNullifier"`) {
		t.Fatalf("a repeated field decoded: %v", err)
	}
	if _, err := decode("custom-ring-audit-delivered-4", honest); err == nil {
		t.Fatal("a request for the 2-output key decoded on the 4-output key")
	}
}
