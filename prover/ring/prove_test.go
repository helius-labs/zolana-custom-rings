package ring

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Every accepted fixture proves under its installed key, and only for its own statement.
func TestGoldenRequestsProveWithTheInstalledKeys(t *testing.T) {
	for _, file := range goldenFiles(t) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			payload, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			meta, err := common.ParseProofRequestMeta(payload)
			if err != nil {
				t.Fatal(err)
			}
			ps := loadRingSystem(t, meta.CircuitType)
			request := extensionOf(t, meta.CircuitType).Request()
			if err := json.Unmarshal(payload, request); err != nil {
				t.Fatal(err)
			}
			proof, err := common.ExtensionProof{System: ps, Request: request}.Prove()
			if err != nil {
				t.Fatal(err)
			}
			assignment := decodePayload(t, meta.CircuitType, payload)
			if err := verifyProof(ps, proof, assignment); err != nil {
				t.Fatal(err)
			}
			if verifyProof(ps, proof, withPublicInputHash(assignment, big.NewInt(1))) == nil {
				t.Fatal("proof admitted under a different statement")
			}
		})
	}
}

func withPublicInputHash(assignment frontend.Circuit, value *big.Int) frontend.Circuit {
	copied := reflect.New(reflect.TypeOf(assignment).Elem())
	copied.Elem().Set(reflect.ValueOf(assignment).Elem())
	copied.Elem().FieldByName("PublicInputHash").Set(reflect.ValueOf(frontend.Variable(value)))
	return copied.Interface().(frontend.Circuit)
}

// Every shipped shape, including nonempty withdrawals and both apply families,
// must produce a proof. REQUIRE_RING_KEYS makes absent release artifacts a hard CI failure.
func TestCatalogRequestsProveWithTheInstalledKeys(t *testing.T) {
	vectors := map[string]any{}
	for _, key := range Keys {
		t.Run(string(key.Circuit), func(t *testing.T) {
			ps := loadRingSystem(t, key.Circuit)
			payload := mustMarshal(t, hostRequest(t, key))
			request := extensionOf(t, key.Circuit).Request()
			if err := json.Unmarshal(payload, request); err != nil {
				t.Fatal(err)
			}
			proof, err := (common.ExtensionProof{System: ps, Request: request}).Prove()
			if err != nil {
				t.Fatal(err)
			}
			assignment := decodePayload(t, key.Circuit, payload)
			vectors[string(key.Circuit)] = struct {
				Statement Field         `json:"statement"`
				Proof     *common.Proof `json:"proof"`
			}{fb(fieldOf(reflect.ValueOf(assignment).Elem().FieldByName("PublicInputHash"))), proof}
			if err := verifyProof(ps, proof, assignment); err != nil {
				t.Fatal(err)
			}
			if verifyProof(ps, proof, withPublicInputHash(assignment, big.NewInt(1))) == nil {
				t.Fatal("proof admitted under different statement")
			}
		})
	}
	if os.Getenv("WRITE_RING_PROOF_VECTORS") == "1" {
		if t.Failed() || len(vectors) != len(Keys) {
			t.Fatal("refusing partial proof vectors")
		}
		encoded, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("../../test-vectors/proof/ring-proofs.json", append(encoded, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}

}
