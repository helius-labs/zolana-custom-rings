package ring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestWriteGoldenRequests(t *testing.T) {
	if os.Getenv("WRITE_RING_GOLDENS") == "" {
		t.Skip("WRITE_RING_GOLDENS=1 rewrites the request fixtures")
	}
	paths := map[common.CircuitType]string{}
	for _, path := range goldenFiles(t) {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head RequestHead
		if err := json.Unmarshal(payload, &head); err != nil {
			t.Fatal(err)
		}
		name := string(head.CircuitType)
		paths[common.CircuitType(name)] = path
	}
	for _, name := range []common.CircuitType{"custom-ring-audit-delivered-2", "custom-ring-audit-delivered-4", "custom-ring-withdrawal-exemption", "custom-ring-policy-member-v3-2-w0-own", "custom-ring-policy-member-v3-2-w2-own", "custom-ring-policy-member-v3-2-w2-curator", "custom-ring-policy-member-v3-2-w32-own", "custom-ring-deposit-1", "custom-ring-deposit-2", "custom-ring-deposit-4", "custom-ring-apply-records-2", "custom-ring-apply-records-4", "custom-ring-apply-records-8"} {
		paths[name] = goldenPath(string(name))
	}
	writeSolved(t, paths)
}

func TestWriteRequestFixtures(t *testing.T) {
	dir := os.Getenv("REQUEST_FIXTURES")
	if dir == "" {
		t.Skip("REQUEST_FIXTURES=<dir> writes a request per ring key")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := map[common.CircuitType]string{}
	for _, key := range Keys {
		paths[key.Circuit] = filepath.Join(dir, strings.TrimSuffix(key.KeyFile(), ".key")+".json")
	}
	writeSolved(t, paths)
}

// writeSolved writes each request only once the server's decoding of it solves the compiled key.
func writeSolved(t *testing.T, paths map[common.CircuitType]string) {
	t.Helper()
	for circuit, path := range paths {
		t.Run(string(circuit), func(t *testing.T) {
			encoded, err := json.MarshalIndent(hostRequest(t, keyOf(t, circuit)), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if meta, err := common.ParseProofRequestMeta(encoded); err != nil || meta.CircuitType != circuit {
				t.Fatalf("%s routes to %q: %v", circuit, meta.CircuitType, err)
			}
			if _, err := solvedWitness(t, circuit, encoded); err != nil {
				t.Fatalf("%s does not solve: %v", circuit, err)
			}
			if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}
