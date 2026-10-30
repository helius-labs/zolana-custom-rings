package ring

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const goldenDigests = "testdata/witness.sha256"

// rustGoldens are written by the Rust SDK, in its own key order.
const rustGoldens = "../../sdk-libs/sdk/tests/fixtures"

// UPDATE_RING_GOLDENS=1 rewrites the digests, never the fixtures.
func TestGoldenRequestsAssignTheRecordedWitness(t *testing.T) {
	rust, err := filepath.Glob(filepath.Join(rustGoldens, "*.json"))
	if err != nil || len(rust) == 0 {
		t.Fatalf("no Rust fixtures: %v", err)
	}
	digests := map[string]string{}
	for _, file := range append(goldenFiles(t), rust...) {
		name := filepath.Base(file)
		if strings.HasPrefix(file, rustGoldens) {
			name = "rust/" + name
		}
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err != nil {
			t.Fatal(err)
		}
		witness, solved := solvedWitness(t, meta.CircuitType, payload)
		if solved != nil {
			t.Errorf("%s does not solve: %v", name, solved)
		}
		encoded, err := witness.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		digests[name] = hex.EncodeToString(digest[:])
	}
	if os.Getenv("UPDATE_RING_GOLDENS") != "" {
		writeDigests(t, digests)
		return
	}
	want := readDigests(t)
	if len(want) != len(digests) {
		t.Fatalf("%d fixtures against %d digests", len(digests), len(want))
	}
	for name, digest := range digests {
		if want[name] != digest {
			t.Errorf("%s assigns a different witness", name)
		}
	}
}

func goldenFiles(t testing.TB) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("testdata", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	sort.Strings(files)
	return files
}

func goldenPath(name string) string {
	var family string
	switch {
	case strings.HasPrefix(name, "custom-ring-audit-anonymous-entry-"):
		family = "audit/entry"
	case strings.HasPrefix(name, "custom-ring-audit-anonymous-v2-"):
		parts := strings.Split(name, "-")
		outputs := parts[len(parts)-1]
		if outputs != "2" && outputs != "4" && outputs != "8" {
			panic("unknown anonymous audit shape: " + name)
		}
		family = "audit/anonymous/outputs_" + outputs
	case strings.HasPrefix(name, "custom-ring-audit-"):
		family = "audit"
	case strings.HasPrefix(name, "custom-ring-policy-member-"):
		family = "policy/member"
	case strings.HasPrefix(name, "custom-ring-policy-delegate-"):
		family = "policy/delegate"
	case strings.HasPrefix(name, "custom-ring-apply-records-"), name == "custom-ring-register-key", name == "custom-ring-withdrawal-exemption":
		family = "records"
	case strings.HasPrefix(name, "custom-ring-deposit-"):
		family = "deposit"
	case strings.HasPrefix(name, "custom-ring-merge-"):
		family = "merge"
	default:
		panic("unknown ring golden family: " + name)
	}
	return filepath.Join("testdata", family, name+".json")
}

func readDigests(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(goldenDigests)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digests := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		digest, name, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("malformed digest line %q", scanner.Text())
		}
		digests[name] = digest
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return digests
}

func writeDigests(t *testing.T, digests map[string]string) {
	t.Helper()
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "%s  %s\n", digests[name], name)
	}
	if err := os.WriteFile(goldenDigests, []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
