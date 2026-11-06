package ring

import (
	"bytes"
	"encoding/json"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestKeysMatchTheRustCatalog(t *testing.T) {
	rust, err := os.ReadFile("../../program-libs/interface/src/proof/ring_keys.rs")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, match := range regexp.MustCompile(`name: "([a-z0-9-]+)"`).FindAllSubmatch(rust, -1) {
		want = append(want, string(match[1]))
	}
	got := make([]string, len(Keys))
	for i, key := range Keys {
		got[i] = string(key.Circuit)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("catalog differs from ring_keys.rs\n got %v\nwant %v", got, want)
	}
}

func TestEveryKeyIsRegisteredAndPinned(t *testing.T) {
	var lock struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(lockfile, &lock); err != nil {
		t.Fatal(err)
	}
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, len(Keys))
	for i, key := range Keys {
		extension := extensionOf(t, key.Circuit)
		if extension.KeyFile != key.KeyFile() || extension.Circuit() == nil {
			t.Fatalf("%s registers key %s", key.Circuit, extension.KeyFile)
		}
		if _, ok := manifest.Keys[key.KeyFile()]; !ok {
			t.Fatalf("%s is missing from the loaded manifest", key.KeyFile())
		}
		files[i] = key.KeyFile()
	}
	slices.Sort(files)
	if pinned := slices.Sorted(maps.Keys(lock.Keys)); !slices.Equal(files, pinned) {
		t.Fatalf("proving-keys.lock differs from the catalog\n got %v\nwant %v", pinned, files)
	}
}

// WRITE_RING_PINS=1 rewrites the measured counts, a count moves only with a circuit change.
func TestWriteConstraintPins(t *testing.T) {
	if os.Getenv("WRITE_RING_PINS") == "" {
		t.Skip("WRITE_RING_PINS=1 rewrites prover/ringtest/ringkey/constraints.json")
	}
	counts := map[string]int{}
	for _, key := range Keys {
		counts[strings.TrimSuffix(key.KeyFile(), ".key")] = compileRing(t, key.Circuit).GetNbConstraints()
	}
	encoded, err := json.MarshalIndent(counts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../ringtest/ringkey/constraints.json", append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every ring key compiles with one public input and the one BSB22 commitment over private wires groth16-solana verifies.
func TestRingKeysCompileToTheVerifiedShape(t *testing.T) {
	for _, key := range Keys {
		t.Run(string(key.Circuit), func(t *testing.T) {
			cs := compileRing(t, key.Circuit)
			ringkey.RequirePinned(t, strings.TrimSuffix(key.KeyFile(), ".key"), cs)
			if public := cs.GetNbPublicVariables() - 1; public != 1 {
				t.Errorf("%d public inputs, the program verifies one", public)
			}
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
				t.Errorf("commitments %v, want one over private wires", cs.GetCommitments())
			}
		})
	}
}

func TestRingKeysCarryTheCompiledCircuits(t *testing.T) {
	for _, key := range Keys {
		t.Run(string(key.Circuit), func(t *testing.T) {
			loaded := loadRingSystem(t, key.Circuit)
			var fromKey, fresh bytes.Buffer
			if _, err := loaded.ConstraintSystem.WriteTo(&fromKey); err != nil {
				t.Fatal(err)
			}
			if _, err := compileRing(t, key.Circuit).WriteTo(&fresh); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fromKey.Bytes(), fresh.Bytes()) {
				t.Fatalf("%s does not carry the compiled circuit, rotate the keys", key.KeyFile())
			}
		})
	}
}

// Compiled fresh each call, the CI runner holds one large circuit at a time.
func compileRing(t testing.TB, circuit common.CircuitType) constraint.ConstraintSystem {
	t.Helper()
	cs, err := extensionOf(t, circuit).R1CS()
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func loadRingSystem(t testing.TB, circuit common.CircuitType) *common.ExtensionProofSystem {
	t.Helper()
	dir := os.Getenv("ZOLANA_PROVER_KEYS_DIR")
	if dir == "" {
		// The justfile's spp-keys-dir.
		dir = "../../zolana/prover/server/proving-keys"
	}
	path := filepath.Join(dir, keyOf(t, circuit).KeyFile())
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("REQUIRE_RING_KEYS") == "1" {
			t.Fatalf("required key %s is not available: %v", path, err)
		}
		t.Skipf("%s is not available", path)
	}
	loaded, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	system, ok := loaded.(*common.ExtensionProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	return system
}
