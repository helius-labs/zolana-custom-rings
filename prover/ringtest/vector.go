package ringtest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark/frontend"
)

// ReadVector decodes test-vectors/name, a file the Rust tests write.
func ReadVector(t testing.TB, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s, %v", name, err)
	}
}

func vectorPath(t testing.TB, name string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate vector.go")
	}
	return filepath.Join(filepath.Dir(source), "../../test-vectors", name)
}

// Hex is a field element written as 64 big-endian hex digits.
type Hex struct{ *big.Int }

func (h *Hex) UnmarshalJSON(data []byte) error {
	var digits string
	if err := json.Unmarshal(data, &digits); err != nil {
		return err
	}
	field, err := parseField(digits)
	h.Int = field
	return err
}

func VectorField(t testing.TB, value string) *big.Int {
	t.Helper()
	field, err := parseField(value)
	if err != nil {
		t.Fatal(err)
	}
	return field
}

func parseField(digits string) (*big.Int, error) {
	field, ok := new(big.Int).SetString(digits, 16)
	if !ok || len(digits) != 64 {
		return nil, fmt.Errorf("vector field %q is not 32 hex bytes", digits)
	}
	return field, nil
}

func VectorBytes(t testing.TB, value string, n int) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		t.Fatalf("invalid %d-byte vector value %q", n, value)
	}
	return raw
}

func VectorWires(t testing.TB, value string, n int) []frontend.Variable {
	t.Helper()
	wires := make([]frontend.Variable, n)
	for i, b := range VectorBytes(t, value, n) {
		wires[i] = int(b)
	}
	return wires
}

// WriteVectorsEnv rewrites a pinned vector from the Go host, every other language reads it.
const WriteVectorsEnv = "WRITE_AUDIT_VECTORS"

// PinVector requires test-vectors/name to hold value, rewriting it first under WriteVectorsEnv.
func PinVector(t testing.TB, name string, value any) {
	t.Helper()
	path := vectorPath(t, name)
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv(WriteVectorsEnv) != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(encoded) {
		t.Fatalf("the host disagrees with test-vectors/%s, rewrite it with %s=1", name, WriteVectorsEnv)
	}
}

func FieldHex(value *big.Int) string {
	var bytes [32]byte
	value.FillBytes(bytes[:])
	return hex.EncodeToString(bytes[:])
}
