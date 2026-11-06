package ring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func rustFixture(t *testing.T, name string) (common.CircuitType, map[string]any) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(rustGoldens, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := common.ParseProofRequestMeta(payload)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	return meta.CircuitType, request
}

func solveRequest(t *testing.T, key common.CircuitType, request map[string]any) error {
	t.Helper()
	return test.IsSolved(extensionOf(t, key).Circuit(), decodeParams(t, key, request), ecc.BN254.ScalarField())
}

// The last hex digit moves the value and keeps it below the field.
func flipped(t *testing.T, value any) string {
	t.Helper()
	text, ok := value.(string)
	if !ok || len(text) != 66 {
		t.Fatalf("not a field: %v", value)
	}
	last := byte('1')
	if text[65] == '1' {
		last = '2'
	}
	return text[:65] + string(last)
}

func TestExactApprovalRequestsSolveAndAFalseDigestIsRefused(t *testing.T) {
	const predicate = "policy.Screening.AssertApprovalTotals"
	for _, name := range []string{"custom-ring-transfer-exact-approval", "custom-ring-transfer-relayed-exact-approval"} {
		t.Run(name, func(t *testing.T) {
			key, request := rustFixture(t, name)
			if err := solveRequest(t, key, request); err != nil {
				t.Fatalf("does not solve: %v", err)
			}
			for _, field := range []string{"approvalTotals", "approvalBlinder"} {
				key, request := rustFixture(t, name)
				request[field] = flipped(t, request[field])
				ringtest.RequireRefused(t, solveRequest(t, key, request), predicate)
			}
		})
	}
}

func TestAnonymousEntryRequestsSolve(t *testing.T) {
	for _, name := range []string{"custom-ring-transfer-anonymous-entry", "custom-ring-transfer-relayed-anonymous-entry"} {
		t.Run(name, func(t *testing.T) {
			key, request := rustFixture(t, name)
			if err := solveRequest(t, key, request); err != nil {
				t.Fatalf("does not solve: %v", err)
			}
		})
	}
}
