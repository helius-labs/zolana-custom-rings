package audit_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

// The stream and statement follow the one moved preimage.
func TestRecordPreimagesFailAtTheirPredicate(t *testing.T) {
	solve := func(s ringaudit.Audit) error {
		return test.IsSolved(ringaudit.NewSectionCircuit(plainShape), s.Circuit(t), ecc.BN254.ScalarField())
	}
	if err := solve(ringaudit.NewSection(t, plainShape)); err != nil {
		t.Fatal(err)
	}
	const ring, exit = 0, 2
	for name, c := range map[string]struct {
		mutate func(*ringaudit.Audit)
		frame  string
	}{
		"ring owner key": {func(s *ringaudit.Audit) { s.Outputs[ring].OwnerKey[0] ^= 1 }, "audit.RecordOpening.Encode"},
		"exit owner key": {func(s *ringaudit.Audit) { s.Outputs[exit].OwnerKey[0] ^= 1 }, "audit.RecordOpening.Encode"},
		"ring mint":      {func(s *ringaudit.Audit) { s.Outputs[ring].Mint[0] ^= 1 }, "audit.assertMint"},
		"exit mint":      {func(s *ringaudit.Audit) { s.Outputs[exit].Mint[0] ^= 1 }, "audit.assertMint"},
	} {
		t.Run(name, func(t *testing.T) {
			s := ringaudit.NewSection(t, plainShape)
			c.mutate(&s)
			err := solve(s)
			ringtest.RequireRefused(t, err, c.frame)
			// Encode calls assertMint, an owner key refusal stops above it.
			if c.frame != "audit.assertMint" && strings.Contains(err.Error(), "audit.assertMint") {
				t.Fatalf("refused at the mint: %v", err)
			}
		})
	}
}
