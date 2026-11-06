package audit_test

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func addressInput() ringaudit.Input {
	input := ringaudit.Input{Utxo: ringaudit.Dummy(0, big.NewInt(31))}
	input.Utxo.Domain = transaction.AddressDomain
	return input
}

func TestAddressOnlyInputsSetNoSpend(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape).Spending(t, 0)
	s.Inputs[0] = addressInput()
	s.InputCount = 1
	c := compileSection(t, plainShape)
	c.RequireSolved(t, s.Circuit(t))
	if !s.Claim().NoSpend {
		t.Fatal("address input cleared no_spend")
	}
	plaintext := s.Keys.Open(t, s.Stream(t))
	if plaintext[audit.EnvelopeKeyLen] != 0 {
		t.Fatal("address input counted as a note")
	}
	start := audit.EnvelopeKeyLen + audit.RealInputCountLen
	if binary.BigEndian.Uint64(plaintext[start:start+audit.AddressInputBitsLen]) != 1 {
		t.Fatal("address input is absent from the bitmap")
	}
	claim := s.Claim()
	claim.NoSpend = false
	c.RefuseStatement(t, s.Circuit(t), s.StatementOf(t, s.Stream(t), claim))
}

func TestInputMapsBindAbsolutePositions(t *testing.T) {
	shape := audit.StreamShape{InputClass: 4, Outputs: 2, Entry: true}
	s := ringaudit.NewSection(t, shape)
	s.Inputs[2] = s.Inputs[1]
	s.Inputs[1] = addressInput()
	s.InputCount = 4
	c := compileSection(t, shape)
	c.RequireSolved(t, s.Circuit(t))
	plaintext := s.Keys.Open(t, s.Stream(t))
	addressStart := audit.EnvelopeKeyLen + audit.RealInputCountLen
	defaultStart := addressStart + audit.AddressInputBitsLen
	if plaintext[audit.EnvelopeKeyLen] != 2 {
		t.Fatal("interleaved note count differs")
	}
	addresses := binary.BigEndian.Uint64(plaintext[addressStart:defaultStart])
	defaults := binary.BigEndian.Uint64(plaintext[defaultStart : defaultStart+audit.DefaultInputBitsLen])
	if addresses != 0b0010 || defaults != 0b0100 {
		t.Fatalf("unexpected input maps %b %b", addresses, defaults)
	}
	for _, tc := range []struct {
		name  string
		start int
		bits  uint64
	}{
		{"address bit cleared", addressStart, 0},
		{"address bit on note", addressStart, 0b0001},
		{"address bit on padding", addressStart, 0b1010},
		{"address bit past published inputs", addressStart, 0b10010},
		{"default bit on address", defaultStart, 0b0110},
		{"default bit on padding", defaultStart, 0b1100},
		{"default bit moved", defaultStart, 0b0001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuseSealed(t, s, func(p *ringaudit.Plaintexts) {
				binary.BigEndian.PutUint64(p.Envelope[tc.start:], tc.bits)
			})
		})
	}
	claim := s.Claim()
	claim.NoSpend = true
	c.RefuseStatement(t, s.Circuit(t), s.StatementOf(t, s.Stream(t), claim))
}

func TestInputMapRefusesWitnessClassChangeWithSealedEvidence(t *testing.T) {
	shape := audit.StreamShape{InputClass: 4, Outputs: 2}
	s := ringaudit.NewSection(t, shape).Spending(t, 2)
	s.Inputs[2] = s.Inputs[1]
	s.Inputs[1] = addressInput()
	s.InputCount = 3
	assignment := s.Circuit(t)
	circuit := ringaudit.NewSectionCircuit(shape)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	assignment.Inputs[2].Domain = transaction.AddressDomain
	ringtest.RequireRefused(t, test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()), "ringaudit.(*SectionCircuit).Define")
}
