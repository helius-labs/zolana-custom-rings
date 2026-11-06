package audit_test

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// SPP's addresses reach the ring through the address chain alone, no input slot opens one.
func TestAnInputSlotHoldsANoteOrADummy(t *testing.T) {
	c := compileSection(t, plainShape)
	honest := ringaudit.NewSection(t, plainShape).Spending(t, 2)
	honest.InputCount = 2
	c.RequireSolved(t, honest.Circuit(t))
	t.Run("an address in an input slot", func(t *testing.T) {
		s := ringaudit.NewSection(t, plainShape).Spending(t, 0)
		s.Inputs[0].Utxo.Domain = transaction.AddressDomain
		c.Refuse(t, s.Circuit(t))
	})
	t.Run("a note after a dummy", func(t *testing.T) {
		s := ringaudit.NewSection(t, plainShape).Spending(t, 1)
		s.Inputs[0], s.Inputs[1] = s.Inputs[1], s.Inputs[0]
		s.InputCount = 2
		c.Refuse(t, s.Circuit(t))
	})
	t.Run("a note at or past the published count", func(t *testing.T) {
		s := ringaudit.NewSection(t, plainShape).Spending(t, 2)
		s.InputCount = 1
		c.Refuse(t, s.Circuit(t))
	})
}

// Entry records follow note order, the default bit of note k names entry record k.
func TestEntryRecordsFollowNoteOrder(t *testing.T) {
	shape := audit.StreamShape{InputClass: 4, Outputs: 2, Entry: true}
	c := compileSection(t, shape)
	s := ringaudit.NewSection(t, shape)
	s.Inputs[0], s.Inputs[1] = s.Inputs[1], s.Inputs[0]
	c.RequireSolved(t, s.Circuit(t))
	_, bits := s.Reader().Envelope(t, s.Stream(t))
	if bits != 0b01 {
		t.Fatalf("default bits %b, the default note leads", bits)
	}
	head := s.Shape.Ranges().EnvelopeHeadLen() - audit.DefaultInputBitsLen
	for name, bits := range map[string]uint64{"bit on the ring note": 0b10, "bit on a dummy": 0b101, "bit cleared": 0} {
		t.Run(name, func(t *testing.T) {
			refuseSealed(t, s, func(p *ringaudit.Plaintexts) { binary.BigEndian.PutUint64(p.Envelope[head:], bits) })
		})
	}
}

// The ring holds its own outputs to SPP's form, so ring slot i is SPP slot i with no output_chain element.
func TestOutputSlotsKeepSppForm(t *testing.T) {
	c := compileSection(t, plainShape)
	const zeroKey, exit, dummy = 1, 2, 3
	c.RequireSolved(t, ringaudit.NewSection(t, plainShape).Circuit(t))
	for name, mutate := range map[string]func(*ringaudit.Audit){
		"a dummy before a note": func(s *ringaudit.Audit) {
			s.Outputs[exit], s.Outputs[dummy] = s.Outputs[dummy], s.Outputs[exit]
		},
		"an address output":        func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.Domain = transaction.AddressDomain },
		"a dummy with an amount":   func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.Amount = 1 },
		"a dummy with an asset":    func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.Asset = big.NewInt(1) },
		"a dummy with a data hash": func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.DataHash = big.NewInt(1) },
		"a dummy with a ring data": func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.RingDataHash = big.NewInt(1) },
		"a dummy with a ring id":   func(s *ringaudit.Audit) { s.Outputs[dummy].Utxo.RingProgramID = big.NewInt(1) },
		"an unknown output domain": func(s *ringaudit.Audit) { s.Outputs[zeroKey].Utxo.Domain = 7 },
		"a note past the published": func(s *ringaudit.Audit) {
			s.Omitted = 1
			s.Outputs[dummy] = s.RingNote(t, dummy, ringaudit.RingOwnerKey, ringaudit.ZeroKey(t), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := ringaudit.NewSection(t, plainShape)
			mutate(&s)
			c.Refuse(t, s.Circuit(t))
		})
	}
}
