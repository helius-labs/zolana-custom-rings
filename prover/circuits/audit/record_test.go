package audit_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

var (
	plainShape = audit.StreamShape{InputClass: 2, Outputs: 4}
	dataShape  = audit.StreamShape{InputClass: 2, Outputs: 2}
	entryShape = audit.StreamShape{InputClass: 2, Outputs: 2, Entry: true}
)

// The statement over the edited stream names bytes the proof never sealed.
func refuseSealed(t *testing.T, s ringaudit.Audit, edit func(*ringaudit.Plaintexts)) {
	t.Helper()
	p := s.Plaintexts(t)
	edit(&p)
	compileSection(t, s.Shape).RefuseStatement(t, s.Circuit(t), s.StatementOf(t, s.Seal(t, p), s.Claim()))
}

func TestSectionSolvesEveryKeyShape(t *testing.T) {
	for _, shape := range []audit.StreamShape{plainShape, dataShape, entryShape} {
		s := ringaudit.NewSection(t, shape)
		compileSection(t, shape).RequireSolved(t, s.Circuit(t))
	}
	data := ringaudit.NewSection(t, dataShape)
	data.HasData = true
	compileSection(t, dataShape).RequireSolved(t, data.Circuit(t))
}

// Each byte range of a record is sealed from its slot, a stream naming another value fails the binding.
func TestEveryRecordFieldIsSealed(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	for name, offset := range map[string]int{"kind": 0, "amount": 8, "owner key": 9, "mint": 41, "nullifier key": 104} {
		t.Run(name, func(t *testing.T) {
			refuseSealed(t, s, func(p *ringaudit.Plaintexts) { p.Records[0][offset] ^= 1 })
		})
	}
}

// The auditor skips a slot by one byte, the byte is the slot's class under the proof.
func TestKindFollowsTheSlot(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	const ring, zeroKey, exit, dummy = 0, 1, 2, 3
	for name, edit := range map[string]func(*ringaudit.Plaintexts){
		"kind 0 on a live ring slot": func(p *ringaudit.Plaintexts) { p.Records[ring][0] = audit.KindDummy },
		"kind 1 on a dummy":          func(p *ringaudit.Plaintexts) { p.Records[dummy][0] = audit.KindRing },
		"kind 2 on a ring slot":      func(p *ringaudit.Plaintexts) { p.Records[zeroKey][0] = audit.KindExit },
		"kind 1 on an exit":          func(p *ringaudit.Plaintexts) { p.Records[exit][0] = audit.KindRing },
		"a dummy naming an owner":    func(p *ringaudit.Plaintexts) { p.Records[dummy][9] = 1 },
	} {
		t.Run(name, func(t *testing.T) { refuseSealed(t, s, edit) })
	}
}

func TestSlotPredicatesRefuseBeforeTheBinding(t *testing.T) {
	c := compileSection(t, plainShape)
	for name, mutate := range map[string]func(*ringaudit.Audit){
		"owner key off the slot's owner":      func(s *ringaudit.Audit) { s.Outputs[0].OwnerKey[0] ^= 1 },
		"exit owner key off the slot's owner": func(s *ringaudit.Audit) { s.Outputs[2].OwnerKey[0] ^= 1 },
		"mint off the slot's asset":           func(s *ringaudit.Audit) { s.Outputs[0].Mint[0] ^= 1 },
		"exit mint off the slot's asset":      func(s *ringaudit.Audit) { s.Outputs[2].Mint[0] ^= 1 },
		"blinding of another slot":            func(s *ringaudit.Audit) { s.Outputs[0].Utxo.Blinding = s.Blinding(t, 1) },
		"exit blinding off the sealed key":    func(s *ringaudit.Audit) { s.Outputs[2].Utxo.Blinding = big.NewInt(0x5ec) },
		"dummy blinding off the sealed key":   func(s *ringaudit.Audit) { s.Outputs[3].Utxo.Blinding = big.NewInt(0x5ec) },
		"asset no mint names":                 func(s *ringaudit.Audit) { s.Outputs[0].Utxo.Asset = big.NewInt(0xdead) },
	} {
		t.Run(name, func(t *testing.T) {
			s := ringaudit.NewSection(t, plainShape)
			mutate(&s)
			c.Refuse(t, s.Circuit(t))
		})
	}
}

// An omitted slot holds no note and drops out of the frame with its counters kept.
func TestCompactFrames(t *testing.T) {
	c := compileSection(t, plainShape)
	s := ringaudit.NewSection(t, plainShape).Omit(t, 1)
	c.RequireSolved(t, s.Circuit(t))
	full := ringaudit.NewSection(t, plainShape)
	if got, want := s.Stream(t).Record(1), full.Stream(t).Record(1); string(got) != string(want) {
		t.Fatal("a compact frame moved a published record")
	}
	t.Run("a note past the published count", func(t *testing.T) {
		live := ringaudit.NewSection(t, plainShape)
		live.Outputs[3] = live.RingNote(t, 3, ringaudit.RingOwnerKey, ringaudit.EnrolledNullifierPk(t), 5)
		live.Omitted = 1
		c.Refuse(t, live.Circuit(t))
	})
	t.Run("a published count of zero", func(t *testing.T) {
		zero := ringaudit.NewSection(t, plainShape)
		zero.Omitted = len(zero.Outputs)
		for i := range zero.Outputs {
			zero.Outputs[i] = ringaudit.Slot{Utxo: ringaudit.Dummy(0, big.NewInt(0))}
		}
		c.Refuse(t, zero.Circuit(t))
	})
}

// An unclamped alias of one tx_u derives other blindings.
func TestSealedKeyStaysClamped(t *testing.T) {
	c := compileSection(t, plainShape)
	s := ringaudit.NewSection(t, plainShape)
	raw := ringtest.Scalar(0x11)
	s.Transfer = s.Transfer.WithKeys(t, s.Keys.WithRawTxScalar(t, raw))
	if ringprotocol.Clamped(raw) == raw {
		t.Fatal("the fixture scalar is already clamped")
	}
	c.Refuse(t, s.Circuit(t))
}

// A live amount at or above 2^64 has no record bytes.
func TestAmountStaysBelowTwoTo64(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	circuit := s.Circuit(t)
	circuit.Outputs[0].Output.Amount = new(big.Int).Lsh(big.NewInt(1), 64)
	compileSection(t, plainShape).Refuse(t, circuit)
}
