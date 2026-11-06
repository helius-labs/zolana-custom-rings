package audit_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

var (
	plainShape = audit.StreamShape{InputClass: 2, Outputs: 4}
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
	for _, shape := range []audit.StreamShape{plainShape, entryShape} {
		s := ringaudit.NewSection(t, shape)
		compileSection(t, shape).RequireSolved(t, s.Circuit(t))
	}
}

// Each byte range of a record is sealed from its slot, a stream naming another value fails the binding.
func TestEveryRecordFieldIsSealed(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	for name, offset := range map[string]int{"kind": 0, "amount": 8, "owner key": 9, "mint": 41, "nullifier key": 104, "blinding": 136} {
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
			zero.Outputs[i] = ringaudit.Slot{Utxo: ringaudit.Dummy(0, big.NewInt(0)), RecipientKey: ringaudit.ViewingKey(t, 1)}
		}
		c.Refuse(t, zero.Circuit(t))
	})
}

// Each record is sealed to the recipient key the auditor stream seals, under its own slot secret.
func TestRecordsAreSealedToTheSealedRecipientKey(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	t.Run("the recipient opens its record", func(t *testing.T) {
		stream := s.Stream(t)
		record := ringprotocol.SealRecord(t, s.Keys.TxViewingSk(), ringaudit.ViewingKey(t, 0), s.Salt, 0, s.FirstNullifier, shared.OutputRecordInfo, stream.Record(0))
		if string(record) != string(s.Outputs[0].Record(t)) {
			t.Fatal("the record differs from the slot's opening")
		}
	})
	t.Run("a record sealed to a key the stream does not name", func(t *testing.T) {
		refuseSealed(t, s, func(p *ringaudit.Plaintexts) { p.SealedTo[0] = ringaudit.ViewingKey(t, 9) })
	})
	t.Run("a stream naming a key the record is not sealed to", func(t *testing.T) {
		refuseSealed(t, s, func(p *ringaudit.Plaintexts) { p.RecipientKeys[0] = ringaudit.ViewingKey(t, 9) })
	})
	t.Run("another slot's record", func(t *testing.T) {
		refuseSealed(t, s, func(p *ringaudit.Plaintexts) { p.Records[1] = p.Records[0] })
	})
	t.Run("a dummy's key moved to a recipient's", func(t *testing.T) {
		refuseSealed(t, s, func(p *ringaudit.Plaintexts) {
			p.RecipientKeys[0], p.SealedTo[0] = p.RecipientKeys[3], p.RecipientKeys[3]
		})
	})
	// The agreement gadget refuses a key with no agreement, a record under it opens for anyone.
	for name, key := range map[string][32]byte{"a zero key": {}, "a key at p": noncanonicalKey()} {
		t.Run(name, func(t *testing.T) {
			circuit := s.Circuit(t)
			ringtest.SetBytes(circuit.Outputs[0].RecipientKey[:], key[:])
			ringtest.RequireRefused(t, test.IsSolved(ringaudit.NewSectionCircuit(plainShape), circuit, ecc.BN254.ScalarField()), "shared.SlotSeal.Seal")
		})
	}
}

// noncanonicalKey is p = 2^255 - 19 little endian, the encoding of zero past the field.
func noncanonicalKey() [32]byte {
	var key [32]byte
	key[0] = 0xed
	for i := 1; i < 31; i++ {
		key[i] = 0xff
	}
	key[31] = 0x7f
	return key
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
