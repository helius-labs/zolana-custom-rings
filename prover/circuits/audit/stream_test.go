package audit_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestRealInputCountIsSealed(t *testing.T) {
	c := compileSection(t, plainShape)
	s := ringaudit.NewSection(t, plainShape).Spending(t, 2)
	s.InputCount = 2
	c.RequireSolved(t, s.Circuit(t))
	realInputs, _ := s.Reader().Envelope(t, s.Stream(t))
	if realInputs != 2 {
		t.Fatalf("the reader read R = %d", realInputs)
	}
	for name, count := range map[string]byte{"one less": 1, "one more": 3} {
		t.Run(name, func(t *testing.T) {
			refuseSealed(t, s, func(p *ringaudit.Plaintexts) { p.Envelope[audit.EnvelopeKeyLen] = count })
		})
	}
}

func TestNoSpendEqualsAZeroCount(t *testing.T) {
	c := compileSection(t, plainShape)
	padded := ringaudit.NewSection(t, plainShape).Spending(t, 0)
	c.RequireSolved(t, padded.Circuit(t))
	if !padded.Claim().NoSpend {
		t.Fatal("no live input leaves no_spend clear")
	}
	if realInputs, _ := padded.Reader().Envelope(t, padded.Stream(t)); realInputs != 0 {
		t.Fatalf("the reader read R = %d", realInputs)
	}
	t.Run("no_spend with a live input", func(t *testing.T) {
		s := ringaudit.NewSection(t, plainShape)
		claim := s.Claim()
		claim.NoSpend = true
		c.RefuseStatement(t, s.Circuit(t), s.StatementOf(t, s.Stream(t), claim))
	})
	t.Run("no_spend clear with no live input", func(t *testing.T) {
		claim := padded.Claim()
		claim.NoSpend = false
		c.RefuseStatement(t, padded.Circuit(t), padded.StatementOf(t, padded.Stream(t), claim))
	})
}

func TestDefaultInputNeedsEntryCapacity(t *testing.T) {
	c := compileSection(t, plainShape)
	s := ringaudit.NewSection(t, plainShape)
	s.Inputs[0].Utxo.RingProgramID = big.NewInt(0)
	c.Refuse(t, s.Circuit(t))
}

func TestDefaultBitsAndRecordsFollowTheSlots(t *testing.T) {
	c := compileSection(t, entryShape)
	s := ringaudit.NewSection(t, entryShape)
	realInputs, bits := s.Reader().Envelope(t, s.Stream(t))
	if realInputs != 2 || bits != 0b10 {
		t.Fatalf("the reader read R = %d, default bits %b", realInputs, bits)
	}
	head := s.Shape.Ranges().EnvelopeHeadLen() - audit.DefaultInputBitsLen
	records := head + audit.DefaultInputBitsLen
	entry := records + audit.EntryRecordLen
	ringCommitment := spptest.MustFieldBytes(t, s.Inputs[0].Utxo.Hash(t))
	for name, edit := range map[string]func(*ringaudit.Plaintexts){
		"default bit cleared":        func(p *ringaudit.Plaintexts) { p.Envelope[head+7] = 0 },
		"default bit on a ring note": func(p *ringaudit.Plaintexts) { p.Envelope[head+7] = 0b11 },
		"record on a ring input":     func(p *ringaudit.Plaintexts) { p.Envelope[records] = 1 },
		"another owner key byte":     func(p *ringaudit.Plaintexts) { p.Envelope[entry] ^= 1 },
		"another nullifier key":      func(p *ringaudit.Plaintexts) { p.Envelope[entry+63] ^= 1 },
		"another amount":             func(p *ringaudit.Plaintexts) { p.Envelope[entry+71] ^= 1 },
		"another mint byte":          func(p *ringaudit.Plaintexts) { p.Envelope[entry+103] ^= 1 },
		"another commitment":         func(p *ringaudit.Plaintexts) { p.Envelope[entry+135] ^= 1 },
		"the ring input's commitment": func(p *ringaudit.Plaintexts) {
			copy(p.Envelope[entry+104:entry+audit.EntryRecordLen], ringCommitment[:])
		},
		"records and bits swapped to input 0": func(p *ringaudit.Plaintexts) {
			first := bytes.Clone(p.Envelope[records:entry])
			copy(p.Envelope[records:entry], p.Envelope[entry:entry+audit.EntryRecordLen])
			copy(p.Envelope[entry:entry+audit.EntryRecordLen], first)
			p.Envelope[head+7] = 0b01
		},
	} {
		t.Run(name, func(t *testing.T) { refuseSealed(t, s, edit) })
	}
	for name, mutate := range map[string]func(*ringaudit.Audit){
		"record naming another owner": func(s *ringaudit.Audit) { s.Inputs[1].OwnerKey[0] ^= 1 },
		"record naming another mint":  func(s *ringaudit.Audit) { s.Inputs[1].Mint[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s := ringaudit.NewSection(t, entryShape)
			mutate(&s)
			c.Refuse(t, s.Circuit(t))
		})
	}
}

// A resend repeats the sealing key, the salt alone keeps its keystream from repeating.
func TestResendUnderAnotherSaltSealsAnotherStream(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	first := s.Stream(t)
	s.Salt[0] ^= 1
	if bytes.Equal(first.Ciphertext, s.Stream(t).Ciphertext) {
		t.Fatal("two salts sealed one stream")
	}
	t.Run("a stream sealed under another salt fails the binding", func(t *testing.T) {
		honest, resent := ringaudit.NewSection(t, plainShape), ringaudit.NewSection(t, plainShape)
		resent.Salt[0] ^= 1
		compileSection(t, plainShape).RefuseStatement(t, honest.Circuit(t), honest.StatementOf(t, resent.Stream(t), honest.Claim()))
	})
}

func TestEntryRecordsServeMixedOwners(t *testing.T) {
	c := compileSection(t, entryShape)
	s := ringaudit.NewSection(t, entryShape)
	other := ringtest.Repeat(0xa3)
	s.Inputs[0] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtest.MustSolanaPkField(t, other), spptest.MustNullifierPk(t, big.NewInt(9)), big.NewInt(0), 30, 53), OwnerKey: other, Mint: ringaudit.FixtureMint}
	c.RequireSolved(t, s.Circuit(t))
	plaintext := s.Keys.Open(t, s.Stream(t))
	head := s.Shape.Ranges().EnvelopeHeadLen()
	if !bytes.Equal(plaintext[head:head+32], other[:]) || !bytes.Equal(plaintext[head+audit.EntryRecordLen:head+audit.EntryRecordLen+32], ringaudit.DefaultOwnerKey[:]) {
		t.Fatal("an entry record names another owner")
	}
}

// Data hashes stay private, bound by the commitment alone, and no layout bit opens them.
func TestDataHashesNeedNoLayoutBit(t *testing.T) {
	c := compileSection(t, plainShape)
	s := ringaudit.NewSection(t, plainShape)
	s.Outputs[0].Utxo.DataHash = big.NewInt(0xda7a)
	s.Outputs[0].Utxo.RingDataHash = big.NewInt(0x5ca1e)
	c.RequireSolved(t, s.Circuit(t))
	t.Run("bit 0", func(t *testing.T) {
		circuit := s.Circuit(t)
		circuit.Layout = 1
		c.Refuse(t, circuit)
	})
}

func TestLayoutIsTheKeys(t *testing.T) {
	refuse := func(t *testing.T, shape audit.StreamShape, layout int) {
		t.Helper()
		s := ringaudit.NewSection(t, shape)
		circuit := s.Circuit(t)
		circuit.Layout = layout
		compileSection(t, shape).Refuse(t, circuit)
	}
	t.Run("entry on a key with no entry capacity", func(t *testing.T) { refuse(t, plainShape, audit.LayoutEntry) })
	t.Run("no entry on an entry key", func(t *testing.T) { refuse(t, entryShape, 0) })
	t.Run("a bit past the flags", func(t *testing.T) { refuse(t, plainShape, 1<<2) })
	t.Run("bit 0 on an entry key", func(t *testing.T) { refuse(t, entryShape, audit.LayoutEntry|1) })
}

// The reader rebuilds every slot with no mint registry.
func TestReaderRebuildsEverySlot(t *testing.T) {
	for _, shape := range []audit.StreamShape{plainShape, entryShape} {
		s := ringaudit.NewSection(t, shape)
		stream, hashes, reader := s.Stream(t), s.PublishedHashes(t), s.Reader()
		for i, hash := range hashes {
			note, err := reader.Read(t, stream, i, hash)
			if err != nil {
				t.Fatalf("%+v slot %d: %v", shape, i, err)
			}
			if !s.Outputs[i].Utxo.IsUtxo() {
				if note != nil {
					t.Fatalf("%+v slot %d: a dummy read as a note", shape, i)
				}
				continue
			}
			if note == nil || note.Hash.Cmp(hash) != 0 || note.Blinding.Cmp(s.Outputs[i].Utxo.Blinding) != 0 {
				t.Fatalf("%+v slot %d: read %+v", shape, i, note)
			}
		}
	}
}

// The auditor never saw a default-ring note, its record names the note and the commitment SPP spends.
func TestReaderReadsADefaultInput(t *testing.T) {
	s := ringaudit.NewSection(t, entryShape)
	s.Inputs[1].Utxo.DataHash = big.NewInt(0xda7a)
	s.Inputs[1].Utxo.RingDataHash = big.NewInt(0x5ca1e)
	compileSection(t, entryShape).RequireSolved(t, s.Circuit(t))
	stream, reader, spent := s.Stream(t), s.Reader(), s.Inputs[1].Utxo
	entry, err := reader.ReadEntry(t, stream, 1, spent.Hash(t))
	if err != nil || entry == nil {
		t.Fatalf("read %+v, %v", entry, err)
	}
	if entry.OwnerKey != ringaudit.DefaultOwnerKey || entry.NullifierPk.Cmp(spent.NullifierPk) != 0 || entry.Amount != spent.Amount || entry.Mint != ringaudit.FixtureMint {
		t.Fatalf("read %+v", entry)
	}
	if entry, err := reader.ReadEntry(t, stream, 0, s.Inputs[0].Utxo.Hash(t)); err != nil || entry != nil {
		t.Fatalf("a ring input read as an entry %+v, %v", entry, err)
	}
	if _, err := reader.ReadEntry(t, stream, 1, big.NewInt(0xdead)); err == nil {
		t.Fatal("the reader accepted a commitment the record does not name")
	}
}

// The record names each slot's key, the reader tries none.
func TestZeroAndEnrolledKeysReadApart(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	stream, hashes, reader := s.Stream(t), s.PublishedHashes(t), s.Reader()
	enrolled, err := reader.Read(t, stream, 0, hashes[0])
	if err != nil {
		t.Fatal(err)
	}
	zero, err := reader.Read(t, stream, 1, hashes[1])
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.NullifierPk.Cmp(ringaudit.EnrolledNullifierPk(t)) != 0 || zero.NullifierPk.Cmp(ringaudit.ZeroKey(t)) != 0 {
		t.Fatalf("read keys %x and %x", enrolled.NullifierPk, zero.NullifierPk)
	}
}

// The slot index enters the slot secret, a record moved to another slot decrypts to noise.
func TestRecordAtAnotherSlotFailsTheReader(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	stream := s.Stream(t)
	moved := stream
	moved.Records = slices.Clone(stream.Records)
	moved.Records[1] = stream.Record(0)
	if note, err := s.Reader().Read(t, moved, 1, s.Outputs[0].Utxo.Hash(t)); err == nil {
		t.Fatalf("a moved record read as %+v", note)
	}
	compileSection(t, plainShape).RefuseStatement(t, s.Circuit(t), s.StatementOf(t, moved, s.Claim()))
}

func TestStreamVector(t *testing.T) {
	type vectorCase struct {
		Name          string   `json:"name"`
		Layout        int64    `json:"layout"`
		InputClass    int      `json:"input_class"`
		Outputs       int      `json:"outputs"`
		OutputCount   int      `json:"output_count"`
		InputCount    int      `json:"input_count"`
		Envelope      string   `json:"envelope_plaintext"`
		EnvelopeCt    string   `json:"envelope_ciphertext"`
		RecipientKeys []string `json:"recipient_keys"`
		KeysCt        string   `json:"recipient_keys_ciphertext"`
		Records       []string `json:"records"`
		RecordCts     []string `json:"record_ciphertexts"`
		OutputHashes  []string `json:"output_hashes"`
		Blindings     []string `json:"blindings"`
		EnvelopeHash  string   `json:"envelope_digest"`
		RecordChain   string   `json:"record_chain"`
	}
	data := ringaudit.NewSection(t, plainShape)
	data.Outputs[0].Utxo.DataHash = big.NewInt(0xda7a)
	data.Outputs[0].Utxo.RingDataHash = big.NewInt(0x5ca1e)
	defaultFirst := ringaudit.NewSection(t, audit.StreamShape{InputClass: 4, Outputs: 2, Entry: true})
	defaultFirst.Inputs[0], defaultFirst.Inputs[1] = defaultFirst.Inputs[1], defaultFirst.Inputs[0]
	sections := []struct {
		name    string
		section ringaudit.Audit
	}{
		{"plain_with_exit_and_dummy", ringaudit.NewSection(t, plainShape)},
		{"compact", ringaudit.NewSection(t, plainShape).Omit(t, 1)},
		{"data", data},
		{"entry", ringaudit.NewSection(t, entryShape)},
		{"no_spend", ringaudit.NewSection(t, plainShape).Spending(t, 0)},
		{"entry_default_first", defaultFirst},
	}
	cases := make([]vectorCase, len(sections))
	for k, tc := range sections {
		s := tc.section
		compileSection(t, s.Shape).RequireSolved(t, s.Circuit(t))
		p, stream := s.Plaintexts(t), s.Stream(t)
		v := vectorCase{
			Name: tc.name, Layout: s.Layout(), InputClass: s.Shape.InputClass, Outputs: s.Shape.Outputs, OutputCount: s.OutputCount(), InputCount: s.InputCount,
			Envelope: hex.EncodeToString(p.Envelope), EnvelopeCt: hex.EncodeToString(stream.Envelope(s.InputCount)),
			KeysCt:       hex.EncodeToString(stream.Keys(s.OutputCount())),
			EnvelopeHash: ringtest.FieldHex(s.StatementOf(t, stream, s.Claim())[7]),
			RecordChain:  ringtest.FieldHex(ringaudit.RecordChain(t, s.StatementOutputs(t, stream))),
		}
		for i := range s.OutputCount() {
			v.RecipientKeys = append(v.RecipientKeys, hex.EncodeToString(p.RecipientKeys[i][:]))
			v.Records = append(v.Records, hex.EncodeToString(p.Records[i]))
			v.RecordCts = append(v.RecordCts, hex.EncodeToString(stream.Record(i)))
			v.OutputHashes = append(v.OutputHashes, ringtest.FieldHex(s.Outputs[i].Utxo.Hash(t)))
			v.Blindings = append(v.Blindings, ringtest.FieldHex(s.Blinding(t, i)))
		}
		cases[k] = v
	}
	txViewingSk, auditorSk := sections[0].section.Keys.TxViewingSk(), ringaudit.AuditorSk()
	ringtest.PinVector(t, "audit/audit-stream.json", map[string]any{
		"description":     "Auditor streams under CRING/adt and output records under CRING/rcp and each slot's delivered secret, from solved witnesses.",
		"tx_viewing_sk":   hex.EncodeToString(txViewingSk[:]),
		"auditor_sk":      hex.EncodeToString(auditorSk[:]),
		"salt":            hex.EncodeToString(sections[0].section.Salt[:]),
		"first_nullifier": ringtest.FieldHex(sections[0].section.FirstNullifier),
		"ring_id":         ringtest.FieldHex(sections[0].section.RingProgramID),
		"output_tree_id":  ringaudit.OutputTreeID,
		"cases":           cases,
	})
}
