package audit_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
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

func TestDefaultBitsAndEvidenceFollowTheSlots(t *testing.T) {
	c := compileSection(t, entryShape)
	s := ringaudit.NewSection(t, entryShape)
	realInputs, bits := s.Reader().Envelope(t, s.Stream(t))
	if realInputs != 2 || bits != 0b10 {
		t.Fatalf("the reader read R = %d, default bits %b", realInputs, bits)
	}
	head := s.Shape.Ranges().EnvelopeHeadLen() - audit.DefaultInputBitsLen
	for name, edit := range map[string]func(*ringaudit.Plaintexts){
		"default bit cleared":        func(p *ringaudit.Plaintexts) { p.Envelope[head+7] = 0 },
		"default bit on a ring note": func(p *ringaudit.Plaintexts) { p.Envelope[head+7] = 0b11 },
		"evidence on a ring input":   func(p *ringaudit.Plaintexts) { p.Envelope[head+audit.DefaultInputBitsLen] = 1 },
		"another evidence amount": func(p *ringaudit.Plaintexts) {
			p.Envelope[head+audit.DefaultInputBitsLen+audit.EntryInputLen+71] ^= 1
		},
		"another evidence blinding": func(p *ringaudit.Plaintexts) {
			p.Envelope[head+audit.DefaultInputBitsLen+audit.EntryInputLen+135] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) { refuseSealed(t, s, edit) })
	}
	for name, mutate := range map[string]func(*ringaudit.Audit){
		"evidence naming another owner": func(s *ringaudit.Audit) { s.Inputs[1].OwnerKey[0] ^= 1 },
		"evidence naming another mint":  func(s *ringaudit.Audit) { s.Inputs[1].Mint[0] ^= 1 },
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

func TestEntryEvidenceServesMixedOwners(t *testing.T) {
	c := compileSection(t, entryShape)
	s := ringaudit.NewSection(t, entryShape)
	other := ringtest.Repeat(0xa3)
	s.Inputs[0] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtest.MustSolanaPkField(t, other), spptest.MustNullifierPk(t, big.NewInt(9)), big.NewInt(0), 30, 53), OwnerKey: other, Mint: ringaudit.FixtureMint}
	c.RequireSolved(t, s.Circuit(t))
	plaintext := s.Keys.Open(t, s.Stream(t))
	head := s.Shape.Ranges().EnvelopeHeadLen()
	if !bytes.Equal(plaintext[head:head+32], other[:]) || !bytes.Equal(plaintext[head+audit.EntryInputLen:head+audit.EntryInputLen+32], ringaudit.DefaultOwnerKey[:]) {
		t.Fatal("an evidence entry names another owner")
	}
}

func TestDataTails(t *testing.T) {
	c := compileSection(t, dataShape)
	withData := func(t *testing.T) ringaudit.Audit {
		t.Helper()
		s := ringaudit.NewSection(t, dataShape)
		s.HasData = true
		s.Outputs[0].Utxo.DataHash = big.NewInt(0xda7a)
		s.Outputs[0].Utxo.RingDataHash = big.NewInt(0x5ca1e)
		return s
	}
	t.Run("a data output reads back", func(t *testing.T) {
		s := withData(t)
		c.RequireSolved(t, s.Circuit(t))
		note, err := s.Reader().Read(t, s.Stream(t), 0, s.Outputs[0].Utxo.Hash(t))
		if err != nil || note == nil {
			t.Fatalf("the reader refused a data output: %v", err)
		}
	})
	for name, edit := range map[string]func(*ringaudit.Plaintexts){
		"another data hash":      func(p *ringaudit.Plaintexts) { p.Tails[0][31] ^= 1 },
		"another ring data hash": func(p *ringaudit.Plaintexts) { p.Tails[0][63] ^= 1 },
		"a dummy's tail":         func(p *ringaudit.Plaintexts) { p.Tails[1][0] = 1 },
	} {
		t.Run(name, func(t *testing.T) { refuseSealed(t, withData(t), edit) })
	}
	for name, mutate := range map[string]func(*ringaudit.Audit){
		"data hash with has_data clear":      func(s *ringaudit.Audit) { s.Outputs[0].Utxo.DataHash = big.NewInt(5) },
		"ring data hash with has_data clear": func(s *ringaudit.Audit) { s.Outputs[0].Utxo.RingDataHash = big.NewInt(5) },
	} {
		t.Run(name, func(t *testing.T) {
			s := ringaudit.NewSection(t, dataShape)
			mutate(&s)
			c.Refuse(t, s.Circuit(t))
		})
	}
	t.Run("a clear has_data keeps tails off the frame", func(t *testing.T) {
		s := ringaudit.NewSection(t, dataShape)
		if outputs := s.StatementOutputs(t, s.Stream(t)); outputs[0].Tail != nil {
			t.Fatal("a frame with has_data clear transmits a tail")
		}
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

// The auditor never saw a default-ring note, its evidence alone rebuilds the commitment SPP spends.
func TestReaderRebuildsADefaultInput(t *testing.T) {
	s := ringaudit.NewSection(t, entryShape)
	s.Inputs[1].Utxo.DataHash = big.NewInt(0xda7a)
	s.Inputs[1].Utxo.RingDataHash = big.NewInt(0x5ca1e)
	compileSection(t, entryShape).RequireSolved(t, s.Circuit(t))
	stream, reader, tree := s.Stream(t), s.Reader(), s.Inputs[1].Utxo.TreeID
	note, err := reader.ReadEntry(t, stream, 1, tree, s.Inputs[1].Utxo.Hash(t))
	if err != nil || note == nil || note.Amount != s.Inputs[1].Utxo.Amount {
		t.Fatalf("read %+v, %v", note, err)
	}
	if note, err := reader.ReadEntry(t, stream, 0, tree, s.Inputs[0].Utxo.Hash(t)); err != nil || note != nil {
		t.Fatalf("a ring input read as evidence %+v, %v", note, err)
	}
	moved := big.NewInt(0xdead)
	if _, err := reader.ReadEntry(t, stream, 1, tree, moved); err == nil {
		t.Fatal("the reader accepted a commitment the evidence does not rebuild")
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

// Counters fix a record to its index, its bytes at another slot decrypt to noise or rebuild no commitment.
func TestRecordAtAnotherSlotFailsTheReader(t *testing.T) {
	s := ringaudit.NewSection(t, plainShape)
	stream := s.Stream(t)
	moved := ringaudit.Stream{Ranges: stream.Ranges, Ciphertext: bytes.Clone(stream.Ciphertext)}
	copy(moved.Ciphertext[stream.Ranges.RecordOffset(1):], stream.Record(0))
	if note, err := s.Reader().Read(t, moved, 1, s.Outputs[1].Utxo.Hash(t)); err == nil {
		t.Fatalf("a moved record read as %+v", note)
	}
	// The same plaintext sealed at the wrong counter names the right fields under the wrong blinding.
	p := s.Plaintexts(t)
	p.Records[1] = s.Outputs[0].Record(t)
	if note, err := s.Reader().Read(t, s.Seal(t, p), 1, s.Outputs[0].Utxo.Hash(t)); err == nil {
		t.Fatalf("a record read at another index as %+v", note)
	}
	compileSection(t, plainShape).RefuseStatement(t, s.Circuit(t), s.StatementOf(t, s.Seal(t, p), s.Claim()))
}

func TestStreamVector(t *testing.T) {
	type vectorCase struct {
		Name         string   `json:"name"`
		Layout       int64    `json:"layout"`
		InputClass   int      `json:"input_class"`
		Outputs      int      `json:"outputs"`
		OutputCount  int      `json:"output_count"`
		InputCount   int      `json:"input_count"`
		Envelope     string   `json:"envelope_plaintext"`
		EnvelopeCt   string   `json:"envelope_ciphertext"`
		Records      []string `json:"records"`
		RecordCts    []string `json:"record_ciphertexts"`
		Tails        []string `json:"tails"`
		TailCts      []string `json:"tail_ciphertexts"`
		OutputHashes []string `json:"output_hashes"`
		Blindings    []string `json:"blindings"`
		EnvelopeHash string   `json:"envelope_digest"`
		RecordChain  string   `json:"record_chain"`
		TailChain    string   `json:"tail_chain"`
	}
	data := ringaudit.NewSection(t, dataShape)
	data.HasData = true
	data.Outputs[0].Utxo.DataHash = big.NewInt(0xda7a)
	data.Outputs[0].Utxo.RingDataHash = big.NewInt(0x5ca1e)
	addressOnly := ringaudit.NewSection(t, plainShape).Spending(t, 0)
	addressOnly.Inputs[0] = addressInput()
	addressOnly.InputCount = 1
	interleaved := ringaudit.NewSection(t, audit.StreamShape{InputClass: 4, Outputs: 2}).Spending(t, 2)
	interleaved.Inputs[2] = interleaved.Inputs[1]
	interleaved.Inputs[1] = addressInput()
	interleaved.InputCount = 4
	interleavedEntry := ringaudit.NewSection(t, audit.StreamShape{InputClass: 4, Outputs: 2, Entry: true})
	interleavedEntry.Inputs[2] = interleavedEntry.Inputs[1]
	interleavedEntry.Inputs[1] = addressInput()
	interleavedEntry.InputCount = 4
	sections := []struct {
		name    string
		section ringaudit.Audit
	}{
		{"plain_with_exit_and_dummy", ringaudit.NewSection(t, plainShape)},
		{"single_asset_payout", ringaudit.NewSection(t, audit.StreamShape{InputClass: 1, Outputs: 16, SingleAssetPayout: true})},
		{"compact", ringaudit.NewSection(t, plainShape).Omit(t, 1)},
		{"data", data},
		{"entry", ringaudit.NewSection(t, entryShape)},
		{"address_only", addressOnly},
		{"interleaved", interleaved},
		{"interleaved_entry", interleavedEntry},
	}
	cases := make([]vectorCase, len(sections))
	for k, tc := range sections {
		s := tc.section
		compileSection(t, s.Shape).RequireSolved(t, s.Circuit(t))
		p, stream := s.Plaintexts(t), s.Stream(t)
		v := vectorCase{
			Name: tc.name, Layout: s.Layout(), InputClass: s.Shape.InputClass, Outputs: s.Shape.Outputs, OutputCount: s.OutputCount(), InputCount: s.InputCount,
			Envelope: hex.EncodeToString(p.Envelope), EnvelopeCt: hex.EncodeToString(stream.Envelope(s.InputCount)),
			EnvelopeHash: ringtest.FieldHex(s.StatementOf(t, stream, s.Claim())[7]),
			RecordChain:  ringtest.FieldHex(ringaudit.RecordChain(t, s.StatementOutputs(t, stream))),
			TailChain:    ringtest.FieldHex(ringaudit.TailChain(t, s.StatementOutputs(t, stream))),
		}
		for i := range s.OutputCount() {
			v.Records = append(v.Records, hex.EncodeToString(p.Records[i][:stream.Ranges.RecordLen()]))
			v.RecordCts = append(v.RecordCts, hex.EncodeToString(stream.Record(i)))
			v.OutputHashes = append(v.OutputHashes, ringtest.FieldHex(s.Outputs[i].Utxo.Hash(t)))
			v.Blindings = append(v.Blindings, ringtest.FieldHex(s.Blinding(t, i)))
			if s.HasData {
				v.Tails = append(v.Tails, hex.EncodeToString(p.Tails[i]))
				v.TailCts = append(v.TailCts, hex.EncodeToString(stream.Tail(i)))
			}
		}
		cases[k] = v
	}
	txViewingSk, auditorSk := sections[0].section.Keys.TxViewingSk(), ringaudit.AuditorSk()
	ringtest.PinVector(t, "audit/audit-stream.json", map[string]any{
		"description":     "Auditor streams from solved witnesses under CRING/adt, with the layout selecting each encrypted record and envelope format.",
		"tx_viewing_sk":   hex.EncodeToString(txViewingSk[:]),
		"auditor_sk":      hex.EncodeToString(auditorSk[:]),
		"salt":            hex.EncodeToString(sections[0].section.Salt[:]),
		"first_nullifier": ringtest.FieldHex(sections[0].section.FirstNullifier),
		"ring_id":         ringtest.FieldHex(sections[0].section.RingProgramID),
		"output_tree_id":  ringaudit.OutputTreeID,
		"cases":           cases,
	})
}
