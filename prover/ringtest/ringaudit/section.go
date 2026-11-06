package ringaudit

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Test only, no proving key serves the section alone.
type SectionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Shape           audit.StreamShape `gnark:"-"`
	audit.AuditWires
	OutputCount frontend.Variable
	Outputs     []audit.OutputWires
	InputCount  frontend.Variable
	Inputs      []shared.UtxoWires
	Entries     []audit.EntryWires
}

func NewSectionCircuit(shape audit.StreamShape) *SectionCircuit {
	c := &SectionCircuit{Shape: shape, Outputs: make([]audit.OutputWires, shape.Outputs), Inputs: make([]shared.UtxoWires, shape.InputClass)}
	if shape.Entry {
		c.Entries = make([]audit.EntryWires, shape.InputClass)
	}
	return c
}

func (c *SectionCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	c.Shape.AssertLayout(api, c.Layout)
	envelope := c.OpenEnvelope(api, rc)
	opened := c.Shape.OpenSlots(api, rc, c.Outputs, c.OutputCount)
	section := transfer.OpenInputs(api, c.Inputs, c.InputCount)
	records := c.RecordChain(api, envelope, opened)
	stream := c.SealStream(api, rc, envelope, c.Shape, opened, audit.SpentInputs{Slots: section.Slots, Count: section.Count, Entries: c.Entries})
	statement := append(envelope.Head(c.AuditWires, stream, shared.TransferStatementDomain),
		stream.NoSpend, c.OutputCount, records, c.InputCount)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// RingOwnerKey owns the fixture ring outputs, PayerKey the fixture ring inputs and DefaultOwnerKey the fixture default-ring inputs.
var (
	RingOwnerKey    = ringtest.Repeat(0xb2)
	PayerKey        = ringtest.Repeat(0xa1)
	DefaultOwnerKey = ringtest.Repeat(0xa2)
	FixtureMint     = ringtest.Repeat(0x0a)
)

func EnrolledNullifierPk(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, big.NewInt(21))
}

// ZeroKey is Poseidon(0), the key of a note with no secret.
func ZeroKey(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, big.NewInt(0))
}

// NewSection is the honest fixture each refusal edits.
func NewSection(t testing.TB, shape audit.StreamShape) Audit {
	t.Helper()
	s := NewAudit(t, shape)
	s.InputCount = 1
	s = s.AllDummies(t)
	s.Outputs[0] = s.RingNote(t, 0, RingOwnerKey, EnrolledNullifierPk(t), 100)
	switch {
	case shape.Outputs >= 4:
		s.Outputs[1] = s.RingNote(t, 1, RingOwnerKey, ZeroKey(t), 30)
		s.Outputs[2] = s.NewExit(t, 2)
	case shape.Outputs >= 2:
		s.Outputs[1] = s.NewExit(t, 1)
	}
	s.Inputs[0] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), s.RingProgramID, 100, 51), OwnerKey: PayerKey, Mint: FixtureMint}
	if shape.Entry {
		s.InputCount = 2
		s.Inputs[1] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, DefaultOwnerKey), spptest.MustNullifierPk(t, big.NewInt(8)), big.NewInt(0), 70, 52), OwnerKey: DefaultOwnerKey, Mint: FixtureMint}
	}
	return s
}

// RingNote is a data-free ring note of owner under the TXOB blinding of slot i.
func (a Audit) RingNote(t testing.TB, i int, owner [32]byte, nullifierPk *big.Int, amount uint64) Slot {
	t.Helper()
	return Slot{OwnerKey: owner, Mint: FixtureMint, Utxo: Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, owner), NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, FixtureMint), Amount: amount, Blinding: a.Blinding(t, i),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: a.RingProgramID,
	}, RecipientKey: ViewingKey(t, byte(i))}
}

func (a Audit) Spending(t testing.TB, n int) Audit {
	t.Helper()
	a.Inputs = slices.Clone(a.Inputs)
	for i := range a.Inputs {
		a.Inputs[i] = Input{Utxo: SpareInput(i)}
		if i < n {
			a.Inputs[i] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), a.RingProgramID, 10, 60+int64(i)), OwnerKey: PayerKey, Mint: FixtureMint}
		}
	}
	return a
}

func (a Audit) DefaultBits() uint64 {
	return a.defaultBits()
}

// Plaintexts are the sealed regions of a transfer, a test edits them to claim what the circuit refuses.
type Plaintexts struct {
	Envelope []byte
	// RecipientKeys hold every slot's key at capacity, the stream seals them for the auditor.
	RecipientKeys [][32]byte
	// SealedTo is the key each record is sealed to, RecipientKeys unless a test parts them.
	SealedTo [][32]byte
	Records  [][]byte
}

func (a Audit) Plaintexts(t testing.TB) Plaintexts {
	t.Helper()
	envelope := append(slices.Clone(a.Keys.txViewingSk[:]), byte(a.RealInputs()))
	if a.Shape.Entry {
		envelope = binary.BigEndian.AppendUint64(envelope, a.defaultBits())
		// The frame transmits one record per published input, the sealed padding past n reads zero.
		for _, input := range a.Inputs[:a.InputCount] {
			envelope = append(envelope, input.entry(t)...)
		}
	}
	p := Plaintexts{Envelope: envelope, Records: make([][]byte, len(a.Outputs)), RecipientKeys: make([][32]byte, len(a.Outputs))}
	for i, output := range a.Outputs {
		p.Records[i] = output.Record(t)
		p.RecipientKeys[i] = output.RecipientKey
	}
	p.SealedTo = slices.Clone(p.RecipientKeys)
	return p
}

func (a Audit) Seal(t testing.TB, p Plaintexts) Stream {
	t.Helper()
	ranges := a.Shape.Ranges()
	plaintext := append(slices.Clone(p.Envelope), make([]byte, ranges.KeyOffset(0)-len(p.Envelope))...)
	for _, key := range p.RecipientKeys {
		plaintext = append(plaintext, key[:]...)
	}
	stream := Stream{Ranges: ranges, Salt: a.Salt, Ciphertext: a.Keys.TransferCiphertext(t, plaintext, a.Salt), Records: make([][]byte, len(p.Records))}
	for i, record := range p.Records {
		stream.Records[i] = a.Keys.SealRecord(t, p.SealedTo[i], a.Salt, i, a.FirstNullifier, record)
	}
	return stream
}

// Open decrypts a stream the auditor read, the keystream is the zero plaintext's ciphertext.
func (k Keys) Open(t testing.TB, stream Stream) []byte {
	t.Helper()
	keystream := k.TransferCiphertext(t, make([]byte, len(stream.Ciphertext)), stream.Salt)
	plaintext := make([]byte, len(keystream))
	for i := range plaintext {
		plaintext[i] = keystream[i] ^ stream.Ciphertext[i]
	}
	return plaintext
}

func (a Audit) PublishedHashes(t testing.TB) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, a.OutputCount())
	for i := range hashes {
		hashes[i] = a.Outputs[i].Utxo.Hash(t)
	}
	return hashes
}

// Claim is the part of the statement the program reads off the frame, a test moves one cell.
type Claim struct {
	NoSpend     bool
	OutputCount int
	InputCount  int
}

func (a Audit) Claim() Claim {
	return Claim{NoSpend: a.RealInputs() == 0, OutputCount: a.OutputCount(), InputCount: a.InputCount}
}

// StatementOf is what the program would hash over stream under claim.
func (a Audit) StatementOf(t testing.TB, stream Stream, claim Claim) []*big.Int {
	t.Helper()
	outputs := a.StatementOutputs(t, stream)
	head := a.Keys.AuditHead(t, a.FirstNullifier, a.RingProgramID, a.Salt, stream.Envelope(claim.InputCount), stream.Keys(claim.OutputCount))
	head.Layout = a.Layout()
	return append(head.ElementsUnder(t, shared.TransferStatementDomain), big.NewInt(ringtest.Bit(claim.NoSpend)), big.NewInt(int64(claim.OutputCount)),
		RecordChain(t, outputs), big.NewInt(int64(claim.InputCount)))
}

func (a Audit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return a.StatementOf(t, a.Seal(t, a.Plaintexts(t)), a.Claim())
}

func (a Audit) Circuit(t testing.TB) *SectionCircuit {
	t.Helper()
	c := NewSectionCircuit(a.Shape)
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.Wires(a.Layout())
	c.OutputCount = a.OutputCount()
	c.InputCount = a.InputCount
	for i, output := range a.Outputs {
		c.Outputs[i] = output.Wires()
	}
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Utxo.Wires()
		if a.Shape.Entry {
			c.Entries[i] = input.EntryWires()
		}
	}
	return c
}

type Note struct {
	Kind        byte
	OwnerKey    [32]byte
	Mint        [32]byte
	Amount      uint64
	NullifierPk *big.Int
	Blinding    *big.Int
	Hash        *big.Int
}

// AuditReader rebuilds a slot with no mint registry and no other slot.
type AuditReader struct {
	Transfer
	Shape      audit.StreamShape
	InputCount int
	TreeID     uint16
}

func (a Audit) Reader() AuditReader {
	return AuditReader{Transfer: a.Transfer, Shape: a.Shape, InputCount: a.InputCount, TreeID: OutputTreeID}
}

func (r AuditReader) Envelope(t testing.TB, stream Stream) (realInputs int, defaultBits uint64) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	realInputs = int(plaintext[audit.EnvelopeKeyLen])
	if r.Shape.Entry {
		defaultBits = binary.BigEndian.Uint64(plaintext[r.Shape.Ranges().EnvelopeHeadLen()-audit.DefaultInputBitsLen:])
	}
	return realInputs, defaultBits
}

// Read opens slot i from the sealed key and its sealed recipient key, and accepts only an exact match, nil on a dummy.
func (r AuditReader) Read(t testing.TB, stream Stream, i int, published *big.Int) (*Note, error) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	txViewingSk := [32]byte(plaintext[:audit.EnvelopeKeyLen])
	offset := stream.Ranges.KeyOffset(i)
	u := [32]byte(plaintext[offset : offset+audit.KeyLen])
	// CTR is its own inverse.
	record := ringprotocol.SealRecord(t, txViewingSk, u, r.Salt, i, r.FirstNullifier, shared.OutputRecordInfo, stream.Record(i))
	kind := record[0]
	if kind == audit.KindDummy {
		if slices.ContainsFunc(record, func(b byte) bool { return b != 0 }) {
			return nil, fmt.Errorf("slot %d: a dummy carries a value", i)
		}
		return nil, nil
	}
	if kind != audit.KindRing && kind != audit.KindExit {
		return nil, fmt.Errorf("slot %d: not a record", i)
	}
	note := Note{Kind: kind, OwnerKey: [32]byte(record[9:41]), Mint: [32]byte(record[41:73]), Amount: binary.BigEndian.Uint64(record[1:9]), NullifierPk: new(big.Int).SetBytes(record[73:105]), Blinding: new(big.Int).SetBytes(record[105:])}
	ringID := big.NewInt(0)
	if kind == audit.KindRing {
		ringID = r.RingProgramID
	}
	// The fixtures carry no data payload, both data hashes read zero.
	note.Hash = Utxo{
		Domain: protocol.UtxoDomain, TreeID: r.TreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, note.OwnerKey), NullifierPk: note.NullifierPk,
		Asset: ringtest.AssetField(t, note.Mint), Amount: note.Amount, Blinding: note.Blinding,
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}.Hash(t)
	if note.Hash.Cmp(published) != 0 {
		return nil, fmt.Errorf("slot %d: the record rebuilds no published commitment", i)
	}
	return &note, nil
}

// ReadEntry reads default input i's record and accepts only the spent commitment, nil on any other slot.
func (r AuditReader) ReadEntry(t testing.TB, stream Stream, i int, spent *big.Int) (*Entry, error) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	_, bits := r.Envelope(t, stream)
	if bits&(1<<i) == 0 {
		return nil, nil
	}
	offset := stream.Ranges.EnvelopeHeadLen() + i*audit.EntryRecordLen
	record := plaintext[offset : offset+audit.EntryRecordLen]
	entry := Entry{OwnerKey: [32]byte(record[:32]), NullifierPk: new(big.Int).SetBytes(record[32:64]), Amount: binary.BigEndian.Uint64(record[64:72]), Mint: [32]byte(record[72:104]), Commitment: new(big.Int).SetBytes(record[104:])}
	if entry.Commitment.Cmp(spent) != 0 {
		return nil, fmt.Errorf("input %d: the record names no spent commitment", i)
	}
	return &entry, nil
}

// Entry is a default-ring input as its record names it, metadata beside the proven commitment.
type Entry struct {
	OwnerKey    [32]byte
	NullifierPk *big.Int
	Amount      uint64
	Mint        [32]byte
	Commitment  *big.Int
}
