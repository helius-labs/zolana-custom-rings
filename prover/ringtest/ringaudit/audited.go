package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Slot is one output with the preimages its record names, the host twin of audit.OutputWires.
type Slot struct {
	Utxo     Utxo
	OwnerKey [32]byte
	Mint     [32]byte
}

func (s Slot) Wires() audit.OutputWires {
	w := audit.OutputWires{Output: s.Utxo.Wires()}
	ringtest.SetBytes(w.OwnerKey[:], s.OwnerKey[:])
	chunks := protocol.MintChunks(s.Mint)
	w.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	return w
}

// Record mirrors audit.RecordOpening.Encode with its padding, all zero on a dummy.
func (s Slot) Record(t testing.TB) []byte {
	t.Helper()
	record := make([]byte, audit.RecordStride)
	if !s.Utxo.isUtxo() {
		return record
	}
	record[0] = audit.KindRing
	if s.Utxo.isExit() {
		record[0] = audit.KindExit
	}
	binary.BigEndian.PutUint64(record[1:9], s.Utxo.Amount)
	copy(record[9:41], s.OwnerKey[:])
	copy(record[41:73], s.Mint[:])
	nullifierPk := spptest.MustFieldBytes(t, s.Utxo.NullifierPk)
	copy(record[73:audit.RecordLen], nullifierPk[:])
	return record
}

// Tail mirrors the audit tail, zero on a dummy.
func (s Slot) Tail(t testing.TB) []byte {
	t.Helper()
	if !s.Utxo.isUtxo() {
		return make([]byte, audit.TailLen)
	}
	dataHash, ringDataHash := spptest.MustFieldBytes(t, s.Utxo.DataHash), spptest.MustFieldBytes(t, s.Utxo.RingDataHash)
	return slices.Concat(dataHash[:], ringDataHash[:])
}

// Input is one spent slot with the preimages its entry evidence names, the host twin of audit.EntryWires.
type Input struct {
	Utxo     Utxo
	OwnerKey [32]byte
	Mint     [32]byte
}

func (i Input) EntryWires() audit.EntryWires {
	w := audit.EntryWires{}
	ringtest.SetBytes(w.OwnerKey[:], i.OwnerKey[:])
	chunks := protocol.MintChunks(i.Mint)
	w.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	return w
}

// entry mirrors the entry evidence, zero off a default-ring note.
func (i Input) entry(t testing.TB) []byte {
	t.Helper()
	if !i.Utxo.isExit() {
		return make([]byte, audit.EntryInputLen)
	}
	nullifierPk, blinding := spptest.MustFieldBytes(t, i.Utxo.NullifierPk), spptest.MustFieldBytes(t, i.Utxo.Blinding)
	dataHash, ringDataHash := spptest.MustFieldBytes(t, i.Utxo.DataHash), spptest.MustFieldBytes(t, i.Utxo.RingDataHash)
	return slices.Concat(i.OwnerKey[:], nullifierPk[:], binary.BigEndian.AppendUint64(nil, i.Utxo.Amount), i.Mint[:], blinding[:], dataHash[:], ringDataHash[:])
}

// Audit is one transfer's auditor stream, the fixture every transfer key seals.
type Audit struct {
	Transfer
	Shape      audit.StreamShape
	Outputs    []Slot
	Inputs     []Input
	InputCount int
	// Omitted is the slots past m, the frame carries no cell for them.
	Omitted int
	// HasData sets the statement bit, tails open every slot's data hashes.
	HasData bool
}

// NewAudit pays every slot to a fixture recipient and spends nothing yet, exits name the slots leaving the ring.
func NewAudit(t testing.TB, shape audit.StreamShape, exits ...int) Audit {
	t.Helper()
	a := Audit{Transfer: newTransfer(t), Shape: shape, Inputs: make([]Input, shape.InputClass)}
	for i := range a.Inputs {
		a.Inputs[i] = Input{Utxo: SpareInput(i)}
	}
	for i := range shape.Outputs {
		switch {
		case slices.Contains(exits, i):
			a.Outputs = append(a.Outputs, a.NewExit(t, i))
		default:
			a.Outputs = append(a.Outputs, a.NewRingOutput(t, Recipient(t, byte(i%3), i, 30+uint64(i))))
		}
	}
	return a
}

// AllDummies replaces every slot with a published dummy.
func (a Audit) AllDummies(t testing.TB) Audit {
	t.Helper()
	a.Outputs = slices.Clone(a.Outputs)
	for i := range a.Outputs {
		a.Outputs[i] = a.NewDummy(t, i)
	}
	return a
}

// Omit cuts the last n slots, each published slot keeps its index.
func (a Audit) Omit(t testing.TB, n int) Audit {
	t.Helper()
	a.Outputs = slices.Clone(a.Outputs)
	for i := len(a.Outputs) - n; i < len(a.Outputs); i++ {
		a.Outputs[i] = Slot{Utxo: unpublished()}
	}
	a.Omitted = n
	return a
}

func (a Audit) OutputCount() int {
	return len(a.Outputs) - a.Omitted
}

func (a Audit) Layout() int64 {
	return ringtest.Bit(a.HasData)*audit.LayoutHasData | ringtest.Bit(a.Shape.Entry)*audit.LayoutEntry | ringtest.Bit(a.Shape.SingleAssetPayout)*audit.LayoutSingleAssetPayout
}

// RealInputs is R, the spent notes among the slots.
func (a Audit) RealInputs() int {
	count := 0
	for _, input := range a.Inputs {
		if input.Utxo.isUtxo() {
			count++
		}
	}
	return count
}

func (a Audit) inputBits(selected func(Utxo) bool) uint64 {
	bits := uint64(0)
	for i, input := range a.Inputs {
		if selected(input.Utxo) {
			bits |= 1 << i
		}
	}
	return bits
}

func (a Audit) defaultBits() uint64 {
	return a.inputBits(Utxo.isExit)
}

// Stream mirrors audit.AuditWires.SealStream.
func (a Audit) Stream(t testing.TB) Stream {
	t.Helper()
	return a.Seal(t, a.Plaintexts(t))
}

// Head is what the program holds for the statement's head.
func (a Audit) Head(t testing.TB, stream Stream) AuditHead {
	t.Helper()
	head := a.Keys.AuditHead(t, a.FirstNullifier, a.RingProgramID, a.Salt, stream.Envelope(a.InputCount))
	head.Layout = a.Layout()
	return head
}

// StatementOutputs is every slot as the statement reads it.
func (a Audit) StatementOutputs(t testing.TB, stream Stream) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(a.Outputs))
	for i, slot := range a.Outputs {
		outputs[i] = StatementOutput{Hash: slot.Utxo.Hash(t), Omitted: i >= a.OutputCount(), Record: stream.Record(i)}
		if a.HasData {
			outputs[i].Tail = stream.Tail(i)
		}
	}
	return outputs
}

// Utxos are the output openings the policy screens.
func (a Audit) Utxos() []Utxo {
	utxos := make([]Utxo, len(a.Outputs))
	for i, slot := range a.Outputs {
		utxos[i] = slot.Utxo
	}
	return utxos
}

// InputUtxos are the input openings SPP spends.
func (a Audit) InputUtxos() []Utxo {
	utxos := make([]Utxo, len(a.Inputs))
	for i, input := range a.Inputs {
		utxos[i] = input.Utxo
	}
	return utxos
}

// SpentUtxo is a note of owner, ring zero a default-ring note.
func SpentUtxo(t testing.TB, ownerPkHash, nullifierPk, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: 3, OwnerPkHash: ownerPkHash, NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, ringtest.Repeat(0x0a)), Amount: amount, Blinding: big.NewInt(blinding),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}
}

// SpareInput is the dummy input i, SPP derives no output from its blinding.
func SpareInput(i int) Utxo {
	return Dummy(3, big.NewInt(0x9000+int64(i)))
}

// SpentHashes is utxo*hash per slot, the list private_tx_hash chains.
func SpentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(utxos))
	for i, utxo := range utxos {
		hashes[i] = utxo.spentHash(t)
	}
	return hashes
}
