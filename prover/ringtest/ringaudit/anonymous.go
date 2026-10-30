package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AnonymousOutput is the host twin of audit.AnonymousOutputWires.
type AnonymousOutput struct {
	Utxo     Utxo
	OwnerKey [32]byte
}

type AnonymousAudit struct {
	Transfer
	Shape             audit.AnonymousAuditShape
	Outputs           []AnonymousOutput
	SenderKey         [32]byte
	SenderNullifierPk *big.Int
	PrivateTxBlinding *big.Int
	// SenderCommitment is 0 on an audit-only transfer.
	SenderCommitment *big.Int
	PartyIdentities  [3]*big.Int
	InputCount       int
	Inputs           []Utxo
	Layout           Layout
}

const (
	kindPayment = iota
	kindChange
	kindExit
	kindDummy
)

var anonymousOutputs = map[int][]int{
	2: {kindPayment, kindChange},
	4: {kindPayment, kindPayment, kindExit, kindChange},
	8: {kindPayment, kindPayment, kindPayment, kindExit, kindChange, kindPayment, kindDummy, kindDummy},
}

// NewAnonymousAudit spends two sender UTXOs, input 1 from the default ring on an entry shape.
func NewAnonymousAudit(t testing.TB, shape audit.AnonymousAuditShape) AnonymousAudit {
	t.Helper()
	a := AnonymousAudit{
		Transfer:          newTransfer(t),
		Shape:             shape,
		SenderKey:         ringtest.Repeat(0xa1),
		SenderNullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		PrivateTxBlinding: big.NewInt(0x5b1d),
		PartyIdentities:   [3]*big.Int{big.NewInt(11), big.NewInt(12), big.NewInt(0)},
		InputCount:        2,
	}
	a.SenderCommitment = ringprotocol.SenderCommitment(t, a.SenderPkHash(t), a.PrivateTxBlinding)
	a.Inputs = make([]Utxo, shape.InputClass)
	for i := range a.Inputs {
		a.Inputs[i] = spareInput(i)
	}
	a.Inputs[0] = a.SenderUtxo(t, a.RingProgramID, 100, 51)
	ring := a.RingProgramID
	if shape.FullOpenings {
		ring = big.NewInt(0)
	}
	a.Inputs[1] = a.SenderUtxo(t, ring, 60, 52)
	payments := 0
	for i, kind := range anonymousOutputs[shape.Outputs] {
		switch kind {
		case kindPayment:
			a.Outputs = append(a.Outputs, a.NewPayment(t, Recipient(t, byte(payments%3), i, 30+uint64(i))))
			payments++
		case kindChange:
			a.Outputs = append(a.Outputs, a.NewPayment(t, a.Change(t, i)))
		case kindExit:
			a.Outputs = append(a.Outputs, a.NewAnonymousExit(t, i))
		case kindDummy:
			a.Outputs = append(a.Outputs, AnonymousOutput{Utxo: a.newDummy(t, i).Utxo, OwnerKey: ringtest.Repeat(0xd1 + byte(i))})
		}
	}
	a.Layout = Layout{Exits: hasExit(anonymousUtxos(a.Outputs)), FullOpenings: shape.FullOpenings}
	return a
}

func (a AnonymousAudit) AtInputCount(count int) AnonymousAudit {
	a.InputCount = count
	a.Inputs = slices.Clone(a.Inputs)
	for i := count; i < len(a.Inputs); i++ {
		a.Inputs[i] = spareInput(i)
	}
	return a
}

// SenderPkHash is the owner identity of the hidden sender.
func (a AnonymousAudit) SenderPkHash(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, a.SenderKey)
}

// SenderUtxo is a UTXO of the hidden sender in the given ring, 0 for the default ring.
func (a AnonymousAudit) SenderUtxo(t testing.TB, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return spentUtxo(t, a.SenderPkHash(t), a.SenderNullifierPk, ringID, amount, blinding)
}

// spentUtxo is a data-free input of owner in the given ring.
func spentUtxo(t testing.TB, ownerPkHash, nullifierPk, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: 3, OwnerPkHash: ownerPkHash, NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, ringtest.Repeat(0x0a)), Amount: amount, Blinding: big.NewInt(blinding),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}
}

// Change is the sender's change slot i.
func (a AnonymousAudit) Change(t testing.TB, i int) DeliverySlot {
	t.Helper()
	return DeliverySlot{Index: i, OwnerKey: a.SenderKey, NullifierPk: a.SenderNullifierPk, AssetAddress: ringtest.Repeat(0x0a), Amount: 15}
}

// NewPayment is a ring output to slot's owner key.
func (a AnonymousAudit) NewPayment(t testing.TB, slot DeliverySlot) AnonymousOutput {
	t.Helper()
	return AnonymousOutput{Utxo: a.ringUtxo(t, slot), OwnerKey: slot.OwnerKey}
}

// NewAnonymousExit carries the exit owner's key, the disclosure masks it.
func (a AnonymousAudit) NewAnonymousExit(t testing.TB, i int) AnonymousOutput {
	t.Helper()
	return AnonymousOutput{Utxo: a.NewExit(t, i).Utxo, OwnerKey: ExitOwnerKey}
}

// PrivateTxHash is SPP's private transaction hash over the slots, with no address input.
func (a AnonymousAudit) PrivateTxHash(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustPrivateTxHash(t, spentHashes(t, a.Inputs), spentHashes(t, anonymousUtxos(a.Outputs)), nil, a.PrivateTxBlinding)
}

func (a AnonymousAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return AnonymousStatement(t, a.AuditHead(t, a.Layout), a.StatementOutputs(t), a.Disclosure(t), a.Tail(t))
}

func (a AnonymousAudit) Tail(t testing.TB) AnonymousTail {
	t.Helper()
	return AnonymousTail{PrivateTxHash: a.PrivateTxHash(t), SenderCommitment: a.SenderCommitment, PartyIdentities: a.PartyIdentities}
}

func (a AnonymousAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(a.Outputs))
	for i, output := range a.Outputs {
		outputs[i] = StatementOutput{Hash: output.Utxo.Hash(t), Exit: output.Utxo.isExit()}
	}
	return outputs
}

// Disclosure is the enciphered anonymous disclosure under a.Layout.
func (a AnonymousAudit) Disclosure(t testing.TB) []*big.Int {
	t.Helper()
	return a.DisclosureOf(t, a.SlotBytes(t), a.InputRecords(t))
}

// SlotBytes mirrors the slot bytes of audit openSlot, one record per output.
func (a AnonymousAudit) SlotBytes(t testing.TB) [][]byte {
	t.Helper()
	slots := make([][]byte, len(a.Outputs))
	for i, output := range a.Outputs {
		var owner, asset [32]byte
		var amount [8]byte
		if output.Utxo.isRingOutput() {
			owner = output.OwnerKey
		}
		if output.Utxo.isUtxo() {
			asset = spptest.MustFieldBytes(t, output.Utxo.Asset)
			binary.BigEndian.PutUint64(amount[:], output.Utxo.Amount)
		}
		slots[i] = slices.Concat(owner[:], asset[:], amount[:])
	}
	return slots
}

// InputRecords is input 0's hash and the prefix pairs of the other published inputs, on an entry layout every published input's asset and blinding.
func (a AnonymousAudit) InputRecords(t testing.TB) []*big.Int {
	t.Helper()
	published := a.Inputs[:a.InputCount]
	if !a.Layout.FullOpenings {
		return CommitmentRecords(spentHashes(t, published))
	}
	var records []*big.Int
	for _, input := range published {
		records = append(records, live(input, input.Asset), live(input, input.Blinding))
	}
	return records
}

// DisclosureOf enciphers the head of a.Layout over slots followed by records.
func (a AnonymousAudit) DisclosureOf(t testing.TB, slots [][]byte, records []*big.Int) []*big.Int {
	t.Helper()
	var nullifierPks []*big.Int
	var slotBytes []byte
	if a.Layout.FullOpenings {
		slotBytes = slices.Clone(a.SenderKey[:])
	}
	for i, output := range a.Outputs {
		nullifierPks = append(nullifierPks, live(output.Utxo, output.Utxo.NullifierPk))
		slotBytes = append(slotBytes, slots[i]...)
	}
	head := slices.Concat(nullifierPks, ringprotocol.PackDisclosure(slotBytes))
	if a.Layout.FullOpenings {
		var amounts []byte
		for _, input := range a.Inputs {
			amounts = binary.BigEndian.AppendUint64(amounts, live(input, new(big.Int).SetUint64(input.Amount)).Uint64())
		}
		head = slices.Concat([]*big.Int{a.Inputs[0].NullifierPk}, head, ringprotocol.PackDisclosure(amounts))
	}
	return a.Keys.Disclose(t, a.Salt, slices.Concat(a.seedOut(a.Layout), head, records))
}

// Circuit is the audit assignment proving the statement.
func (a AnonymousAudit) Circuit(t testing.TB) *audit.AnonymousAuditCircuit {
	t.Helper()
	c, err := audit.NewAnonymousAuditCircuit(a.Shape)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.wires(a.Layout)
	for i, output := range a.Outputs {
		c.Outputs[i] = audit.AnonymousOutputWires{Output: output.Utxo.Wires()}
		ringtest.SetBytes(c.Outputs[i].OwnerKey[:], output.OwnerKey[:])
	}
	c.PrivateTxHash = a.PrivateTxHash(t)
	c.PrivateTxBlinding = a.PrivateTxBlinding
	if a.Shape.FullOpenings {
		ringtest.SetBytes(c.SenderKey, a.SenderKey[:])
	}
	c.InputCount = a.InputCount
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Wires()
	}
	c.SenderCommitment = a.SenderCommitment
	for i, party := range a.PartyIdentities {
		c.PartyIdentities[i] = party
	}
	return c
}

func anonymousUtxos(outputs []AnonymousOutput) []Utxo {
	utxos := make([]Utxo, len(outputs))
	for i, output := range outputs {
		utxos[i] = output.Utxo
	}
	return utxos
}

func spentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(utxos))
	for i, utxo := range utxos {
		hashes[i] = utxo.spentHash(t)
	}
	return hashes
}

// CommitmentRecords mirrors the commitment tail of audit.
func CommitmentRecords(hashes []*big.Int) []*big.Int {
	records := []*big.Int{hashes[0]}
	var prefixes []*big.Int
	for _, hash := range hashes[1:] {
		prefixes = append(prefixes, new(big.Int).Rsh(hash, 8*(32-audit.InputPrefixLen)))
	}
	for k := 0; k < len(prefixes); k += 2 {
		second := big.NewInt(0)
		if k+1 < len(prefixes) {
			second = prefixes[k+1]
		}
		records = append(records, new(big.Int).Add(new(big.Int).Lsh(prefixes[k], audit.InputPrefixBits), second))
	}
	return records
}

func spareInput(i int) Utxo {
	return Dummy(3, big.NewInt(0x9000+int64(i)))
}
