package registry_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type batch struct {
	circuit *registry.ApplyRecordsCircuit
	writes  []ringregistry.Write
	// chain[k] is the chain value after k entries, chain[0] the start.
	chain []*big.Int
}

func entry(member, mask, value, escrowKey int64) ringregistry.Entry {
	return ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(value), EscrowKey: big.NewInt(escrowKey)}
}

// applyBatch applies entries to members and assigns the capacity-n circuit, padding writes all zero.
func applyBatch(t *testing.T, members *ringregistry.Registry, n int, chainStart *big.Int, entries ...ringregistry.Entry) *batch {
	t.Helper()
	c := applyCircuit(t, n)
	c.OldRoot, c.OldNextIndex, c.ChainStart, c.Count = members.Root(), new(big.Int).SetUint64(members.NextIndex()), chainStart, len(entries)
	b := &batch{circuit: c, chain: []*big.Int{chainStart}}
	for i := range c.Writes {
		c.Writes[i] = zeroWrite()
	}
	for i, e := range entries {
		w := members.Apply(t, e)
		b.writes = append(b.writes, w)
		c.Writes[i] = writeWires(w)
		b.chain = append(b.chain, ringtest.MustPoseidonHash(t, b.chain[i], e.Hash(t)))
	}
	c.NewRoot, c.NewNextIndex, c.ChainEnd = members.Root(), new(big.Int).SetUint64(members.NextIndex()), b.chain[len(entries)]
	b.bind(t)
	return b
}

// bind hashes the statement from the circuit's current values, as the program rebuilds it.
func (b *batch) bind(t *testing.T) {
	t.Helper()
	c := b.circuit
	statement := []*big.Int{big.NewInt(shared.ApplyRecordsDomain)}
	for _, v := range []frontend.Variable{c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count} {
		statement = append(statement, ringtest.AsBigInt(v))
	}
	c.PublicInputHash = spptest.MustHashChain4(t, statement)
}

func writeWires(w ringregistry.Write) registry.RecordWrite {
	e := w.Entry
	exists := 0
	if w.Exists {
		exists = 1
	}
	return registry.RecordWrite{
		Entry:  registry.QueueEntry{Member: e.Member, Mask: e.Mask, Value: e.Value, EscrowKey: e.EscrowKey, MintPolicy: policyValue(e.MintPolicy), WithdrawalThreshold: policyValue(e.WithdrawalThreshold), AssetLimits: e.AssetLimits.Wires()},
		Exists: exists,
		Old: registry.RecordBody{
			Next: w.OldNext, Lists: w.OldLists, EscrowKey: w.OldEscrow, MintPolicy: policyValue(w.OldMintPolicy),
			WithdrawalThreshold: policyValue(w.OldWithdrawalThreshold), AssetLimits: w.OldAssetLimits.Wires(),
		},
		Slot:    w.Slot.Wires(),
		Low:     w.Low.Wires(),
		LowSlot: w.LowPath.Wires(),
	}
}

func zeroWrite() registry.RecordWrite {
	zero := ringregistry.Write{
		Entry:   entry(0, 0, 0, 0),
		OldNext: big.NewInt(0), OldLists: big.NewInt(0), OldEscrow: big.NewInt(0),
		Low: ringregistry.Record{Member: big.NewInt(0), Next: big.NewInt(0), Lists: big.NewInt(0), EscrowKey: big.NewInt(0)},
	}
	for level := range zero.Slot.Siblings {
		for k := range zero.Slot.Siblings[level] {
			zero.Slot.Siblings[level][k], zero.LowPath.Siblings[level][k] = big.NewInt(0), big.NewInt(0)
		}
	}
	return writeWires(zero)
}

func solve(t *testing.T, c *registry.ApplyRecordsCircuit) error {
	t.Helper()
	return test.IsSolved(applyCircuit(t, c.NumWrites), c, ecc.BN254.ScalarField())
}

// seeded holds alice (0x10) with the allow list and carol (0x30) with a registered key.
func seeded(t *testing.T) *ringregistry.Registry {
	t.Helper()
	members := ringregistry.New(t)
	members.Apply(t, entry(0x10, ringregistry.AllowBit, ringregistry.AllowBit, 0))
	members.Apply(t, entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc1))
	return members
}

func TestApplyRecordsAppliesTheQueueInOrder(t *testing.T) {
	members := seeded(t)
	b := applyBatch(t, members, registry.ApplyBatch, big.NewInt(0x5eed),
		entry(0x20, ringregistry.AllowBit|ringregistry.BlockBit, ringregistry.BlockBit, 0),                       // insert between alice and carol
		entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0),                                             // alice keeps allow, gains block
		entry(0x10, ringregistry.AllowBit, 0, 0),                                                                 // alice drops allow, keeps block
		entry(0x40, ringregistry.AllowBit, 0, 0),                                                                 // an empty record is never inserted
		entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc2),                                        // carol keeps her first key
		entry(0x50, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc3),                                        // RegisterKey inserts a new member
		entry(0x05, ringregistry.AllowBit|ringregistry.BlockBit, ringregistry.AllowBit|ringregistry.BlockBit, 0), // insert below every member
	)
	if err := solve(t, b.circuit); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[int64][2]int64{0x10: {ringregistry.BlockBit, 0}, 0x20: {ringregistry.BlockBit, 0}, 0x30: {ringregistry.EscrowBit, 0xc1}, 0x50: {ringregistry.EscrowBit, 0xc3}, 0x05: {ringregistry.AllowBit | ringregistry.BlockBit, 0}} {
		record := members.Opening(big.NewInt(member))
		if !record.Present || record.Record.Lists.Int64() != want[0] || record.Record.EscrowKey.Int64() != want[1] {
			t.Fatalf("member %#x: present=%v lists=%v escrow=%v", member, record.Present, record.Record.Lists, record.Record.EscrowKey)
		}
	}
	if members.Opening(big.NewInt(0x40)).Present || members.NextIndex() != 6 {
		t.Fatalf("next index %d, an empty record was inserted", members.NextIndex())
	}
	full := ringregistry.New(t)
	var entries []ringregistry.Entry
	for i := range registry.ApplyBatch {
		entries = append(entries, entry(int64(0x100+i), ringregistry.AllowBit, ringregistry.AllowBit, 0))
	}
	if err := solve(t, applyBatch(t, full, registry.ApplyBatch, big.NewInt(0), entries...).circuit); err != nil {
		t.Fatalf("full batch: %v", err)
	}
}

// Each case forges a batch consistent with every rule but the one it names, whose frames refuse it.
func TestApplyRecordsRefusals(t *testing.T) {
	gate := []string{"gadget.AssertEqualWhen", "registry.RecordWrite.apply"}
	empty := []string{"gadget.AssertZeroWhen", "registry.RecordWrite.apply"}
	bracket := []string{"ringgadget.AssertOrderedWhen", "registry.RecordWrite.apply"}
	define := []string{"[assertIsEqual]", "registry.(*ApplyRecordsCircuit).Define"}
	insert := entry(0x20, ringregistry.AllowBit, ringregistry.AllowBit, 0)
	tests := []struct {
		name    string
		members func(*testing.T) *ringregistry.Registry
		n       int
		entries []ringregistry.Entry
		tamper  func(*testing.T, *batch)
		frames  []string
	}{
		{"insert at next_index + 1", fourRecords, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			// Both empty leaves of the group share their siblings, the root folds the record one leaf on.
			slot := b.writes[0].Slot
			slot.Index++
			b.circuit.Writes[0].Slot = slot.Wires()
			b.circuit.NewRoot = slot.Root(t, newRecord(b.writes[0], ringregistry.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"absence proven with the low record of another gap", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			// carol's record opens under the old root, its link starts above 0x20.
			opening := seeded(t).Opening(big.NewInt(0x30))
			w := &b.circuit.Writes[0]
			w.Low.Member, w.Low.Next, w.Low.Lists, w.Low.EscrowKey = opening.Record.Member, opening.Record.Next, opening.Record.Lists, opening.Record.EscrowKey
			w.LowSlot = opening.Path.Wires()
		}, bracket},
		{"a present member inserted again through the record linking to it", seeded, 1, []ringregistry.Entry{entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0)}, func(t *testing.T, b *batch) {
			// The sentinel links to alice, so its relink changes nothing and a second alice record follows.
			members := seeded(t)
			sentinel := members.Opening(big.NewInt(1))
			duplicate := ringregistry.Write{Entry: b.writes[0].Entry, OldNext: big.NewInt(0x10), OldLists: big.NewInt(0), OldEscrow: big.NewInt(0),
				Slot: members.Path(members.NextIndex()), Low: sentinel.Record, LowPath: sentinel.Path}
			b.circuit.Writes[0] = writeWires(duplicate)
			b.circuit.NewRoot = duplicate.Slot.Root(t, newRecord(duplicate, ringregistry.BlockBit).Hash(t))
			b.circuit.NewNextIndex = new(big.Int).SetUint64(members.NextIndex() + 1)
			b.bind(t)
		}, bracket},
		{"a low record under another root", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			// The batch is honest for a registry holding 0x1f in alice's place.
			forged := applyBatch(t, replaced(t, 0x1f), 1, b.chain[0], insert)
			forged.circuit.OldRoot = b.circuit.OldRoot
			forged.bind(t)
			*b = *forged
		}, gate},
		{"an old list bit on an absent member", seeded, 1, []ringregistry.Entry{entry(0x20, ringregistry.BlockBit, ringregistry.BlockBit, 0)}, func(t *testing.T, b *batch) {
			listed := seeded(t)
			listed.Apply(t, entry(0x20, ringregistry.AllowBit|ringregistry.BlockBit, ringregistry.AllowBit|ringregistry.BlockBit, 0))
			b.circuit.Writes[0].Old.Lists = big.NewInt(ringregistry.AllowBit)
			b.circuit.NewRoot = listed.Root()
			b.bind(t)
		}, empty},
		{"an insert carrying an escrow key the queue never held", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			keyed := seeded(t)
			keyed.Apply(t, entry(0x20, ringregistry.AllowBit, ringregistry.AllowBit, 0x99))
			b.circuit.Writes[0].Old.EscrowKey = big.NewInt(0x99)
			b.circuit.NewRoot = keyed.Root()
			b.bind(t)
		}, empty},
		{"an insert linking past the low record's next", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			w := b.writes[0]
			w.OldNext = big.NewInt(0x40)
			b.circuit.Writes[0].Old.Next = w.OldNext
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringregistry.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"an absent member claimed present", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			w := b.writes[0]
			w.Exists, w.Slot = true, seeded(t).Path(w.Slot.Index)
			b.circuit.Writes[0] = writeWires(w)
			b.circuit.NewRoot, b.circuit.NewNextIndex = w.Slot.Root(t, newRecord(w, ringregistry.AllowBit).Hash(t)), b.circuit.OldNextIndex
			b.bind(t)
		}, gate},
		{"an update over another old record", seeded, 1, []ringregistry.Entry{entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0)}, func(t *testing.T, b *batch) {
			// alice holds allow, the forged witness says she held nothing.
			w := b.writes[0]
			w.OldLists = big.NewInt(0)
			b.circuit.Writes[0].Old.Lists = w.OldLists
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringregistry.BlockBit).Hash(t))
			b.bind(t)
		}, gate},
		{"an insert over a record at a stale next index", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			// The statement names carol's leaf as the next one, the insert would overwrite it.
			w := b.writes[0]
			w.Slot = seeded(t).Path(2)
			b.circuit.Writes[0].Slot = w.Slot.Wires()
			b.circuit.OldNextIndex, b.circuit.NewNextIndex = big.NewInt(2), big.NewInt(3)
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringregistry.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"second escrow key replaces the first", seeded, 1, []ringregistry.Entry{entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc2)}, func(t *testing.T, b *batch) {
			b.circuit.NewRoot = replacedKeyRoot(t)
			b.bind(t)
		}, define},
		{"a bit outside the mask changes", seeded, 1, []ringregistry.Entry{entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0)}, func(t *testing.T, b *batch) {
			cleared := ringregistry.New(t)
			cleared.Apply(t, entry(0x10, ringregistry.AllowBit|ringregistry.BlockBit, ringregistry.BlockBit, 0))
			cleared.Apply(t, entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc1))
			b.circuit.NewRoot = cleared.Root()
			b.bind(t)
		}, define},
		{"an empty record is inserted", seeded, 1, []ringregistry.Entry{entry(0x40, ringregistry.AllowBit, 0, 0)}, func(t *testing.T, b *batch) {
			forged := seeded(t)
			b.circuit.Writes[0] = writeWires(forged.Insert(t, b.writes[0].Entry))
			b.circuit.NewRoot, b.circuit.NewNextIndex = forged.Root(), new(big.Int).SetUint64(forged.NextIndex())
			b.bind(t)
		}, define},
		{"a next index advanced past a no-op", seeded, 1, []ringregistry.Entry{entry(0x40, ringregistry.AllowBit, 0, 0)}, func(t *testing.T, b *batch) {
			b.circuit.NewNextIndex = new(big.Int).Add(ringtest.AsBigInt(b.circuit.NewNextIndex), big.NewInt(1))
			b.bind(t)
		}, define},
		{"an entry the chain never held", seeded, 1, []ringregistry.Entry{entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc2)}, func(_ *testing.T, b *batch) {
			// carol keeps her first key either way, only the chain sees the other entry.
			b.circuit.Writes[0].Entry.EscrowKey = big.NewInt(0xc3)
		}, define},
		{"the queue applied out of order", seeded, registry.ApplyBatch, []ringregistry.Entry{entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0), entry(0x10, ringregistry.BlockBit, 0, 0)}, func(t *testing.T, b *batch) {
			// The writes and the root follow the swapped order, the chain end the queued one.
			swapped := applyBatch(t, seeded(t), registry.ApplyBatch, b.chain[0], b.writes[1].Entry, b.writes[0].Entry)
			swapped.circuit.ChainEnd = b.circuit.ChainEnd
			swapped.bind(t)
			*b = *swapped
		}, define},
		{"a chain end short of the applied writes", seeded, registry.ApplyBatch, []ringregistry.Entry{insert, entry(0x10, ringregistry.BlockBit, ringregistry.BlockBit, 0)}, func(t *testing.T, b *batch) {
			b.circuit.ChainEnd = b.chain[1]
			b.bind(t)
		}, define},
		{"an empty batch", seeded, 1, []ringregistry.Entry{insert}, func(t *testing.T, b *batch) {
			b.circuit.Count = 0
			b.bind(t)
		}, []string{"ringgadget.SelectCount"}},
		{"the statement of another batch", seeded, 1, []ringregistry.Entry{insert}, func(_ *testing.T, b *batch) {
			b.circuit.PublicInputHash = big.NewInt(1)
		}, define},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := applyBatch(t, tt.members(t), tt.n, big.NewInt(0x5eed), tt.entries...)
			if err := solve(t, b.circuit); err != nil {
				t.Fatalf("honest batch: %v", err)
			}
			tt.tamper(t, b)
			ringtest.RequireRefused(t, solve(t, b.circuit), tt.frames...)
		})
	}
}

func newRecord(w ringregistry.Write, lists int64) ringregistry.Record {
	escrow := w.OldEscrow
	if escrow.Sign() == 0 {
		escrow = w.Entry.EscrowKey
	}
	return ringregistry.Record{Member: w.Entry.Member, Next: w.OldNext, Lists: big.NewInt(lists), EscrowKey: escrow}
}

// replaced is the seeded registry with low in alice's place.
func replaced(t *testing.T, low int64) *ringregistry.Registry {
	t.Helper()
	members := ringregistry.New(t)
	members.Apply(t, entry(low, ringregistry.AllowBit, ringregistry.AllowBit, 0))
	members.Apply(t, entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc1))
	return members
}

// fourRecords is the seeded registry with 0x40 on the allow list, its next index the first of a leaf group.
func fourRecords(t *testing.T) *ringregistry.Registry {
	t.Helper()
	members := seeded(t)
	members.Apply(t, entry(0x40, ringregistry.AllowBit, ringregistry.AllowBit, 0))
	return members
}

// replacedKeyRoot is the seeded root with carol's key replaced by 0xc2, a root no fill-once write reaches.
func replacedKeyRoot(t *testing.T) *big.Int {
	t.Helper()
	members := ringregistry.New(t)
	members.Apply(t, entry(0x10, ringregistry.AllowBit, ringregistry.AllowBit, 0))
	members.Apply(t, entry(0x30, ringregistry.EscrowBit, ringregistry.EscrowBit, 0xc2))
	return members.Root()
}

func TestApplyRecordsKeys(t *testing.T) {
	for _, n := range registry.ApplyWidths {
		ringkey.RequirePinned(t, fmt.Sprintf("custom_ring_apply_records_%d", n), ringkey.Compile(t, applyCircuit(t, n)))
	}
	if _, err := registry.NewApplyRecordsCircuit(3); err == nil {
		t.Fatal("built a capacity no apply key ships")
	}
	unchecked := &registry.ApplyRecordsCircuit{NumWrites: 3, Writes: make([]registry.RecordWrite, 3)}
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, unchecked); err == nil {
		t.Fatal("compiled a capacity no apply key ships")
	}
}

func applyCircuit(t *testing.T, writes int) *registry.ApplyRecordsCircuit {
	t.Helper()
	c, err := registry.NewApplyRecordsCircuit(writes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func policyValue(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return value
}
