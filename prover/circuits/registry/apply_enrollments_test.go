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

type enrollmentBatch struct {
	circuit *registry.ApplyEnrollmentsCircuit
	writes  []ringregistry.TrackingWrite
	chain   []*big.Int
}

func applyEnrollments(t *testing.T, tree *ringregistry.Tracking, n int, chainStart *big.Int, entries ...ringregistry.TrackingEntry) *enrollmentBatch {
	t.Helper()
	c := enrollmentCircuit(t, n)
	c.OldRoot, c.OldNextIndex, c.ChainStart, c.Count = tree.Root(), new(big.Int).SetUint64(tree.NextIndex()), chainStart, len(entries)
	b := &enrollmentBatch{circuit: c, chain: []*big.Int{chainStart}}
	for i := range c.Writes {
		c.Writes[i] = ringregistry.ZeroTrackingWrite().Wires()
	}
	for i, e := range entries {
		w := tree.Apply(t, e)
		b.writes = append(b.writes, w)
		c.Writes[i] = w.Wires()
		b.chain = append(b.chain, ringtest.MustPoseidonHash(t, b.chain[i], e.Hash(t)))
	}
	c.NewRoot, c.NewNextIndex, c.ChainEnd = tree.Root(), new(big.Int).SetUint64(tree.NextIndex()), b.chain[len(entries)]
	b.bind(t)
	return b
}

func (b *enrollmentBatch) bind(t *testing.T) {
	t.Helper()
	c := b.circuit
	statement := []*big.Int{big.NewInt(shared.ApplyEnrollmentsDomain)}
	for _, v := range []frontend.Variable{c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count} {
		statement = append(statement, ringtest.AsBigInt(v))
	}
	c.PublicInputHash = spptest.MustHashChain4(t, statement)
}

func solveEnrollments(t *testing.T, c *registry.ApplyEnrollmentsCircuit) error {
	t.Helper()
	return test.IsSolved(enrollmentCircuit(t, c.NumWrites), c, ecc.BN254.ScalarField())
}

func enrollmentCircuit(t *testing.T, writes int) *registry.ApplyEnrollmentsCircuit {
	t.Helper()
	c, err := registry.NewApplyEnrollmentsCircuit(writes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestApplyEnrollmentsAppliesEntriesInNamedOrder(t *testing.T) {
	tree := trackingTree(t)
	b := applyEnrollments(t, tree, registry.ApplyBatch, big.NewInt(0x5eed),
		trackingEntry(0x20, 0xb0), // insert between alice and carol
		trackingEntry(0x05, 0x50), // insert below every owner
		trackingEntry(0x40, 0xd0), // insert above every owner
		trackingEntry(0x28, 0xe0), // insert after an insert of the same batch
	)
	if err := solveEnrollments(t, b.circuit); err != nil {
		t.Fatal(err)
	}
	if tree.NextIndex() != 7 {
		t.Fatalf("next index %d, want the sentinel and six owners", tree.NextIndex())
	}
	bob := tree.Opening(big.NewInt(0x20))
	if !bob.Present || bob.Record.Next.Int64() != 0x28 || bob.Record.NullifierPk.Int64() != 0xb0 {
		t.Fatalf("bob after the batch: %+v", bob.Record)
	}
	for _, n := range registry.ApplyWidths {
		one := applyEnrollments(t, tree, n, big.NewInt(1), trackingEntry(int64(0x1000+n), int64(0xe000+n)))
		if err := solveEnrollments(t, one.circuit); err != nil {
			t.Fatalf("width %d: %v", n, err)
		}
	}
}

// Each case forges a batch consistent with every rule but the one it names, whose frames refuse it.
func TestApplyEnrollmentsRefusals(t *testing.T) {
	gate := []string{"gadget.AssertEqualWhen", "registry.EnrollmentWrite.apply"}
	bracket := []string{"ringgadget.AssertOrderedWhen", "registry.EnrollmentWrite.apply"}
	define := []string{"[assertIsEqual]", "registry.(*ApplyEnrollmentsCircuit).Define"}
	insert := trackingEntry(0x20, 0xb0)
	second := trackingEntry(0x28, 0xe0)
	tests := []struct {
		name    string
		entries []ringregistry.TrackingEntry
		tamper  func(*testing.T, *enrollmentBatch)
		frames  []string
	}{
		{"a present owner inserted again through the record linking to it", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			tree := trackingTree(t)
			sentinel := tree.Opening(big.NewInt(1))
			alice := trackingEntry(0x10, 0xa0)
			w := ringregistry.TrackingWrite{Entry: alice, Slot: tree.Path(tree.NextIndex()), Low: sentinel.Record, LowPath: sentinel.Path}
			b.circuit.Writes[0] = w.Wires()
		}, bracket},
		{"a present owner inserted again over its own leaf", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			tree := trackingTree(t)
			alice := tree.Opening(big.NewInt(0x10))
			w := ringregistry.TrackingWrite{Entry: trackingEntry(0x10, 0xa0), Slot: alice.Path, Low: alice.Record, LowPath: alice.Path}
			b.circuit.Writes[0] = w.Wires()
		}, bracket},
		{"an insert past the next index", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.Writes[0].Slot.Index = 4
		}, gate},
		{"an insert over a written leaf", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.Writes[0].Slot = trackingTree(t).Opening(big.NewInt(0x30)).Path.Wires()
		}, gate},
		{"an insert under another low record", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.Writes[0].Low.ListTag = big.NewInt(1)
		}, gate},
		{"a substituted entry", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			// The tree moves to the forged key, the chain end the program computed stays.
			forged := insert
			forged.NullifierPk = big.NewInt(0x77)
			moved := applyEnrollments(t, trackingTree(t), 1, b.chain[0], forged)
			moved.circuit.ChainEnd = b.circuit.ChainEnd
			moved.bind(t)
			*b = *moved
		}, define},
		{"entries out of the named order", []ringregistry.TrackingEntry{insert, second}, func(t *testing.T, b *enrollmentBatch) {
			swapped := applyEnrollments(t, trackingTree(t), registry.ApplyBatch, b.chain[0], second, insert)
			swapped.circuit.ChainEnd = b.circuit.ChainEnd
			swapped.bind(t)
			*b = *swapped
		}, define},
		{"a chain end short of the applied entries", []ringregistry.TrackingEntry{insert, second}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.ChainEnd = b.chain[1]
			b.bind(t)
		}, define},
		{"a next index past the inserts", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.NewNextIndex = new(big.Int).Add(ringtest.AsBigInt(b.circuit.NewNextIndex), big.NewInt(1))
			b.bind(t)
		}, define},
		{"a stale old root", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.OldRoot = big.NewInt(1)
			b.bind(t)
		}, gate},
		{"an empty batch", []ringregistry.TrackingEntry{insert}, func(t *testing.T, b *enrollmentBatch) {
			b.circuit.Count = 0
			b.bind(t)
		}, []string{"ringgadget.SelectCount"}},
		{"the statement of another batch", []ringregistry.TrackingEntry{insert}, func(_ *testing.T, b *enrollmentBatch) {
			b.circuit.PublicInputHash = big.NewInt(1)
		}, define},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := 1
			if len(tt.entries) > 1 {
				n = registry.ApplyBatch
			}
			b := applyEnrollments(t, trackingTree(t), n, big.NewInt(0x5eed), tt.entries...)
			if err := solveEnrollments(t, b.circuit); err != nil {
				t.Fatalf("honest batch: %v", err)
			}
			tt.tamper(t, b)
			ringtest.RequireRefused(t, solveEnrollments(t, b.circuit), tt.frames...)
		})
	}
}

func TestApplyEnrollmentsAtCapacity(t *testing.T) {
	capacity := big.NewInt(registry.TrackingCapacity)
	b := applyEnrollments(t, trackingTree(t), 1, big.NewInt(0), trackingEntry(0x20, 0xb0))
	b.circuit.Writes[0].Slot.Index = capacity
	b.circuit.OldNextIndex, b.circuit.NewNextIndex = capacity, new(big.Int).Add(capacity, big.NewInt(1))
	b.bind(t)
	ringtest.RequireRefused(t, solveEnrollments(t, b.circuit), "[ToBinary]", "registry.TrackingPath.digits")
}

func TestApplyEnrollmentsKeys(t *testing.T) {
	for _, n := range registry.ApplyWidths {
		ringkey.RequirePinned(t, fmt.Sprintf("custom_ring_apply_enrollments_%d", n), ringkey.Compile(t, enrollmentCircuit(t, n)))
	}
	if _, err := registry.NewApplyEnrollmentsCircuit(3); err == nil {
		t.Fatal("built a capacity no apply key ships")
	}
	unchecked := &registry.ApplyEnrollmentsCircuit{NumWrites: 3, Writes: make([]registry.EnrollmentWrite, 3)}
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, unchecked); err == nil {
		t.Fatal("compiled a capacity no apply key ships")
	}
}
