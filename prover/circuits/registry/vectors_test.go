package registry_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

// The host twin builds the Rust witnesses and the circuit accepts them.
func TestApplyRecordsMatchesRustVectors(t *testing.T) {
	var v ringregistry.Vector
	ringtest.ReadVector(t, "registry/ring-records.json", &v)
	members := ringregistry.New(t)
	if members.Root().Cmp(v.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", members.Root(), v.EmptyRoot.Int)
	}
	registryAddress := ringtest.VectorBytes(t, v.Registry, 32)
	for _, update := range v.Updates {
		t.Run(update.Name, func(t *testing.T) {
			// 1. The chain starts at the registry and revision the program binds, never at an earlier update's end.
			if start := ringregistry.ChainStart(t, registryAddress, update.Revision); start.Cmp(update.ChainStart.Int) != 0 {
				t.Fatalf("chain start %x, Rust %x", start, update.ChainStart.Int)
			}
			// 2. Every write of the batch enters the chain in instruction order.
			entries := make([]ringregistry.Entry, len(update.Writes))
			chain := update.ChainStart.Int
			for i, write := range update.Writes {
				entries[i] = write.Entry()
				hash := entries[i].Hash(t)
				chain = ringtest.MustPoseidonHash(t, chain, hash)
				if hash.Cmp(write.EntryHash.Int) != 0 || chain.Cmp(write.Chain.Int) != 0 {
					t.Fatalf("write %d hash %x chain %x, Rust %x %x", i, hash, chain, write.EntryHash.Int, write.Chain.Int)
				}
			}
			// 3. The host twin replays the batch to the Rust statement and proof inputs, and the circuit accepts them.
			b := applyBatch(t, members, update.Width, update.ChainStart.Int, entries...)
			c := b.circuit
			for name, pair := range map[string][2]*big.Int{
				"old root":       {ringtest.AsBigInt(c.OldRoot), update.OldRoot.Int},
				"new root":       {ringtest.AsBigInt(c.NewRoot), update.NewRoot.Int},
				"old next index": {ringtest.AsBigInt(c.OldNextIndex), new(big.Int).SetUint64(update.OldNextIndex)},
				"new next index": {ringtest.AsBigInt(c.NewNextIndex), new(big.Int).SetUint64(update.NewNextIndex)},
				"chain end":      {ringtest.AsBigInt(c.ChainEnd), update.ChainEnd.Int},
				"statement":      {ringtest.AsBigInt(c.PublicInputHash), update.StatementHash.Int},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Fatalf("%s %x, Rust %x", name, pair[0], pair[1])
				}
			}
			for i, w := range update.ProofInputs {
				rust := w.Write(t)
				if !sameWrite(b.writes[i], rust) {
					t.Fatalf("write %d differs from the Rust witness", i)
				}
				c.Writes[i] = writeWires(rust)
			}
			if err := solve(t, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func sameWrite(a, b ringregistry.Write) bool {
	fields := func(w ringregistry.Write) []*big.Int {
		values := []*big.Int{w.Entry.Member, w.Entry.Mask, w.Entry.Value, w.OldNext, w.OldLists,
			w.Low.Member, w.Low.Next, w.Low.Lists, new(big.Int).SetUint64(w.Slot.Index), new(big.Int).SetUint64(w.LowPath.Index)}
		for _, path := range []ringregistry.Path{w.Slot, w.LowPath} {
			for _, row := range path.Siblings {
				values = append(values, row[:]...)
			}
		}
		return values
	}
	return a.Exists == b.Exists && slices.EqualFunc(fields(a), fields(b), func(p, q *big.Int) bool { return p.Cmp(q) == 0 })
}
