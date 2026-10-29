package registry_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
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
	for _, app := range v.Applications {
		t.Run(app.Name, func(t *testing.T) {
			queued := slices.Concat(app.Pending, app.AuthorityWrites)
			entries := make([]ringregistry.Entry, len(queued))
			chain := app.ChainStart.Int
			for i, q := range queued {
				entries[i] = q.Entry()
				hash := entries[i].Hash(t)
				chain = ringtest.MustPoseidonHash(t, chain, hash)
				if hash.Cmp(q.EntryHash.Int) != 0 || chain.Cmp(q.Chain.Int) != 0 {
					t.Fatalf("entry %d hash %x chain %x, Rust %x %x", i, hash, chain, q.EntryHash.Int, q.Chain.Int)
				}
			}
			n := registry.ApplyBatch
			if app.Count == 1 {
				n = 1
			}
			b := applyBatch(t, members, n, app.ChainStart.Int, entries...)
			c := b.circuit
			for name, pair := range map[string][2]*big.Int{
				"old root":       {ringtest.AsBigInt(c.OldRoot), app.OldRoot.Int},
				"new root":       {ringtest.AsBigInt(c.NewRoot), app.NewRoot.Int},
				"old next index": {ringtest.AsBigInt(c.OldNextIndex), new(big.Int).SetUint64(app.OldNextIndex)},
				"new next index": {ringtest.AsBigInt(c.NewNextIndex), new(big.Int).SetUint64(app.NewNextIndex)},
				"chain end":      {ringtest.AsBigInt(c.ChainEnd), app.ChainEnd.Int},
				"statement":      {ringtest.AsBigInt(c.PublicInputHash), app.StatementHash.Int},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Fatalf("%s %x, Rust %x", name, pair[0], pair[1])
				}
			}
			for i, w := range app.Writes {
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
		values := []*big.Int{w.Entry.Member, w.Entry.Mask, w.Entry.Value, w.Entry.EscrowKey, w.OldNext, w.OldLists, w.OldEscrow,
			w.Low.Member, w.Low.Next, w.Low.Lists, w.Low.EscrowKey, new(big.Int).SetUint64(w.Slot.Index), new(big.Int).SetUint64(w.LowPath.Index)}
		for _, path := range []ringregistry.Path{w.Slot, w.LowPath} {
			for _, row := range path.Siblings {
				values = append(values, row[:]...)
			}
		}
		return values
	}
	return a.Exists == b.Exists && slices.EqualFunc(fields(a), fields(b), func(p, q *big.Int) bool { return p.Cmp(q) == 0 })
}
