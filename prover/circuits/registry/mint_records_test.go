package registry_test

import (
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"math/big"
	"testing"
)

func TestMintRecordsMatchRustAndPreserveSettings(t *testing.T) {
	var vector struct {
		Rows []struct {
			Member, Field ringtest.Hex
			Limits        []ringtest.Hex
			Amount        string
			EntryHash     ringtest.Hex `json:"entry_hash"`
		}
		Root ringtest.Hex
	}
	ringtest.ReadVector(t, "registry/mint-records.json", &vector)
	tree := ringregistry.New(t)
	entries := make([]ringregistry.Entry, len(vector.Rows))
	for i, row := range vector.Rows {
		amount, ok := new(big.Int).SetString(row.Amount, 10)
		if !ok {
			t.Fatal("amount")
		}
		entries[i] = ringregistry.Entry{Member: row.Member.Int, Mask: big.NewInt(0), Value: big.NewInt(0), EscrowKey: big.NewInt(0), MintPolicy: new(big.Int).Or(row.Field.Int, new(big.Int).Lsh(big.NewInt(1), 192)), WithdrawalThreshold: amount, AssetLimits: ringregistry.Limits{row.Limits[0].Int, row.Limits[1].Int}}
		if entries[i].Hash(t).Cmp(row.EntryHash.Int) != 0 {
			t.Fatal("queue hash differs from Rust")
		}
	}
	b := applyBatch(t, tree, 16, big.NewInt(0), entries...)
	if err := solve(t, b.circuit); err != nil {
		t.Fatal(err)
	}
	if tree.Root().Cmp(vector.Root.Int) != 0 {
		t.Fatal("root differs from Rust")
	}
	for _, e := range []ringregistry.Entry{entry(9, 1, 1, 0), entry(9, 128, 128, 99)} {
		b = applyBatch(t, tree, 1, b.chain[len(b.chain)-1], e)
		if err := solve(t, b.circuit); err != nil {
			t.Fatal(err)
		}
		got := tree.Opening(big.NewInt(9)).Record
		if got.WithdrawalThreshold.Uint64() != 900 || got.MintPolicy.Cmp(vector.Rows[8].Field.Int) != 0 || got.AssetLimits[1].Cmp(vector.Rows[8].Limits[1].Int) != 0 {
			t.Fatal("settings lost")
		}
	}
	clear := entry(9, 0, 0, 0)
	clear.MintPolicy = new(big.Int).Lsh(big.NewInt(1), 192)
	b = applyBatch(t, tree, 1, b.chain[len(b.chain)-1], clear)
	if err := solve(t, b.circuit); err != nil {
		t.Fatal(err)
	}
	got := tree.Opening(big.NewInt(9)).Record
	if got.WithdrawalThreshold.Sign() != 0 || got.MintPolicy.Sign() != 0 || !got.AssetLimits.IsZero() || got.EscrowKey.Uint64() != 99 || got.Lists.Uint64() != 129 {
		t.Fatal("clearing changed other fields")
	}
	b.circuit.Writes[0].OldWithdrawalThreshold = 901
	if solve(t, b.circuit) == nil {
		t.Fatal("forged old threshold admitted")
	}
}
