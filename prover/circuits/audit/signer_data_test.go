package audit_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const countPredicate = "audit.SignerDataCounts.Assert"

var (
	aliceIdentity = big.NewInt(0x0a11)
	bobIdentity   = big.NewInt(0x0b0b)
	carolIdentity = big.NewInt(0x0c0c)
)

// signerDataCircuit runs the count section alone over opened slots.
type signerDataCircuit struct {
	Packed      frontend.Variable
	SignerCount frontend.Variable
	Members     []frontend.Variable
	Outputs     []shared.UtxoWires
}

func (c *signerDataCircuit) Define(api frontend.API) error {
	count := ringgadget.SelectCount(api, c.SignerCount, 0, len(c.Members)+1)
	slots := make([]shared.Output, len(c.Outputs))
	for o, output := range c.Outputs {
		slots[o] = output.Open(api)
	}
	audit.SignerDataCounts{Packed: c.Packed, Members: c.Members, Active: count.Active, Slots: slots}.Assert(api)
	return nil
}

func slotOf(owner *big.Int, dataHash, ringDataHash int64) shared.UtxoWires {
	return shared.UtxoWires{Domain: transaction.UtxoDomain, TreeID: 9, OwnerPkHash: owner, NullifierPk: 7, Asset: 5, Amount: 10, Blinding: 3, DataHash: dataHash, RingDataHash: ringDataHash, RingProgramID: 0x7711}
}

func dummySlot() shared.UtxoWires {
	return shared.UtxoWires{Domain: transaction.DummyDomain, TreeID: 0, OwnerPkHash: 0, NullifierPk: 0, Asset: 0, Amount: 0, Blinding: 3, DataHash: 0, RingDataHash: 0, RingProgramID: 0}
}

// witnessOf pads the run to members slots and packs the counts in run order.
func witnessOf(run []*big.Int, members int, outputs []shared.UtxoWires, counts ...int64) *signerDataCircuit {
	c := &signerDataCircuit{SignerCount: len(run), Members: make([]frontend.Variable, members), Outputs: outputs}
	for k := range c.Members {
		c.Members[k] = 0
		if k < len(run) {
			c.Members[k] = run[k]
		}
	}
	c.Packed = packedCounts(counts...)
	return c
}

func packedCounts(counts ...int64) *big.Int {
	packed := big.NewInt(0)
	for entry, count := range counts {
		packed.Add(packed, new(big.Int).Lsh(big.NewInt(count), uint(entry*audit.SignerDataEntryBits)))
	}
	return packed
}

func solveCounts(c *signerDataCircuit) error {
	shape := &signerDataCircuit{Members: make([]frontend.Variable, len(c.Members)), Outputs: make([]shared.UtxoWires, len(c.Outputs))}
	return test.IsSolved(shape, c, ecc.BN254.ScalarField())
}

// Bob owns two data-bearing slots, Alice one and an ordinary payment.
func mixedSlots() []shared.UtxoWires {
	return []shared.UtxoWires{slotOf(bobIdentity, 0x77, 0), slotOf(aliceIdentity, 0, 0), slotOf(bobIdentity, 0x78, 0), slotOf(aliceIdentity, 0x79, 0)}
}

func TestSignerDataCountsSolve(t *testing.T) {
	alone := func(slot shared.UtxoWires) []shared.UtxoWires {
		return []shared.UtxoWires{slot, dummySlot()}
	}
	dummyWithData := dummySlot()
	dummyWithData.OwnerPkHash, dummyWithData.DataHash = aliceIdentity, 0x77
	for _, tt := range []struct {
		name string
		c    *signerDataCircuit
	}{
		{"each entry in run order", witnessOf([]*big.Int{aliceIdentity, bobIdentity}, 4, mixedSlots(), 1, 2)},
		{"the same run reordered", witnessOf([]*big.Int{bobIdentity, aliceIdentity}, 4, mixedSlots(), 2, 1)},
		{"an empty run", witnessOf(nil, 4, mixedSlots())},
		{"a key with fewer inputs than entries", witnessOf([]*big.Int{bobIdentity}, 1, mixedSlots(), 2)},
		{"a signer of no data-bearing slot", witnessOf([]*big.Int{carolIdentity}, 4, mixedSlots(), 0)},
		{"an ordinary output never counts", witnessOf([]*big.Int{aliceIdentity}, 4, alone(slotOf(aliceIdentity, 0, 0)), 0)},
		{"a ring data hash alone never counts", witnessOf([]*big.Int{aliceIdentity}, 4, alone(slotOf(aliceIdentity, 0, 0x78)), 0)},
		{"a dummy never counts", witnessOf([]*big.Int{aliceIdentity}, 4, []shared.UtxoWires{dummyWithData}, 0)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := solveCounts(tt.c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every lie about the packed element fails at the one predicate, past the statement that binds it.
func TestSignerDataCountsRefusals(t *testing.T) {
	run := []*big.Int{aliceIdentity, bobIdentity}
	for _, tt := range []struct {
		name   string
		packed *big.Int
		frame  string
	}{
		{"counts at the wrong signer positions", packedCounts(2, 1), "[assertIsEqual]"},
		{"a nonzero entry past the run", packedCounts(1, 2, 1), "[assertIsEqual]"},
		{"a nonzero last entry past the run", new(big.Int).Add(packedCounts(1, 2), new(big.Int).Lsh(big.NewInt(1), (audit.SignerDataEntries-1)*audit.SignerDataEntryBits)), "[assertIsEqual]"},
		{"a bit past the last entry", new(big.Int).Add(packedCounts(1, 2), new(big.Int).Lsh(big.NewInt(1), audit.SignerDataEntries*audit.SignerDataEntryBits)), "[ToBinary]"},
		{"a count carried into its neighbor", packedCounts(1+1<<audit.SignerDataEntryBits, 2), "[assertIsEqual]"},
		{"a count short of a data-bearing output", packedCounts(0, 2), "[assertIsEqual]"},
		{"an ordinary output counted", packedCounts(2, 2), "[assertIsEqual]"},
		{"a zero element over data-bearing outputs", packedCounts(), "[assertIsEqual]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := witnessOf(run, 4, mixedSlots(), 1, 2)
			c.Packed = tt.packed
			ringtest.RequireRefused(t, solveCounts(c), tt.frame, countPredicate)
		})
	}
	t.Run("a nonzero element over an empty run", func(t *testing.T) {
		c := witnessOf(nil, 4, mixedSlots(), 1)
		ringtest.RequireRefused(t, solveCounts(c), "[assertIsEqual]", countPredicate)
	})
	t.Run("a nonzero entry on a key with fewer inputs than entries", func(t *testing.T) {
		c := witnessOf([]*big.Int{bobIdentity}, 1, mixedSlots(), 2, 1)
		ringtest.RequireRefused(t, solveCounts(c), "[assertIsEqual]", countPredicate)
	})
}

// The last entry reads its own bits and a member past it has no bits to publish a count in.
func TestRunsPastTheLastEntry(t *testing.T) {
	wide := make([]*big.Int, audit.SignerDataEntries+1)
	for k := range wide {
		wide[k] = big.NewInt(0x1000 + int64(k))
	}
	counts := make([]int64, audit.SignerDataEntries)
	t.Run("a member past the last entry with no data-bearing slot", func(t *testing.T) {
		outputs := []shared.UtxoWires{slotOf(wide[audit.SignerDataEntries], 0, 0)}
		if err := solveCounts(witnessOf(wide, len(wide), outputs, counts...)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the last entry counts", func(t *testing.T) {
		outputs := []shared.UtxoWires{slotOf(wide[audit.SignerDataEntries-1], 0x77, 0)}
		last := append([]int64{}, counts...)
		last[audit.SignerDataEntries-1] = 1
		if err := solveCounts(witnessOf(wide, len(wide), outputs, last...)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a member past the last entry with a data-bearing slot", func(t *testing.T) {
		outputs := []shared.UtxoWires{slotOf(wide[audit.SignerDataEntries], 0x77, 0)}
		ringtest.RequireRefused(t, solveCounts(witnessOf(wide, len(wide), outputs, counts...)), "[assertIsEqual]", countPredicate)
	})
}

// One signer owning every output of the widest key fills its entry below the next one.
func TestAKeysWidestCountFitsItsEntry(t *testing.T) {
	const widest = 16
	outputs := make([]shared.UtxoWires, widest)
	for o := range outputs {
		outputs[o] = slotOf(aliceIdentity, 0x77+int64(o), 0)
	}
	if err := solveCounts(witnessOf([]*big.Int{aliceIdentity, bobIdentity}, 4, outputs, widest, 0)); err != nil {
		t.Fatal(err)
	}
}
