package registry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

func trackingEntry(member, key int64) ringregistry.TrackingEntry {
	return ringregistry.TrackingEntry{Member: big.NewInt(member), NullifierPk: big.NewInt(key), CtHash: big.NewInt(key + 1), ListTag: big.NewInt(key + 2)}
}

// The tree holds alice (0x10) and carol (0x30), bob (0x20) is absent between them.
func trackingTree(t *testing.T) *ringregistry.Tracking {
	t.Helper()
	tree := ringregistry.NewTracking(t)
	tree.Apply(t, trackingEntry(0x10, 0xa0))
	tree.Apply(t, trackingEntry(0x30, 0xc0))
	return tree
}

type trackingRowCircuit struct {
	Cond, Root, Member frontend.Variable
	Present            frontend.Variable
	NullifierPk        frontend.Variable
	ListTag            frontend.Variable
	Opening            registry.TrackingOpening
}

func (c *trackingRowCircuit) Define(api frontend.API) error {
	row := c.Opening.Resolve(api, c.Cond, c.Root, c.Member)
	api.AssertIsEqual(row.Present, c.Present)
	api.AssertIsEqual(row.NullifierPk, c.NullifierPk)
	api.AssertIsEqual(row.ListTag, c.ListTag)
	return nil
}

func trackingRow(tree *ringregistry.Tracking, member *big.Int) *trackingRowCircuit {
	opening := tree.Opening(member)
	c := &trackingRowCircuit{Cond: 1, Root: tree.Root(), Member: member, Present: 0, NullifierPk: 0, ListTag: 0, Opening: opening.Wires()}
	if opening.Present {
		c.Present, c.NullifierPk, c.ListTag = 1, opening.Record.NullifierPk, opening.Record.ListTag
	}
	return c
}

func solveTrackingRow(c *trackingRowCircuit) error {
	return test.IsSolved(&trackingRowCircuit{}, c, ecc.BN254.ScalarField())
}

func TestTrackingOpeningResolvesPresentAndAbsentOwners(t *testing.T) {
	tree := trackingTree(t)
	for name, member := range map[string]int64{"present": 0x10, "absent between": 0x20, "absent below": 0x01, "absent above": 0xff} {
		t.Run(name, func(t *testing.T) {
			if err := solveTrackingRow(trackingRow(tree, big.NewInt(member))); err != nil {
				t.Fatal(err)
			}
		})
	}
	off := trackingRow(tree, big.NewInt(0x10))
	off.Cond, off.Root, off.Present, off.NullifierPk, off.ListTag = 0, big.NewInt(1), 0, 0, 0
	if err := solveTrackingRow(off); err != nil {
		t.Fatalf("an unset cond binds the opening: %v", err)
	}
}

func TestTrackingOpeningRefusals(t *testing.T) {
	tree := trackingTree(t)
	alice, bob := big.NewInt(0x10), big.NewInt(0x20)
	root := []string{"gadget.AssertEqualWhen", "registry.TrackingOpening.Resolve"}
	bracket := []string{"ringgadget.AssertOrderedWhen", "registry.TrackingOpening.Resolve"}
	tests := []struct {
		name   string
		member *big.Int
		tamper func(*trackingRowCircuit)
		frames []string
	}{
		{"an enrolled owner claimed absent through its own leaf", alice, func(c *trackingRowCircuit) {
			c.Opening.Present, c.Present, c.NullifierPk, c.ListTag = 0, 0, 0, 0
		}, bracket},
		{"an enrolled owner claimed absent through the sentinel", alice, func(c *trackingRowCircuit) {
			c.Opening, c.Present, c.NullifierPk, c.ListTag = tree.Opening(big.NewInt(1)).Wires(), 0, 0, 0
		}, bracket},
		{"an absent owner claimed present through its low record", bob, func(c *trackingRowCircuit) {
			c.Opening.Present, c.Present = 1, 1
		}, root},
		{"a nullifier key the leaf does not hold", alice, func(c *trackingRowCircuit) {
			c.Opening.Record.NullifierPk, c.NullifierPk = big.NewInt(1), big.NewInt(1)
		}, root},
		{"a list tag the leaf does not hold", alice, func(c *trackingRowCircuit) {
			c.Opening.Record.ListTag, c.ListTag = big.NewInt(1), big.NewInt(1)
		}, root},
		{"another ring's root", alice, func(c *trackingRowCircuit) { c.Root = big.NewInt(1) }, root},
		{"a present flag that is no bit", alice, func(c *trackingRowCircuit) { c.Opening.Present = 2 }, []string{"[assertIsBoolean]", "registry.TrackingOpening.Resolve"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := trackingRow(tree, tt.member)
			tt.tamper(c)
			ringtest.RequireRefused(t, solveTrackingRow(c), tt.frames...)
		})
	}
	t.Run("an index past the capacity", func(t *testing.T) {
		c := trackingRow(tree, alice)
		c.Opening.Path.Index = new(big.Int).Add(big.NewInt(1), big.NewInt(registry.TrackingCapacity))
		ringtest.RequireRefused(t, solveTrackingRow(c), "[ToBinary]", "registry.TrackingPath.digits")
	})
}

type trackingVector struct {
	EmptyRoot     string `json:"empty_root"`
	Member        string `json:"member"`
	NullifierPk   string `json:"nullifier_pk"`
	CtHash        string `json:"ct_hash"`
	ListTag       string `json:"list_tag"`
	EntryHash     string `json:"entry_hash"`
	ChainFromZero string `json:"chain_from_zero"`
	ListSalt      string `json:"list_salt"`
	SecretListTag string `json:"secret_list_tag"`
}

// The host twin mirrors both gadgets, the Rust side pins them through the same vector.
func TestTrackingHashesMatchRustVector(t *testing.T) {
	var vectors struct {
		Tracking trackingVector `json:"tracking"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.Tracking
	if got := ringregistry.NewTracking(t).Root(); got.Cmp(ringtest.VectorField(t, v.EmptyRoot)) != 0 {
		t.Fatalf("empty root %x, Rust %s", got, v.EmptyRoot)
	}
	entry := ringregistry.TrackingEntry{
		Member: ringtest.VectorField(t, v.Member), NullifierPk: ringtest.VectorField(t, v.NullifierPk), CtHash: ringtest.VectorField(t, v.CtHash),
		ListTag: ringtest.VectorField(t, v.ListTag),
	}
	hash := entry.Hash(t)
	if hash.Cmp(ringtest.VectorField(t, v.EntryHash)) != 0 {
		t.Fatalf("entry hash %x, Rust %s", hash, v.EntryHash)
	}
	if chain := ringtest.MustPoseidonHash(t, big.NewInt(0), hash); chain.Cmp(ringtest.VectorField(t, v.ChainFromZero)) != 0 {
		t.Fatalf("chain %x, Rust %s", chain, v.ChainFromZero)
	}
	gadgets := &listDerivationCircuit{Salt: ringtest.VectorField(t, v.ListSalt), Tag: ringtest.VectorField(t, v.SecretListTag)}
	if err := test.IsSolved(&listDerivationCircuit{}, gadgets, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	entryGadget := &trackingEntryCircuit{Entry: entry.Wires(), Hash: hash}
	if err := test.IsSolved(&trackingEntryCircuit{}, entryGadget, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

type listDerivationCircuit struct {
	Salt, Tag frontend.Variable
}

func (c *listDerivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(shared.ListTag(api, c.Salt), c.Tag)
	return nil
}

type trackingEntryCircuit struct {
	Entry registry.TrackingEntry
	Hash  frontend.Variable
}

func (c *trackingEntryCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Entry.Hash(api), c.Hash)
	return nil
}

type sharedTrackingCircuit struct {
	Active, Root frontend.Variable
	Records      []registry.TrackingRecord
	Proof        registry.SharedQuadProof
}

func (c *sharedTrackingCircuit) Define(api frontend.API) error {
	leaves := make([]frontend.Variable, len(c.Records))
	for i, record := range c.Records {
		leaves[i] = record.Hash(api)
	}
	c.Proof.AssertLeavesWhen(api, c.Active, c.Root, leaves)
	return nil
}

// Both canopy branches fold at the tracking height.
func TestSharedTrackingProofOpensLeaves(t *testing.T) {
	tree := ringregistry.NewTracking(t)
	for m := int64(1); m <= 20; m++ {
		tree.Apply(t, trackingEntry(m*10, 0x1000+m))
	}
	for _, openings := range []int{1, 4, 17} {
		indices := make([]uint64, openings)
		records := make([]registry.TrackingRecord, openings)
		for i := range indices {
			member := big.NewInt(int64(i+1) * 10)
			opening := tree.Opening(member)
			indices[i], records[i] = opening.Path.Index, opening.Record.Wires()
		}
		proof, err := tree.SharedProof(indices)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := registry.NewTrackingProof(openings)
		if err != nil {
			t.Fatal(err)
		}
		circuit := func() *sharedTrackingCircuit {
			return &sharedTrackingCircuit{Records: make([]registry.TrackingRecord, openings), Proof: shape}
		}
		assignment := &sharedTrackingCircuit{Active: 1, Root: tree.Root(), Records: records, Proof: proof}
		if err := test.IsSolved(circuit(), assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%d openings: %v", openings, err)
		}
		records[0].ListTag = big.NewInt(1)
		if test.IsSolved(circuit(), assignment, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("%d openings: a leaf outside the tree opened", openings)
		}
	}
	if proof, err := registry.NewTrackingProof(1); err != nil || len(proof.Paths[0].Siblings) != registry.TrackingHeight {
		t.Fatalf("tracking proof height %v, %v", proof, err)
	}
	if proof, err := registry.NewSharedQuadProof(1); err != nil || len(proof.Paths[0].Siblings) != registry.Height {
		t.Fatalf("policy proof height %v, %v", proof, err)
	}
	if proof, err := registry.NewTrackingProof(1); err != nil || proof.Validate(1) != nil {
		t.Fatalf("a tracking proof fails its own shape: %v", err)
	}
	policyShape, err := registry.NewSharedQuadProof(1)
	if err != nil {
		t.Fatal(err)
	}
	policyShape.TreeHeight = registry.TrackingHeight
	if policyShape.Validate(1) == nil {
		t.Fatal("a path of the policy height passes at the tracking height")
	}
}
