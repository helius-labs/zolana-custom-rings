package circuits_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func solved(t *testing.T, s *ringmerge.Statement) error {
	t.Helper()
	return test.IsSolved(&circuits.MergeCircuit{}, s.Circuit, ecc.BN254.ScalarField())
}

// The statement stays the program's, each case changes what the prover claims behind it.
func TestMergeRefusals(t *testing.T) {
	define := []string{"[assertIsEqual]", "circuits.(*MergeCircuit).Define"}
	tests := []struct {
		name   string
		tamper func(*ringmerge.Statement)
	}{
		{"another amount", func(s *ringmerge.Statement) { s.Circuit.Amount = big.NewInt(13) }},
		{"another owner key", func(s *ringmerge.Statement) { s.Circuit.OwnerKey[0] = 0 }},
		{"another mint", func(s *ringmerge.Statement) { s.Circuit.MintChunks[1] = 0 }},
		{"another asset", func(s *ringmerge.Statement) { s.Circuit.Asset = 1 }},
		{"another owner identity", func(s *ringmerge.Statement) { s.Circuit.OwnerPkHash = 1 }},
		{"another seed", func(s *ringmerge.Statement) { s.Circuit.Seed = big.NewInt(20) }},
		{"the zero seed", func(s *ringmerge.Statement) { s.Circuit.Seed = big.NewInt(0) }},
		{"another nullifier key", func(s *ringmerge.Statement) { s.Circuit.NullifierPk = big.NewInt(5) }},
		{"another ring", func(s *ringmerge.Statement) { s.Circuit.RingProgramID = big.NewInt(0x5a0f) }},
		{"another output tree", func(s *ringmerge.Statement) { s.Circuit.OutputTreeID = 10 }},
		{"another ring data hash", func(s *ringmerge.Statement) { s.Circuit.OutputRingDataHash = 1 }},
		{"another first nullifier", func(s *ringmerge.Statement) { s.Circuit.FirstNullifier = big.NewInt(1) }},
		{"another auditor", func(s *ringmerge.Statement) { s.Circuit.AuditorPk[1] = 0 }},
		{"a ciphertext of another record", func(s *ringmerge.Statement) {
			s.Record = slices.Clone(s.Record)
			s.Record[15] ^= 1
			s.Rebind(t)
		}},
	}
	for _, tt := range tests {
		for _, build := range []func(testing.TB) *ringmerge.Statement{ringmerge.Build, ringmerge.BuildZeroKey} {
			t.Run(tt.name, func(t *testing.T) {
				s := build(t)
				tt.tamper(s)
				ringtest.RequireRefused(t, solved(t, s), define...)
			})
		}
	}
}

// A witness off the record's opening refuses inside the record encoder.
func TestMergeRecordOffItsOpening(t *testing.T) {
	for name, tamper := range map[string]func(*ringmerge.Statement){
		"another owner key": func(s *ringmerge.Statement) { s.Circuit.OwnerKey[0] = 0 },
		"another mint":      func(s *ringmerge.Statement) { s.Circuit.MintChunks[1] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			s := ringmerge.Build(t)
			tamper(s)
			ringtest.RequireRefused(t, solved(t, s), "audit.MergeRecord.Encode")
		})
	}
	for name, offset := range map[string]int{"a sealed seed off the opening": audit.RecordLen, "a sealed blinding off the opening": audit.RecordLen - 1} {
		t.Run(name, func(t *testing.T) {
			s := ringmerge.Build(t)
			s.Record = slices.Clone(s.Record)
			s.Record[offset] ^= 1
			s.Rebind(t)
			ringtest.RequireRefused(t, solved(t, s), "circuits.(*MergeCircuit).Define")
		})
	}
}

// The merge record is sealed to the recipient key its envelope gives the auditor.
func TestMergeRecordIsSealedToTheEnvelopesKey(t *testing.T) {
	s := ringmerge.Build(t)
	if err := solved(t, s); err != nil {
		t.Fatal(err)
	}
	t.Run("the owner opens the record under its viewing key", func(t *testing.T) {
		record := ringprotocol.SealRecord(t, s.Keys.EphSk(), s.RecipientKey, [16]byte{}, 0, ringmerge.FirstNullifier, shared.MergeOutputInfo, s.Ciphertext(t))
		if !slices.Equal(record, s.Record) {
			t.Fatal("the record differs from the merged opening")
		}
	})
	t.Run("an envelope naming another key", func(t *testing.T) {
		s := ringmerge.Build(t)
		ringtest.SetBytes(s.Circuit.RecipientKey[:], func() []byte { key := ringaudit.ViewingKey(t, 0x41); return key[:] }())
		ringtest.RequireRefused(t, solved(t, s), "circuits.(*MergeCircuit).Define")
	})
	t.Run("a record under the transfer label", func(t *testing.T) {
		s := ringmerge.Build(t)
		transferRecord := ringprotocol.SealRecord(t, s.Keys.EphSk(), s.RecipientKey, [16]byte{}, 0, ringmerge.FirstNullifier, shared.OutputRecordInfo, s.Record)
		if slices.Equal(transferRecord, s.Ciphertext(t)) {
			t.Fatal("the merge record shares the transfer keystream")
		}
	})
}

// A byte outside 0..255 packing to the same identity would open another record.
func TestMergeOwnerKeyBytesStayBytes(t *testing.T) {
	s := ringmerge.Build(t)
	key := &s.Circuit.OwnerKey
	key[0], key[1] = ringtest.AsBigInt(key[0]).Int64()-1, ringtest.AsBigInt(key[1]).Int64()+256
	ringtest.RequireRefused(t, solved(t, s), "lookup query too large")
}

// The record's amount is eight bytes, a wider amount has no record.
func TestMergeRefusesAnAmountAboveItsBytes(t *testing.T) {
	s := ringmerge.Build(t)
	s.Amount = new(big.Int).Lsh(big.NewInt(1), 64)
	s.Circuit.Amount = s.Amount
	s.OutputHash = spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: spptest.MustOwnerHash(t, s.OwnerPkHash, s.NullifierPk), Asset: ringtest.AssetField(t, s.Mint), Amount: s.Amount,
		Blinding: s.OutputBlinding, DataHash: big.NewInt(0), RingDataHash: ringmerge.RingData, RingProgramID: ringmerge.RingProgramID,
	}, big.NewInt(ringmerge.OutputTreeID))
	s.Circuit.OutputUtxoHash = s.OutputHash
	s.Rebind(t)
	ringtest.RequireRefused(t, solved(t, s), "[ToBinary]", "audit.RecordOpening.Encode")
}

func TestMergeTrackingRow(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, *ringmerge.Statement)
	}{
		{"another root", func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.TrackingRoot = big.NewInt(1)
			s.Rebind(t)
		}},
		{"another row field", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Tracking.Record.CtHash = big.NewInt(1)
		}},
		{"another path", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Tracking.Path.Index = 2
		}},
		{"another member's row", func(t *testing.T, s *ringmerge.Statement) {
			other := big.NewInt(0x77)
			s.Tracking.Apply(t, s.TrackingEntry(other, s.NullifierPk))
			s.Circuit.Tracking = s.Tracking.Opening(other).Wires()
			s.Circuit.TrackingRoot = s.Tracking.Root()
			s.Rebind(t)
		}},
		{"a row under another key", func(t *testing.T, s *ringmerge.Statement) {
			s.Tracking = ringregistry.NewTracking(t)
			s.Tracking.Apply(t, s.TrackingEntry(s.OwnerPkHash, big.NewInt(5)))
			s.Circuit.Tracking = s.Tracking.Opening(s.OwnerPkHash).Wires()
			s.Circuit.TrackingRoot = s.Tracking.Root()
			s.Rebind(t)
		}},
		{"an absent row", func(t *testing.T, s *ringmerge.Statement) {
			s.Tracking = ringregistry.NewTracking(t)
			s.Tracking.Apply(t, s.TrackingEntry(big.NewInt(0x77), s.NullifierPk))
			s.Circuit.Tracking = s.Tracking.Opening(s.OwnerPkHash).Wires()
			s.Circuit.TrackingRoot = s.Tracking.Root()
			s.Rebind(t)
		}},
		{"no row at all", func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.Tracking = ringmerge.UnreadTracking()
			s.Circuit.TrackingRoot = 0
			s.Rebind(t)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ringmerge.Build(t)
			tt.tamper(t, s)
			ringtest.RequireRefused(t, solved(t, s), "[assertIsEqual]", "circuits.(*MergeCircuit).Define")
		})
	}
}

// A zero key reads no row and publishes its owner, any other key reads its row and hides its owner.
func TestMergeModes(t *testing.T) {
	t.Run("nonzero key with its row settles with no owner published", func(t *testing.T) {
		s := ringmerge.Build(t)
		if err := solved(t, s); err != nil {
			t.Fatal(err)
		}
		if s.PublishedOwner.Sign() != 0 {
			t.Fatal("a hidden owner was published")
		}
	})
	t.Run("zero key with no row settles under its published owner", func(t *testing.T) {
		s := ringmerge.BuildZeroKey(t)
		if err := solved(t, s); err != nil {
			t.Fatal(err)
		}
		if s.NullifierPk.Cmp(shared.ZeroNullifierPk) != 0 || s.PublishedOwner.Cmp(s.OwnerPkHash) != 0 {
			t.Fatal("the zero key fixture left its mode")
		}
	})
	t.Run("zero key hiding its owner refuses", func(t *testing.T) {
		s := ringmerge.BuildZeroKey(t)
		s.PublishedOwner = big.NewInt(0)
		s.Rebind(t)
		if solved(t, s) == nil {
			t.Fatal("a zero key merge hid its owner, no signer binds it")
		}
	})
	t.Run("nonzero key publishing an owner refuses", func(t *testing.T) {
		s := ringmerge.Build(t)
		s.PublishedOwner = s.OwnerPkHash
		s.Rebind(t)
		if solved(t, s) == nil {
			t.Fatal("a hidden owner claimed the published rail")
		}
	})
}

// An enrolled wallet's old zero key note stays mergeable, no row can bar it.
func TestMergeZeroKeyIgnoresEveryRow(t *testing.T) {
	s := ringmerge.BuildZeroKey(t)
	s.Circuit.TrackingRoot = big.NewInt(0x99)
	s.Rebind(t)
	if err := solved(t, s); err != nil {
		t.Fatal(err)
	}
}

func TestMergePayer(t *testing.T) {
	// Paying names the hidden owner, a privacy choice the wallet makes and no proof refuses.
	t.Run("a hidden owner pays", func(t *testing.T) {
		s := ringmerge.Build(t)
		s.Circuit.Payer = s.OwnerPkHash
		s.Rebind(t)
		if err := solved(t, s); err != nil {
			t.Fatal(err)
		}
	})
	// The authorization stays, a paying hidden owner still opens its own row under its own key.
	t.Run("a paying hidden owner under another key", func(t *testing.T) {
		s := ringmerge.Build(t)
		s.Circuit.Payer = s.OwnerPkHash
		s.Tracking = ringregistry.NewTracking(t)
		s.Tracking.Apply(t, s.TrackingEntry(s.OwnerPkHash, big.NewInt(5)))
		s.Circuit.Tracking = s.Tracking.Opening(s.OwnerPkHash).Wires()
		s.Circuit.TrackingRoot = s.Tracking.Root()
		s.Rebind(t)
		ringtest.RequireRefused(t, solved(t, s), "circuits.(*MergeCircuit).Define")
	})
	t.Run("a published owner pays", func(t *testing.T) {
		s := ringmerge.BuildZeroKey(t)
		s.Circuit.Payer = s.OwnerPkHash
		s.Rebind(t)
		if err := solved(t, s); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the payer is statement bound", func(t *testing.T) {
		s := ringmerge.Build(t)
		s.Circuit.Payer = big.NewInt(99)
		if solved(t, s) == nil {
			t.Fatal("unbound payer accepted")
		}
	})
}

// The record alone rebuilds the output, a zero key blinding never follows from secret zero.
func TestMergeRecordRebuildsTheOutput(t *testing.T) {
	for name, build := range map[string]func(testing.TB) *ringmerge.Statement{"nonzero": ringmerge.Build, "zero": ringmerge.BuildZeroKey} {
		t.Run(name, func(t *testing.T) {
			s := build(t)
			opened := ringmerge.Open(t, s)
			if len(opened.Plain) != circuits.MergeRecordLen {
				t.Fatalf("%d byte record", len(opened.Plain))
			}
			if opened.Hash(t).Cmp(s.OutputHash) != 0 {
				t.Fatal("the record does not rebuild the published output")
			}
			if name == "zero" && ringtest.MustPoseidonHash(t, big.NewInt(mergeshared.MergeOutputBlindingDomainV1), big.NewInt(0), ringmerge.FirstNullifier).Cmp(s.OutputBlinding) == 0 {
				t.Fatal("the zero key blinding follows from public data")
			}
		})
	}
}

func TestMergeCost(t *testing.T) {
	cs := ringkey.Compile(t, &circuits.MergeCircuit{})
	ringkey.RequirePinned(t, "custom_ring_merge", cs)
	for _, s := range []*ringmerge.Statement{ringmerge.Build(t), ringmerge.BuildZeroKey(t)} {
		if err := solveCS(t, cs, s.Circuit); err != nil {
			t.Fatal(err)
		}
	}
}

func solveCS(t *testing.T, cs constraint.ConstraintSystem, c *circuits.MergeCircuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.Solve(witness)
	return err
}
