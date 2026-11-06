// Refusals of the salted read, an enrolled owner skipping it, and a salted key off its Rust twin.

package policy_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

const (
	block        = ringregistry.BlockBit
	privateBlock = ringregistry.PrivateBlockBit
	allow        = ringregistry.AllowBit
	privateAllow = ringregistry.PrivateAllowBit
)

// saltedWorld pays Alice under the given rules, every list on the own registry.
func saltedWorld(rules ...ringpolicy.Rule) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table = ringpolicy.Table{Lists: []uint64{allow, block, privateBlock, privateAllow}, Salted: privateBlock | privateAllow, Rules: rules}
	w.Own = map[int64]ringpolicy.Record{}
	w.Salted = map[int64]uint64{}
	return w
}

func solveSalted(b ringpolicy.Witness) error {
	return test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
}

// Two independent deny rules hold each owner to both lists, enrollment moves only the salted one.
func TestPublicAndPrivateBlocksAreTwoRules(t *testing.T) {
	rules := []ringpolicy.Rule{ringpolicy.Forbid(policy.SubjectOutputOwner, block), ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock)}
	for _, tt := range []struct {
		name                                          string
		public, private                               bool
		refusedBeforeEnrolling, refusedAfterEnrolling bool
	}{
		{"unlisted", false, false, false, false},
		{"public only", true, false, true, true},
		{"private only", false, true, false, true},
		{"both", true, true, true, true},
	} {
		for _, enrolled := range []bool{false, true} {
			name := tt.name + " before enrolling"
			want := tt.refusedBeforeEnrolling
			if enrolled {
				name, want = tt.name+" after enrolling", tt.refusedAfterEnrolling
			}
			t.Run(name, func(t *testing.T) {
				w := saltedWorld(rules...)
				if tt.public {
					w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: block}
				}
				if tt.private {
					w.Salted[ringpolicy.Alice] = privateBlock
				}
				if enrolled {
					w.Enrolled = []int64{ringpolicy.Alice}
				}
				err := solveSalted(w.Build(t))
				if want {
					ringtest.RequireRefused(t, err, "policy.assertPaymentRules")
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// One rule over both grant lists, a program owner with no row enters through the public list.
func TestGrantReadsEitherList(t *testing.T) {
	rule := ringpolicy.Rule{Subject: policy.SubjectOutputOwner, Mode: policy.ModePresent, Mask: allow | privateAllow}
	for _, tt := range []struct {
		name            string
		public, private bool
		enrolled        bool
		refused         bool
	}{
		{"public grant with no row", true, false, false, false},
		{"salted grant of an enrolled owner", false, true, true, false},
		{"salted grant with no row is unreadable", false, true, false, true},
		{"enrolled owner with no grant", false, false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := saltedWorld(rule)
			w.Own[ringpolicy.Sender] = ringpolicy.Record{Lists: allow}
			if tt.public {
				w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: allow}
			}
			if tt.private {
				w.Salted[ringpolicy.Alice] = privateAllow
			}
			if tt.enrolled {
				w.Enrolled = []int64{ringpolicy.Alice}
			}
			err := solveSalted(w.Build(t))
			if tt.refused {
				ringtest.RequireRefused(t, err, "policy.assertPaymentRules")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSaltedSenderAndWithdrawalOwnersAreRead(t *testing.T) {
	t.Run("a blocked sender", func(t *testing.T) {
		w := saltedWorld(ringpolicy.Forbid(policy.SubjectSender, privateBlock))
		w.Salted[ringpolicy.Sender], w.Enrolled = privateBlock, []int64{ringpolicy.Sender}
		ringtest.RequireRefused(t, solveSalted(w.Build(t)), "policy.assertSenderRules")
	})
	t.Run("a blocked withdrawal owner", func(t *testing.T) {
		w := saltedWorld(ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
		w.WithdrawalCapacity = 4
		w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 7}}
		w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -7}}
		requireSolved(t, w.Build(t))
		w.Salted[ringpolicy.Bob], w.Enrolled = privateBlock, []int64{ringpolicy.Bob}
		ringtest.RequireRefused(t, solveSalted(w.Build(t)), "policy.assertPaymentRules")
	})
}

// A private block refuses Alice both ways, a private freeze refuses Bob as a sender and admits him as a payee.
func TestPrivateBlockAndPrivateFreezeInOneRing(t *testing.T) {
	privateFrozen := uint64(ringregistry.PrivateFrozenBit)
	world := func(sender int64, payee int64) ringpolicy.World {
		w := saltedWorld(
			ringpolicy.Forbid(policy.SubjectSender, privateBlock),
			ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock),
			ringpolicy.Forbid(policy.SubjectSender, privateFrozen),
		)
		w.Table.Lists = append(w.Table.Lists, privateFrozen)
		w.Table.Salted |= privateFrozen
		w.Enrolled = []int64{ringpolicy.Sender, ringpolicy.Alice, ringpolicy.Bob}
		w.Salted[ringpolicy.Alice], w.Salted[ringpolicy.Bob] = privateBlock, privateFrozen
		w.Sender = sender
		w.Slots = []ringpolicy.Slot{{Owner: payee, Asset: ringpolicy.AssetA, Amount: 500}}
		return w
	}
	t.Run("bob receives", func(t *testing.T) {
		requireSolved(t, world(ringpolicy.Sender, ringpolicy.Bob).Build(t))
	})
	t.Run("bob sends", func(t *testing.T) {
		ringtest.RequireRefused(t, solveSalted(world(ringpolicy.Bob, ringpolicy.Sender).Build(t)), "policy.assertSenderRules")
	})
	t.Run("alice receives", func(t *testing.T) {
		ringtest.RequireRefused(t, solveSalted(world(ringpolicy.Sender, ringpolicy.Alice).Build(t)), "policy.assertPaymentRules")
	})
	t.Run("alice sends", func(t *testing.T) {
		ringtest.RequireRefused(t, solveSalted(world(ringpolicy.Alice, ringpolicy.Sender).Build(t)), "policy.assertSenderRules")
	})
}

// A present tracking row forces the salt, the key and the salted read, each honest world below listed.
func TestPresentRowCannotSkipTheSaltedRead(t *testing.T) {
	listed := func(t *testing.T) ringpolicy.Witness {
		t.Helper()
		w := saltedWorld(ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
		w.Enrolled = []int64{ringpolicy.Alice, ringpolicy.Bob}
		w.Salted[ringpolicy.Alice] = privateBlock
		return w.Build(t)
	}
	alice := big.NewInt(ringpolicy.Alice)
	t.Run("the honest read refuses", func(t *testing.T) {
		ringtest.RequireRefused(t, solveSalted(listed(t)), "policy.assertPaymentRules")
	})
	t.Run("another salt fails the tag", func(t *testing.T) {
		b := listed(t)
		entry := &b.Circuit.OwnerEntries[0]
		entry.ListSalt = big.NewInt(0x1234)
		ringtest.RequireRefused(t, solveSalted(b), "policy.(*Policy).resolveSubjects")
	})
	t.Run("a salt from another ring fails the tag", func(t *testing.T) {
		b := listed(t)
		b.Circuit.OwnerEntries[0].ListSalt = ringpolicy.ListSaltIn(t, alice, big.NewInt(0x5c0f))
		ringtest.RequireRefused(t, solveSalted(b), "policy.(*Policy).resolveSubjects")
	})
	t.Run("a zero salt fails the tag", func(t *testing.T) {
		b := listed(t)
		b.Circuit.OwnerEntries[0].ListSalt = 0
		ringtest.RequireRefused(t, solveSalted(b), "policy.(*Policy).resolveSubjects")
	})
	t.Run("another owner's tracking subject fails the member", func(t *testing.T) {
		b := listed(t)
		b.Circuit.OwnerEntries[0].Tracking = trackingSubject(t, b, big.NewInt(ringpolicy.Sender))
		ringtest.RequireRefused(t, solveSalted(b), "policy.subjectPool.read")
	})
	t.Run("a low tracking record cannot call the owner absent", func(t *testing.T) {
		b := listed(t)
		index := ringtest.AsBigInt(b.Circuit.OwnerEntries[0].Tracking).Int64()
		for i, subject := range b.Circuit.TrackingSubjects {
			if ringtest.AsBigInt(subject.Member).Cmp(alice) != 0 {
				b.Circuit.TrackingSubjects[index].RecordIndex = i
				break
			}
		}
		ringtest.RequireRefused(t, solveSalted(b), "policy.recordPool.read")
	})
	t.Run("another owner's salted subject fails the key", func(t *testing.T) {
		b := listed(t)
		b.Circuit.OwnerEntries[0].OwnSalted = b.Circuit.OwnerEntries[0].Own
		ringtest.RequireRefused(t, solveSalted(b), "policy.subjectPool.read")
	})
	t.Run("a low salted record cannot call the key absent", func(t *testing.T) {
		b := listed(t)
		subject := &b.Circuit.OwnSubjects[ringtest.AsBigInt(b.Circuit.OwnerEntries[0].OwnSalted).Int64()]
		for i, record := range b.Circuit.OwnRecords {
			if ringtest.AsBigInt(record.Member).Cmp(ringtest.AsBigInt(subject.Member)) != 0 {
				subject.RecordIndex = i
				break
			}
		}
		ringtest.RequireRefused(t, solveSalted(b), "policy.recordPool.read")
	})
}

// A distinct owner reads an own public, a curator public and a salted record.
func TestDistinctOwnersReadAllThreeRecords(t *testing.T) {
	for _, curatedSalted := range []bool{false, true} {
		w := saltedWorld(ringpolicy.Forbid(policy.SubjectOutputOwner, block), ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.FrozenBit), ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
		w.Outputs, w.WithdrawalCapacity, w.SaltedKeys = 16, 8, 28
		w.Table.Lists = append(w.Table.Lists, ringregistry.FrozenBit)
		w.Table.Curator = map[uint64]bool{ringregistry.FrozenBit: true, privateBlock: curatedSalted}
		w.Curator = map[int64]ringpolicy.Record{}
		w.Slots = nil
		w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -16}}
		for i := range int64(24) {
			owner := 3000 + i
			w.Enrolled = append(w.Enrolled, owner)
			w.Own[owner], w.Curator[owner] = ringpolicy.Record{Lists: allow}, ringpolicy.Record{Lists: allow}
			if i < 16 {
				w.Slots = append(w.Slots, ringpolicy.Slot{Owner: owner, Asset: ringpolicy.AssetA, Amount: 1})
			} else {
				w.Withdrawals = append(w.Withdrawals, ringpolicy.Slot{Owner: owner, Asset: ringpolicy.AssetA, Amount: 2})
			}
		}
		w.Enrolled = append(w.Enrolled, ringpolicy.Sender)
		requireSolved(t, w.Build(t))
	}
}

func TestSaltedKeyMatchesRust(t *testing.T) {
	want, _ := new(big.Int).SetString("0cd39067a2c6eff923c63afab8a8d09543bdcc320bcb82dfd063b7da2826d248", 16)
	if ringregistry.ListKey(t, big.NewInt(7), big.NewInt(9)).Cmp(want) != 0 {
		t.Fatal("the salted key drifted from Member::salted")
	}
}

func trackingSubject(t *testing.T, b ringpolicy.Witness, member *big.Int) int {
	t.Helper()
	for i, subject := range b.Circuit.TrackingSubjects {
		if ringtest.AsBigInt(subject.Member).Cmp(member) == 0 {
			return i
		}
	}
	t.Fatalf("no tracking subject for %v", member)
	return 0
}

// Two pools read one tree, a subject's public and salted records then take no capacity from each other.
func TestSaltedListThroughTheCuratorPool(t *testing.T) {
	w := saltedWorld(ringpolicy.Forbid(policy.SubjectOutputOwner, block), ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
	w.Table.Curator = map[uint64]bool{privateBlock: true}
	w.Enrolled = []int64{ringpolicy.Alice}
	w.Curator = map[int64]ringpolicy.Record{}
	requireSolved(t, w.Build(t))
	w.CuratorSalted = map[int64]uint64{ringpolicy.Alice: privateBlock}
	ringtest.RequireRefused(t, solveSalted(w.Build(t)), "policy.assertPaymentRules")
	w.Salted[ringpolicy.Alice], w.CuratorSalted = privateBlock, nil
	requireSolved(t, w.Build(t))
}

// A repeated subject opens one public record and one salted record, each authenticated once.
func TestRepeatedSubjectReusesItsRecords(t *testing.T) {
	w := saltedWorld(ringpolicy.Forbid(policy.SubjectSender, block), ringpolicy.Forbid(policy.SubjectSender, privateBlock), ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
	w.Enrolled = []int64{ringpolicy.Sender}
	b := w.Build(t)
	change := b.Circuit.OwnerEntries[1]
	sender := b.Circuit.SenderEntries[0]
	if ringtest.AsBigInt(change.Own).Cmp(ringtest.AsBigInt(sender.Own)) != 0 || ringtest.AsBigInt(change.OwnSalted).Cmp(ringtest.AsBigInt(sender.OwnSalted)) != 0 {
		t.Fatal("a repeated subject took a second row")
	}
	if ringtest.AsBigInt(sender.Own).Cmp(ringtest.AsBigInt(sender.OwnSalted)) == 0 {
		t.Fatal("the public and salted reads share a row")
	}
	requireSolved(t, b)
}
