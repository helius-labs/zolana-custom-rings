// The owner lookup key, apart from the bare identity and the salted key, and its Rust twin.

package policy_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

func TestOwnerListsReadAtTheLookupKey(t *testing.T) {
	alice := big.NewInt(ringpolicy.Alice)
	ownSubject := func(b ringpolicy.Witness, entry policy.OwnerEntry) *policy.PoolSubject {
		return &b.Policy().OwnSubjects[ringtest.AsBigInt(entry.Own).Int64()]
	}
	t.Run("a grant at the zero salt key admits", func(t *testing.T) {
		b := ringpolicy.Confidential().Build(t)
		if ringtest.AsBigInt(ownSubject(b, b.Policy().OwnerEntries[0]).Member).Cmp(ringregistry.PublicKey(t, alice)) != 0 {
			t.Fatal("the owner's public read left its lookup key")
		}
		requireSolved(t, b)
	})
	t.Run("a grant at the bare identity reads absent", func(t *testing.T) {
		w := ringpolicy.Confidential()
		delete(w.Own, ringpolicy.Alice)
		w.Unkeyed = map[int64]ringpolicy.Record{ringpolicy.Alice: {Lists: allow}}
		ringtest.RequireRefused(t, solveSalted(w.Build(t)), "policy.assertPaymentRules")
	})
	t.Run("a subject at the bare identity fails its record", func(t *testing.T) {
		b := ringpolicy.Confidential().Build(t)
		ownSubject(b, b.Policy().OwnerEntries[0]).Member = alice
		ringtest.RequireRefused(t, solveSalted(b), "policy.recordPool.read")
	})
	t.Run("a public read at the salted key fails the member", func(t *testing.T) {
		w := saltedWorld(ringpolicy.Forbid(policy.SubjectOutputOwner, block), ringpolicy.Forbid(policy.SubjectOutputOwner, privateBlock))
		w.Enrolled = []int64{ringpolicy.Alice}
		b := w.Build(t)
		b.Circuit.OwnerEntries[0].Own = b.Circuit.OwnerEntries[0].OwnSalted
		ringtest.RequireRefused(t, solveSalted(b), "policy.subjectPool.read")
	})
}

func TestPublicKeyMatchesRust(t *testing.T) {
	want, _ := new(big.Int).SetString("18eb3f0cf43fb318e0ab77c3d2fc13af04d5ef7fa7afd1f47909f087ff748fe3", 16)
	if ringregistry.PublicKey(t, big.NewInt(7)).Cmp(want) != 0 {
		t.Fatal("the public key drifted from Member::public")
	}
}
