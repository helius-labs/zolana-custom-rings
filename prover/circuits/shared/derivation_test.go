package shared_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Distinct tags keep a hash of one role from opening as another, SPP's blinding tags included.
func TestRingDomainsAreTheAsciiTags(t *testing.T) {
	seen := map[uint64]string{
		transaction.OutputBlindingDomainV1:      "TXOB",
		transaction.OutputBlindingSeedDomainV1:  "TXOS",
		transaction.PrivateTxBlindingDomainV1:   "TXPB",
		mergeshared.MergeOutputBlindingDomainV1: "TMOB",
	}
	for _, domain := range []struct {
		tag   string
		value uint64
	}{
		{"CRBS", shared.BlindingSeedDomain},
		{"CRTB", shared.PolicyTableDomain},
		{"CRQW", shared.RecordWriteDomain},
		{"CRAP", shared.ApplyRecordsDomain},
		{"CRRG", shared.RegisterKeyDomain},
		{"CRMG", shared.MergeStatementDomain},
		{"CRPW", shared.WithdrawalsDomain},
		{"CRTX", shared.TransferStatementDomain},
		{"CRTK", shared.TrackingLeafDomain},
		{"CRTQ", shared.TrackingEntryDomain},
		{"CRTA", shared.ApplyEnrollmentsDomain},
		{"CRPT", shared.ListTagDomain},
		{"CR_S", shared.DomSepCRShared},
	} {
		if want := new(big.Int).SetBytes([]byte(domain.tag)).Uint64(); domain.value != want {
			t.Errorf("%s = %#x, want %#x", domain.tag, domain.value, want)
		}
		if other, taken := seen[domain.value]; taken {
			t.Errorf("%s shares its value with %s", domain.tag, other)
		}
		seen[domain.value] = domain.tag
	}
}
