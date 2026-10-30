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
		{"CRAU", shared.AuditStatementDomain},
		{"CRDS", shared.DeliveredSlotSecretDomain},
		{"CRBS", shared.BlindingSeedDomain},
		{"CRSC", shared.SenderCommitmentDomain},
		{"CROD", shared.DisclosurePadDomain},
		{"CRPO", shared.PolicyStatementDomain},
		{"CRTB", shared.PolicyTableDomain},
		{"CRQW", shared.QueueWriteDomain},
		{"CRAP", shared.ApplyRecordsDomain},
		{"CRRG", shared.RegisterKeyDomain},
		{"CRDP", shared.DepositStatementDomain},
		{"CRMG", shared.MergeStatementDomain},
		{"CRDB", shared.DepositBlindingDomain},
		{"CRPW", shared.WithdrawalsDomain},
		{"CRWX", shared.WithdrawalExemptionDomain},
		{"CR_S", shared.DomSepCRShared},
		{"CR_MD", shared.MergeDisclosureDomain},
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
