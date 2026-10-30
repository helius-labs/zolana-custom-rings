package audit_test

import (
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

func TestAuditKeysCompileAtPinnedCounts(t *testing.T) {
	for _, capacity := range audit.DeliveredAuditCapacities {
		ringkey.RequirePinned(t, deliveredKeyName(capacity), compileDelivered(t, capacity).cs)
	}
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, {InputClass: 16, Outputs: 2}, entryShape} {
		ringkey.RequirePinned(t, anonymousKeyName(shape), compileAnonymous(t, shape).cs)
	}
}
