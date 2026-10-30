package ring

import (
	"fmt"
	"slices"
	"strings"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Family is mirrored by RingCircuit in program-libs/interface/src/proof/key_catalog.rs.
type Family int

const (
	DeliveredAudit Family = iota
	AnonymousAudit
	AnonymousEntryAudit
	MemberPolicy
	DelegatePolicy
	ApplyRecords
	RegisterKey
	Deposit
	AnonymousMerge
	WithdrawalExemption
)

type Key struct {
	Circuit common.CircuitType
	Family  Family
	// Inputs counts the input slots, queued writes or merged UTXOs the key sizes.
	Inputs      int
	Outputs     int
	Withdrawals int
	OwnOnly     bool
}

// Keys takes each shape from the package that sizes it, one delegate key per SPP ring-authority key.
var Keys = keys()

func (k Key) KeyFile() string {
	return strings.ReplaceAll(string(k.Circuit), "-", "_") + ".key"
}

func keys() []Key {
	var keys []Key
	add := func(family Family, inputs, outputs int) {
		key := Key{Family: family, Inputs: inputs, Outputs: outputs}
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, outputs := range audit.DeliveredAuditCapacities {
		add(DeliveredAudit, 0, outputs)
	}
	for _, shape := range audit.AnonymousAuditShapes {
		add(AnonymousAudit, shape.InputClass, shape.Outputs)
	}
	for _, shape := range audit.AnonymousEntryShapes {
		add(AnonymousEntryAudit, shape.InputClass, shape.Outputs)
	}
	for _, outputs := range policy.MemberOutputs {
		for _, withdrawals := range policy.WithdrawalCapacities {
			for _, ownOnly := range []bool{false, true} {
				key := Key{Family: MemberPolicy, Outputs: outputs, Withdrawals: withdrawals, OwnOnly: ownOnly}
				key.Circuit = key.circuitType()
				keys = append(keys, key)
			}
		}
	}
	for _, shape := range ringAuthorityShapes() {
		for _, ownOnly := range []bool{false, true} {
			key := Key{Family: DelegatePolicy, Inputs: shape.NInputs, Outputs: shape.NOutputs, OwnOnly: ownOnly}
			key.Circuit = key.circuitType()
			keys = append(keys, key)
		}
	}
	for _, writes := range registry.ApplyWidths {
		add(ApplyRecords, writes, 0)
	}
	add(RegisterKey, 0, 0)
	add(WithdrawalExemption, 0, 0)
	for _, capacity := range circuits.DepositCapacities {
		add(Deposit, capacity, 0)
	}
	for _, width := range circuits.MergeWidths {
		add(AnonymousMerge, width, 0)
	}
	return keys
}

func (k Key) anonymousShape() audit.AnonymousAuditShape {
	return audit.AnonymousAuditShape{InputClass: k.Inputs, Outputs: k.Outputs, FullOpenings: k.Family == AnonymousEntryAudit}
}

func ringAuthorityShapes() []protocol.Shape {
	return slices.DeleteFunc(slices.Clone(protocol.SupportedShapes), func(s protocol.Shape) bool {
		return !common.ProofShape{
			Circuit: common.TransferRingAuthorityCircuitType,
			Inputs:  uint32(s.NInputs),
			Outputs: uint32(s.NOutputs),
		}.Supported()
	})
}

func (k Key) circuitType() common.CircuitType {
	named := func(format string, args ...any) common.CircuitType {
		return common.CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case DeliveredAudit:
		return named("audit-delivered-%d", k.Outputs)
	case AnonymousAudit:
		return named("audit-anonymous-v2-%d-%d", k.Inputs, k.Outputs)
	case AnonymousEntryAudit:
		return named("audit-anonymous-entry-v2-%d-%d", k.Inputs, k.Outputs)
	case MemberPolicy:
		return named("policy-member-v3-%d-w%d-%s", k.Outputs, k.Withdrawals, k.sourceName())
	case DelegatePolicy:
		return named("policy-delegate-v3-%dx%d-%s", k.Inputs, k.Outputs, k.sourceName())
	case ApplyRecords:
		return named("apply-records-%d", k.Inputs)
	case WithdrawalExemption:
		return named("withdrawal-exemption")
	case RegisterKey:
		return named("register-key")
	case Deposit:
		return named("deposit-%d", k.Inputs)
	case AnonymousMerge:
		return named("merge-anonymous-v2-%d", k.Inputs)
	}
	panic(fmt.Sprintf("ring: unknown ring family %d", k.Family))
}

func (k Key) sourceName() string {
	if k.OwnOnly {
		return "own"
	}
	return "curator"
}
