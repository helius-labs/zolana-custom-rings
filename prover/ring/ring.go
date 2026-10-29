// Package ring registers the custom ring circuits with the SPP prover server.
package ring

import (
	_ "embed"
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

//go:embed proving-keys.lock
var lockfile []byte

func init() {
	for _, key := range Keys {
		common.RegisterExtension(key.extension())
	}
	provingkeys.Register(lockfile)
}

func (k Key) extension() common.ExtensionCircuit {
	switch k.Family {
	case DeliveredAudit:
		return bind[DeliveredAuditParams](k, audit.NewDeliveredAuditCircuit, k.Outputs)
	case AnonymousAudit, AnonymousEntryAudit:
		return bind[AnonymousAuditParams](k, audit.NewAnonymousAuditCircuit, k.anonymousShape())
	case MemberPolicy:
		return bindPolicy[MemberPolicyParams](k, policy.NewMemberPolicyCircuit, policy.MemberShape{Outputs: k.Outputs, Withdrawals: k.Withdrawals, OwnOnly: k.OwnOnly})
	case DelegatePolicy:
		return bindPolicy[DelegatePolicyParams](k, policy.NewDelegatePolicyCircuit, policy.DelegateShape{Shape: transaction.NewShape(k.Inputs, k.Outputs), OwnOnly: k.OwnOnly})
	case ApplyRecords:
		return bind[ApplyRecordsParams](k, registry.NewApplyRecordsCircuit, k.Inputs)
	case WithdrawalExemption:
		return bind[WithdrawalExemptionParams](k, unsized[policy.WithdrawalExemptionCircuit], struct{}{})
	case RegisterKey:
		return bind[RegisterKeyParams](k, unsized[registry.RegisterKeyCircuit], struct{}{})
	case Deposit:
		return bind[DepositParams](k, circuits.NewDepositCircuit, k.Inputs)
	case Merge:
		return bind[MergeParams](k, circuits.NewMergeCircuit, k.Inputs)
	}
	panic(fmt.Sprintf("ring: no circuit for ring family %d", k.Family))
}

func bind[P headed, S any, C frontend.Circuit](k Key, constructor func(S) (C, error), shape S) common.ExtensionCircuit {
	build := func() (frontend.Circuit, error) { return constructor(shape) }
	return common.ExtensionCircuit{
		Type:    k.Circuit,
		KeyFile: k.KeyFile(),
		Circuit: func() frontend.Circuit {
			circuit, err := build()
			if err != nil {
				// Every catalog shape comes from its constructor's own list.
				panic(err)
			}
			return circuit
		},
		Request: func() common.ExtensionRequest { return &request[P]{circuit: k.Circuit, build: build} },
	}
}

type pooledCircuit interface {
	frontend.Circuit
	RecordPools() policy.RecordPoolShape
}

type pooledParams interface {
	headed
	pooled() PolicyParams
}

// bindPolicy refuses a pool index outside the key's pools before assignment.
func bindPolicy[P pooledParams, S any, C pooledCircuit](k Key, constructor func(S) (C, error), shape S) common.ExtensionCircuit {
	extension := bind[P](k, constructor, shape)
	plain := extension.Request
	extension.Request = func() common.ExtensionRequest {
		return &policyRequest[P]{request: plain().(*request[P]), pools: extension.Circuit().(C).RecordPools()}
	}
	return extension
}

func unsized[C any](struct{}) (*C, error) {
	return new(C), nil
}

// request decodes strictly on the server's encoding/json path.
type request[P headed] struct {
	circuit common.CircuitType
	build   func() (frontend.Circuit, error)
	params  P
}

func (r *request[P]) UnmarshalJSON(data []byte) error {
	if err := Unmarshal(data, &r.params); err != nil {
		return err
	}
	if got := r.params.head().CircuitType; got != r.circuit {
		return fmt.Errorf("custom-ring: a %s request on the %s key", got, r.circuit)
	}
	return nil
}

type policyRequest[P pooledParams] struct {
	*request[P]
	pools policy.RecordPoolShape
}

func (r *policyRequest[P]) Assignment() (frontend.Circuit, error) {
	if err := r.params.pooled().validateIndices(r.pools); err != nil {
		return nil, err
	}
	return r.request.Assignment()
}

func (p PolicyParams) pooled() PolicyParams { return p }

func (p PolicyParams) validateIndices(pools policy.RecordPoolShape) error {
	if err := validatePoolIndices(p.OwnSubjects, p.OwnProof, pools.Own); err != nil {
		return err
	}
	if err := validatePoolIndices(p.CuratorSubjects, p.CuratorProof, pools.Curator); err != nil {
		return err
	}
	for _, entry := range slices.Concat([]PooledEntry{p.SenderEntry}, p.OwnerEntries, p.AssetEntries) {
		if err := entry.validateIndices(pools); err != nil {
			return err
		}
	}
	for _, index := range p.PublicAssetEntries {
		if err := poolIndex("public asset subject", index, pools.OwnSubjects); err != nil {
			return err
		}
	}
	return nil
}

func validatePoolIndices(subjects []PooledSubject, proof SharedRegistryProof, records int) error {
	for _, subject := range subjects {
		if err := poolIndex("record", subject.RecordIndex, records); err != nil {
			return err
		}
	}
	for _, path := range proof.Paths {
		if path.Index >= registry.Capacity {
			return fmt.Errorf("policy path index is outside the registry")
		}
	}
	return nil
}

func (e PooledEntry) validateIndices(pools policy.RecordPoolShape) error {
	if err := poolIndex("own subject", e.Own, pools.OwnSubjects); err != nil {
		return err
	}
	for _, index := range e.Curator {
		if err := poolIndex("curator subject", index, pools.CuratorSubjects); err != nil {
			return err
		}
	}
	return nil
}

func poolIndex(name string, index uint32, size int) error {
	if uint64(index) >= uint64(size) {
		return fmt.Errorf("policy %s index is outside the pool", name)
	}
	return nil
}

// Assignment fails for a request that leaves a circuit value unset or sizes a slice off the key's shape.
func (r *request[P]) Assignment() (frontend.Circuit, error) {
	assignment, err := r.build()
	if err != nil {
		return nil, err
	}
	return assignment, assign(assignment, &r.params)
}
