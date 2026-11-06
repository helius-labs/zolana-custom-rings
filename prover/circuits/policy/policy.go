// Package policy proves a custom ring's policy over a transaction SPP proves.
//
// SPP authorizes a spend and conserves each asset, and it reads no list, threshold or cap. A ring's
// policy is a rule table over member lists and a mint record per asset. The rules read private owners,
// assets and amounts, so the program cannot run them and the proof does. Without the package a ring's
// allow lists, block lists, guards and caps would hold nothing on a private transfer.
//
// Read after transfer/transfer.go, shared/utxo.go, registry/registry.go, policy/record_pool.go,
// policy/tracking.go, transfer/owners.go. Read before, in call order, policy/screen.go,
// policy/withdrawals.go, policy/table.go, policy/subjects.go, policy/rules.go, policy/comparator.go,
// policy/outflow.go.
//
// Screen proves these properties over the slots SPP hashes and the roots the statement binds. Properties 2 to 5 hold while Screened.
//  1. While Screened, the rules are the table the program hashed at policy_hash.
//  2. Every live sender, payment owner, payment asset and input asset reads its list bits from a record
//     the policy root of its source holds, present or proven absent by its predecessor.
//  3. An enrolled owner reads a private list at the one salted key its tracking row fixes, only an owner
//     proven absent under the tracking root skips the read.
//  4. Every sender rule holds over every live row, every owner rule over every live payment's nonzero
//     owner and every asset rule over every live payment unless its guard exempts the total, and every
//     unconditional asset rule over every live input's asset.
//  5. Payment totals read output and withdrawal amounts, an input's amount only nets a same ring
//     receipt of its own owner and asset.
//  6. While Outflow is set the caps hold and Screening carries the approval bits the flows reach.
//  7. The authority rail clears Screened and Outflow, no rule binds on it. The merge circuit reads no policy.
//
// The properties rely on what the package cannot see. The program validates the table at write time,
// reads each root live, refuses a tracking root below a salted source's floor, folds the gross and reads
// the legs. Package transfer ties the slots to SPP and gives every live input owner a row.
package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type PolicyInputs struct {
	// Senders counts the owners the key screens, Outputs the slots, the pool holds a row for each.
	Senders, Outputs int `gnark:"-"`
	Spent            int `gnark:"-"`
	// SaltedKeys widens each pool past its public subjects.
	SaltedKeys      int `gnark:"-"`
	WithdrawalCount frontend.Variable
	WithdrawalHash  frontend.Variable
	Withdrawals     []WithdrawalWires
	PolicyHash      frontend.Variable
	RingProgramID   frontend.Variable
	OwnRoot         frontend.Variable
	CuratorRoot     frontend.Variable
	PublicAssets    [transaction.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, the statement alone reads them.
	PublicAmounts [transaction.NPublicSlots]frontend.Variable
	// PublicGross are the gross withdrawals per slot, no deposit subtracted, read while Outflow is on.
	PublicGross [transaction.NPublicSlots]frontend.Variable
	Table
}

// Policy adds the private wires of the record pools, the entries are prover chosen indexes and a query checks what each one reads.
type Policy struct {
	PolicyInputs
	OwnRecords      []registry.Record
	CuratorRecords  []registry.Record
	OwnProof        registry.SharedQuadProof
	CuratorProof    registry.SharedQuadProof
	OwnSubjects     []PoolSubject
	CuratorSubjects []PoolSubject
	SenderEntries   []OwnerEntry
	OwnerEntries    []OwnerEntry
	// AssetEntries index each payment's asset subject, then each input slot's.
	AssetEntries       []PoolEntry
	PublicAssetEntries []frontend.Variable
}

type InputsShape struct {
	Outputs, Withdrawals, Senders, SaltedKeys, Spent int
}

func (s InputsShape) Inputs() PolicyInputs {
	return PolicyInputs{Senders: s.Senders, Outputs: s.Outputs, Spent: s.Spent, SaltedKeys: s.SaltedKeys, Withdrawals: make([]WithdrawalWires, s.Withdrawals)}
}

// NewPolicy sizes the record pools, capacity zero fields take the shape's limits.
func NewPolicy(inputs PolicyInputs, capacity RecordPoolShape, publicAssets int) (Policy, error) {
	payments := inputs.Outputs + len(inputs.Withdrawals)
	limits := inputs.recordCapacity(publicAssets)
	capacity = capacity.withDefaults(limits)
	if err := capacity.validate(limits); err != nil {
		return Policy{}, err
	}
	p := Policy{
		PolicyInputs:       inputs,
		OwnRecords:         make([]registry.Record, capacity.Own),
		CuratorRecords:     make([]registry.Record, capacity.Curator),
		OwnSubjects:        make([]PoolSubject, capacity.OwnSubjects),
		CuratorSubjects:    make([]PoolSubject, capacity.CuratorSubjects),
		SenderEntries:      make([]OwnerEntry, inputs.Senders),
		OwnerEntries:       make([]OwnerEntry, payments),
		AssetEntries:       make([]PoolEntry, payments+inputs.Spent),
		PublicAssetEntries: make([]frontend.Variable, publicAssets),
	}
	var err error
	if p.OwnProof, err = registry.NewSharedQuadProof(capacity.Own); err != nil {
		return Policy{}, err
	}
	if p.CuratorProof, err = registry.NewSharedQuadProof(capacity.Curator); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p *Policy) RecordPools() RecordPoolShape {
	return RecordPoolShape{Own: len(p.OwnRecords), Curator: len(p.CuratorRecords), OwnSubjects: len(p.OwnSubjects), CuratorSubjects: len(p.CuratorSubjects)}
}

// Validate refuses a pool or reference list sized off the key's shape before any wire is read.
func (p *Policy) Validate(publicAssets int) error {
	payments := p.Outputs + len(p.Withdrawals)
	if p.Outputs == 0 || len(p.OwnerEntries) != payments || len(p.AssetEntries) != payments+p.Spent {
		return fmt.Errorf("policy requires owner and asset references for every payment and an asset reference for every input")
	}
	if len(p.SenderEntries) != p.Senders {
		return fmt.Errorf("policy requires one reference per screened sender")
	}
	if len(p.PublicAssetEntries) != publicAssets {
		return fmt.Errorf("policy requires one public asset reference per public slot")
	}
	if err := p.RecordPools().validate(p.recordCapacity(publicAssets)); err != nil {
		return err
	}
	if err := p.OwnProof.Validate(len(p.OwnRecords)); err != nil {
		return err
	}
	return p.CuratorProof.Validate(len(p.CuratorRecords))
}
