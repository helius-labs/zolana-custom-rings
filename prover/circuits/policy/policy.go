// Holds the public statement that the member and delegate policy proofs share
// with the program. Every value a rule reads ties back to the statement, so the
// proof checks the transfer the program settles.
//
// Read after policy/table.go, policy/record_pool.go. Read before
// policy/transaction.go, policy/member.go, policy/delegate.go.

// Package policy proves a custom ring's policy over a transaction SPP proves.
package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. The rules read the policy table the program validated and hashed into policy_hash.
// 2. The outputs are the ones SPP settles under the private_tx_hash its proof binds.
// 3. One sender, the owner signer of a confidential ring, the sender an anonymous ring's commitment hides, or the one member a delegate move spends.
// 4. Every output slot's public recipient is its owner identity, zero on a dummy and on an anonymous ring.
// 5. Every enabled rule holds for the sender and every live output or withdrawal owner and asset on the lists their records carry, unless an amount guard exempts it.
// 6. On the member key every limit row's outflow is never negative and within its cap, and approval_required is set exactly when one passes its co-sign bound.
// 7. Under key escrow every UTXO output's owner record escrows the output's nullifier key.

type PolicyInputs struct {
	OwnOnly         bool `gnark:"-"`
	WithdrawalCount frontend.Variable
	WithdrawalHash  frontend.Variable
	Withdrawals     []WithdrawalWires
	PrivateTxHash   frontend.Variable
	PolicyHash      frontend.Variable
	RingProgramID   frontend.Variable
	OwnRoot         frontend.Variable
	CuratorRoot     frontend.Variable
	PublicAssets    [transaction.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, a withdrawal enters as the field negation of its amount.
	PublicAmounts [transaction.NPublicSlots]frontend.Variable
	Table

	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable
	Outputs           []OutputWires
	Recipients        []frontend.Variable
	// Read on an anonymous ring and on the delegate key, free on a confidential ring.
	SenderPkHash frontend.Variable
}

type Policy struct {
	PolicyInputs
	OwnRecords         []registry.Record
	CuratorRecords     []registry.Record
	OwnProof           registry.SharedQuadProof
	CuratorProof       registry.SharedQuadProof
	OwnSubjects        []PoolSubject
	CuratorSubjects    []PoolSubject
	SenderEntry        PoolEntry
	OwnerEntries       []PoolEntry
	AssetEntries       []PoolEntry
	PublicAssetEntries []frontend.Variable
}

type railValues struct {
	// anonymous is the member key's mode bit, absent from the delegate statement.
	anonymous                           []frontend.Variable
	approvalRequired, keyEscrow, sender frontend.Variable
}

func newPolicyInputs(outputs, withdrawals int, ownOnly bool) PolicyInputs {
	return PolicyInputs{OwnOnly: ownOnly, Outputs: make([]OutputWires, outputs), Recipients: make([]frontend.Variable, outputs), Withdrawals: make([]WithdrawalWires, withdrawals)}
}

func newPolicy(inputs PolicyInputs, capacity RecordPoolShape, publicAssets int) (Policy, error) {
	payments := len(inputs.Outputs) + len(inputs.Withdrawals)
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
		SenderEntry:        newPoolEntry(inputs.OwnOnly),
		OwnerEntries:       make([]PoolEntry, payments),
		AssetEntries:       make([]PoolEntry, payments),
		PublicAssetEntries: make([]frontend.Variable, publicAssets),
	}
	for i := range p.OwnerEntries {
		p.OwnerEntries[i], p.AssetEntries[i] = newPoolEntry(inputs.OwnOnly), newPoolEntry(inputs.OwnOnly)
	}
	var err error
	if p.OwnProof, err = registry.NewSharedQuadProof(capacity.Own); err != nil {
		return Policy{}, err
	}
	if !inputs.OwnOnly {
		if p.CuratorProof, err = registry.NewSharedQuadProof(capacity.Curator); err != nil {
			return Policy{}, err
		}
	}
	return p, nil
}

func (p *Policy) RecordPools() RecordPoolShape {
	return RecordPoolShape{Own: len(p.OwnRecords), Curator: len(p.CuratorRecords), OwnSubjects: len(p.OwnSubjects), CuratorSubjects: len(p.CuratorSubjects)}
}

func (p *Policy) validate(publicAssets int) error {
	payments := len(p.Outputs) + len(p.Withdrawals)
	if len(p.Outputs) == 0 || len(p.OwnerEntries) != payments || len(p.AssetEntries) != payments {
		return fmt.Errorf("policy requires owner and asset references for every payment")
	}
	if len(p.Recipients) != len(p.Outputs) {
		return fmt.Errorf("policy requires one recipient per output")
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
	if !p.OwnOnly {
		if err := p.CuratorProof.Validate(len(p.CuratorRecords)); err != nil {
			return err
		}
	}
	for _, entry := range slices.Concat([]PoolEntry{p.SenderEntry}, p.OwnerEntries, p.AssetEntries) {
		if err := entry.validate(p.OwnOnly); err != nil {
			return err
		}
	}
	return nil
}

// statement is the policy preimage, mirrored by PolicyStatement::elements in program-libs/interface/src/proof/statement.rs.
//
//	CRPO, private_tx_hash, policy_hash, ring_id, anonymous on the member key only, approval_required,
//	key_escrow, own_root, curator_root, sender, recipient_o per output slot, asset_k and amount_k per public slot, version, withdrawal_hash
func (p *PolicyInputs) statement(rail railValues) []frontend.Variable {
	fields := []frontend.Variable{shared.PolicyStatementDomain, p.PrivateTxHash, p.PolicyHash, p.RingProgramID}
	fields = append(fields, rail.anonymous...)
	fields = append(fields, rail.approvalRequired, rail.keyEscrow, p.OwnRoot, p.CuratorRoot, rail.sender)
	fields = append(fields, p.Recipients...)
	for k := range p.PublicAssets {
		fields = append(fields, p.PublicAssets[k], p.PublicAmounts[k])
	}
	return append(fields, shared.PolicyStatementVersion, p.WithdrawalHash)
}

func bindStatement(api frontend.API, publicInputHash frontend.Variable, statement []frontend.Variable) {
	// The one public input fixes every statement value the steps read to the ones the program rebuilds.
	api.AssertIsEqual(publicInputHash, gadget.HashChain4(api, statement))
}
