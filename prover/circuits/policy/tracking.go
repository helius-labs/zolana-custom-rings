// Opens a ring's enrollment tree for the owner predicates and the salted reads.
//
// SPP has no enrollment. A ring's tracking tree maps an owner to the nullifier key whose secret the auditor holds
// and to the list tag fixing the owner's salt. A row reads present or proven absent through the pool
// gadget the policy registries use, and both answers carry weight. The zero key rule in
// transfer/owners.go and the salted read in policy/subjects.go each treat an absent owner apart from an
// enrolled one.
//
// Read after policy/record_pool.go, registry/tracking.go. Read before transfer/owners.go, policy/subjects.go.
//
// Properties:
// 1. Every record row is a leaf under TrackingRoot on every rail, the gate of a policy pool does not apply.
// 2. A row query reads the member's key and list tag, or zeros with a leaf link proving the member absent.
// 3. A nonzero key alone tells presence, registry/register_key.go refuses to enroll the zero secret and the key is a hash of the secret.
//
// The circuit cannot see the root's age. The program serves a root within its grace and refuses one below
// a salted source's floor, in LiveRoots::tracking in program-libs/interface/src/accounts/state.rs.

package policy

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
)

// Tracking opens every owner row, output owner and withdrawal owner under the frame's tracking root.
type Tracking struct {
	TrackingRoot     frontend.Variable
	TrackingRecords  []registry.TrackingRecord
	TrackingProof    registry.SharedQuadProof
	TrackingSubjects []PoolSubject
	// RowEntries and OutputEntries index TrackingSubjects.
	RowEntries    []frontend.Variable
	OutputEntries []frontend.Variable
}

// TrackingView reads zeros for an absent member, an enrolled key hashes a nonzero secret so the key alone tells presence.
type TrackingView struct {
	NullifierPk, ListTag frontend.Variable
}

// TrackingPool answers row and output queries, a member absent from the root reads zeros.
// It shares only the pool's authentication with the policy registries, its leaf is TrackingRecord's, its root TrackingRoot and its absence zero columns.
type TrackingPool struct {
	subjects subjectPool
}

const trackingColumns = 2

// NewTracking also sizes for the key's withdrawal owners, a salted list reads each owner's row.
func NewTracking(rows, outputs, withdrawals int) (Tracking, error) {
	capacity := rows + outputs + withdrawals
	proof, err := registry.NewTrackingProof(capacity)
	if err != nil {
		return Tracking{}, err
	}
	return Tracking{
		TrackingRecords:  make([]registry.TrackingRecord, capacity),
		TrackingProof:    proof,
		TrackingSubjects: make([]PoolSubject, capacity),
		RowEntries:       make([]frontend.Variable, rows),
		OutputEntries:    make([]frontend.Variable, outputs),
	}, nil
}

// ValidateTracking refuses a pool sized off the key before any wire is read.
func (t *Tracking) ValidateTracking(rows, outputs, withdrawals int) error {
	capacity := rows + outputs + withdrawals
	if len(t.RowEntries) != rows || len(t.OutputEntries) != outputs {
		return fmt.Errorf("tracking requires one reference per row and output")
	}
	if len(t.TrackingRecords) != capacity || len(t.TrackingSubjects) != capacity {
		return errors.New("tracking pool capacity is invalid")
	}
	return t.TrackingProof.Validate(capacity)
}

// TrackingPoolSize is the records and subjects the key opens.
func (t *Tracking) TrackingPoolSize() int {
	return len(t.TrackingRecords)
}

func (t *Tracking) OpenTracking(api frontend.API) TrackingPool {
	// The pool's gate is the constant one, a frame cannot skip the tree its owner predicates read.
	records := newRecordPool(api, 1, trackingColumns)
	leaves := make([]frontend.Variable, len(t.TrackingRecords))
	for i, record := range t.TrackingRecords {
		leaves[i] = record.Hash(api)
		records.table.Insert([]frontend.Variable{record.Member, record.Next, record.NullifierPk, record.ListTag})
	}
	t.TrackingProof.AssertLeaves(api, t.TrackingRoot, leaves)
	return TrackingPool{subjects: openSubjectPool(api, records, t.TrackingSubjects)}
}

// Row reads member at entry while active is set, zeros otherwise.
func (p TrackingPool) Row(api frontend.API, active, member, entry frontend.Variable) TrackingView {
	columns := p.subjects.read(api, recordQuery{active: active, member: member, index: entry})
	return TrackingView{NullifierPk: columns[0], ListTag: columns[1]}
}
