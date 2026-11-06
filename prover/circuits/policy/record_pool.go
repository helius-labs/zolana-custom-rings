// Reads a registry's records by member, for every subject a transfer screens, from one shared proof.
//
// SPP has no registries. A rule's answer comes from a record under a root the program read, and a subject
// not on any list must prove that too. A transfer reads a record for each sender, payment owner, asset and
// salted key, and many of those repeat, so the file dedups in two tiers.
//
// A record row is a leaf of the tree, opened once under the root by a SharedQuadProof. A subject row is a
// member with the columns it resolves to, proven once against a record row. A query then finds its
// member's subject row by a prover chosen index. A repeated subject takes one subject row, and absent
// subjects that fall in one link share its record row.
//
// Absence is a sorted list argument. registry/apply_records.go keeps the records linked in ascending
// member order, and a sentinel at index 0 brackets every member in [1, q-2]. A member strictly between a
// leaf's Member and Next has no leaf of its own, and a present member lies inside no link.
//
// Deduplication is sound because an index selects a row and never its content. The lookup binds whole
// rows, a member cannot pair with another record's columns. Duplicate rows are harmless, one member
// resolves to one answer under one root. Capacity bounds what a key can prove and never what it checks.
// A padded pool cycles real rows, see RecordPoolOf::padded in program-libs/member-registry/src/record_pool.rs.
//
// Read after registry/registry.go, registry/shared_path.go, registry/apply_records.go. Read before
// policy/tracking.go, policy/subjects.go.
//
// Properties:
// 1. Every record row of an active pool is a leaf under the pool's root.
// 2. Every subject row of an active pool holds its member's columns, or zeros beside a link proving the member absent.
// 3. An active query reads the row of its own member and needs an active pool, an inactive query reads zeros.
// 4. Lists split one way below 2^64, the low NSources bits are the bits a rule reads.
// 5. A mint policy splits one way into three limbs below 2^64.

package policy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type PoolSubject struct {
	Member      frontend.Variable
	RecordIndex frontend.Variable
}

type RecordPoolShape struct {
	Own, Curator                 int
	OwnSubjects, CuratorSubjects int
}

// Curator keeps the one element the request's list carries.
type PoolEntry struct {
	Own     frontend.Variable
	Curator [1]frontend.Variable
}

type OwnerEntry struct {
	PoolEntry
	Tracking      frontend.Variable
	ListSalt      frontend.Variable
	OwnSalted     frontend.Variable
	CuratorSalted [1]frontend.Variable
}

type recordQuery struct {
	active, member, index frontend.Variable
}

type pooledRecord struct {
	onList [NSources]frontend.Variable
	// mintPolicy stays packed, only an asset's reader decodes it.
	mintPolicy, withdrawalThreshold frontend.Variable
}

// Lists lead, the leaf hash still covers the whole record.
type recordColumns struct {
	width   int
	project func(record registry.Record) []frontend.Variable
}

var (
	ownColumns = recordColumns{width: 3, project: func(record registry.Record) []frontend.Variable {
		return []frontend.Variable{record.Lists, record.MintPolicy, record.WithdrawalThreshold}
	}}
	// A curator lookup reads list bits alone, every other field binds through the leaf hash only.
	curatorColumns = recordColumns{width: 1, project: func(record registry.Record) []frontend.Variable {
		return []frontend.Variable{record.Lists}
	}}
)

type pooledTable struct {
	active frontend.Variable
	table  *lookup.Table
}

type recordPool struct {
	pooledTable
	width int
}

type subjectPool struct{ pooledTable }

func openRecordPool(api frontend.API, active, root frontend.Variable, records []registry.Record, proof registry.SharedQuadProof, columns recordColumns) recordPool {
	api.AssertIsBoolean(active)
	pool := newRecordPool(api, active, columns.width)
	leaves := make([]frontend.Variable, len(records))
	for i, record := range records {
		leaves[i] = record.Hash(api)
		pool.table.Insert(append([]frontend.Variable{record.Member, record.Next}, columns.project(record)...))
	}
	proof.AssertLeavesWhen(api, active, root, leaves)
	return pool
}

func newRecordPool(api frontend.API, active frontend.Variable, width int) recordPool {
	return recordPool{pooledTable{active: active, table: lookup.New(api, 2+width)}, width}
}

// openSubjectPool resolves every subject row once against the records, a query then needs no ordering check of its own.
func openSubjectPool(api frontend.API, records recordPool, subjects []PoolSubject) subjectPool {
	pool := subjectPool{pooledTable{active: records.active, table: lookup.New(api, 1+records.width)}}
	for _, subject := range subjects {
		resolved := records.read(api, recordQuery{active: records.active, member: subject.Member, index: subject.RecordIndex})
		pool.table.Insert(append([]frontend.Variable{subject.Member}, resolved...))
	}
	return pool
}

// Zeros for an inactive query or an absent member.
func (p recordPool) read(api frontend.API, query recordQuery) []frontend.Variable {
	row := p.lookup(api, query)
	present := IsSame(api, row[0], query.member)
	// The row's Member is the query's, or the query lies strictly inside the row's link. AssertOrderedWhen compares canonical field integers.
	ringgadget.AssertOrderedWhen(api, api.Mul(query.active, api.Sub(1, present)), row[0], query.member, row[1])
	// An absent member reads zeros whatever its predecessor holds.
	return gated(api, api.Mul(query.active, present), row[2:])
}

func (p subjectPool) resolve(api frontend.API, query recordQuery) []frontend.Variable {
	return withLists(api, p.read(api, query))
}

func (p subjectPool) read(api frontend.API, query recordQuery) []frontend.Variable {
	row := p.lookup(api, query)
	// A row of another member would answer for the query's.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: query.active, A: row[0], B: query.member})
	return gated(api, query.active, row[1:])
}

func (p pooledTable) lookup(api frontend.API, query recordQuery) []frontend.Variable {
	api.AssertIsBoolean(query.active)
	// The rows of an inactive pool fold under no root, an active query there would read prover chosen lists.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: query.active, V: api.Sub(1, p.active)})
	return p.table.Lookup(query.index)
}

func gated(api frontend.API, active frontend.Variable, columns []frontend.Variable) []frontend.Variable {
	zeroed := make([]frontend.Variable, len(columns))
	for i, column := range columns {
		zeroed[i] = api.Mul(active, column)
	}
	return zeroed
}

func withLists(api frontend.API, columns []frontend.Variable) []frontend.Variable {
	onList := sourceLists(api, columns[0])
	return append(onList[:], columns[1:]...)
}

func pooledRecordAt(columns []frontend.Variable) pooledRecord {
	return pooledRecord{onList: [NSources]frontend.Variable(columns[:NSources]), mintPolicy: columns[NSources], withdrawalThreshold: columns[NSources+1]}
}

// The range check bounds lists below 2^ListBits so one split exists.
// A rule reads the low NSources bits alone, a list past them has no source slot. No stored record fails the split, ValueOutsideMask keeps lists within u64 at the write.
func sourceLists(api frontend.API, lists frontend.Variable) [NSources]frontend.Variable {
	low, err := api.Compiler().NewHint(rangecheck.DecomposeHint, 1, NSources, NSources, lists)
	if err != nil {
		panic(err)
	}
	rangecheck.New(api).Check(api.DivUnchecked(api.Sub(lists, low[0]), 1<<NSources), registry.ListBits-NSources)
	return [NSources]frontend.Variable(api.ToBinary(low[0], NSources))
}

// decodeMintPolicy reads cosign_above, cap and threshold from low to high, the bounded limbs recompose over the integers and no limb aliases another. registry/apply_records.go keeps a stored policy below 2^192.
func decodeMintPolicy(api frontend.API, packed frontend.Variable) mintPolicyWires {
	limbs, err := api.Compiler().NewHint(rangecheck.DecomposeHint, 3, 192, 64, packed)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, 64)
	}
	base := new(big.Int).Lsh(big.NewInt(1), 64)
	api.AssertIsEqual(packed, api.Add(limbs[0], api.Mul(base, limbs[1]), api.Mul(new(big.Int).Mul(base, base), limbs[2])))
	return mintPolicyWires{threshold: limbs[2], cap: limbs[1], cosignAbove: limbs[0]}
}

func (p *PolicyInputs) recordCapacity(publicAssets int) RecordPoolShape {
	outputs, withdrawals := p.Outputs, len(p.Withdrawals)
	// Withdrawals settle through SPP public slots, so their assets are among at most NPublicSlots.
	withdrawalAssets := min(withdrawals, transaction.NPublicSlots)
	distinct := p.Senders + outputs + withdrawals + outputs + p.SaltedKeys + p.Spent
	return RecordPoolShape{Own: distinct + max(withdrawalAssets, publicAssets), Curator: distinct + withdrawalAssets}
}

func (s RecordPoolShape) withDefaults(limits RecordPoolShape) RecordPoolShape {
	if s.Own == 0 {
		s.Own = limits.Own
	}
	if s.Curator == 0 {
		s.Curator = limits.Curator
	}
	if s.OwnSubjects == 0 {
		s.OwnSubjects = s.Own
	}
	if s.CuratorSubjects == 0 {
		s.CuratorSubjects = s.Curator
	}
	return s
}

func (s RecordPoolShape) validate(limits RecordPoolShape) error {
	if err := validatePoolCapacity(s.Own, s.OwnSubjects, limits.Own); err != nil {
		return err
	}
	return validatePoolCapacity(s.Curator, s.CuratorSubjects, limits.Curator)
}

func validatePoolCapacity(records, subjects, maximum int) error {
	for _, capacity := range []int{records, subjects} {
		if capacity < 1 || capacity > maximum {
			return fmt.Errorf("policy pool capacity is invalid")
		}
	}
	return nil
}
