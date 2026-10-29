package policy

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
)

type PoolSubject struct {
	Member      frontend.Variable
	RecordIndex frontend.Variable
}

type recordQuery struct {
	active, member, index frontend.Variable
}

type pooledRecord struct {
	escrowKey  frontend.Variable
	onList     [NSources]frontend.Variable
	mintPolicy mintPolicyWires
}

const pooledColumns = 4 + NSources

type pooledTable struct {
	active frontend.Variable
	table  *lookup.Table
}

type recordPool struct{ pooledTable }

type subjectPool struct{ pooledTable }

func openRecordPool(api frontend.API, active, root frontend.Variable, records []registry.Record, proof registry.SharedQuadProof) recordPool {
	api.AssertIsBoolean(active)
	pool := recordPool{pooledTable{active: active, table: lookup.New(api, 2+pooledColumns)}}
	leaves := make([]frontend.Variable, len(records))
	for i, record := range records {
		leaves[i] = record.Hash(api)
		// No stored record fails these splits, ValueOutsideMask in program-libs/interface/src/instructions/instruction.rs keeps lists u64 and registry/apply_records.go keeps mint policy below 2^192.
		onList := sourceLists(api, record.Lists)
		row := pooledRecord{escrowKey: record.EscrowKey, onList: onList, mintPolicy: decodeMintPolicy(api, record.MintPolicy)}
		pool.table.Insert(row.columns(record.Member, record.Next))
	}
	proof.AssertLeavesWhen(api, active, root, leaves)
	return pool
}

// sourceLists keeps the NSources list bits a table can source, the split bounds lists below 2^ListBits.
func sourceLists(api frontend.API, lists frontend.Variable) [NSources]frontend.Variable {
	var onList [NSources]frontend.Variable
	copy(onList[:], api.ToBinary(lists, registry.ListBits))
	return onList
}

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

func (p pooledTable) lookup(api frontend.API, query recordQuery) []frontend.Variable {
	api.AssertIsBoolean(query.active)
	api.AssertIsEqual(api.Mul(query.active, api.Sub(1, p.active)), 0)
	return p.table.Lookup(query.index)
}

func (p recordPool) resolve(api frontend.API, query recordQuery) pooledRecord {
	row := p.lookup(api, query)
	result := pooledRecordAt(row[2:])
	present := api.IsZero(api.Sub(row[0], query.member))
	ringgadget.AssertOrderedWhen(api, api.Mul(query.active, api.Sub(1, present)), row[0], query.member, row[1])
	live := api.Mul(query.active, present)
	return result.gated(api, live)
}

func (r pooledRecord) columns(prefix ...frontend.Variable) []frontend.Variable {
	row := append(prefix, r.escrowKey, r.mintPolicy.threshold, r.mintPolicy.cap, r.mintPolicy.cosignAbove)
	return append(row, r.onList[:]...)
}

func pooledRecordAt(columns []frontend.Variable) pooledRecord {
	record := pooledRecord{escrowKey: columns[0], mintPolicy: mintPolicyWires{threshold: columns[1], cap: columns[2], cosignAbove: columns[3]}}
	copy(record.onList[:], columns[4:])
	return record
}

func (r pooledRecord) gated(api frontend.API, active frontend.Variable) pooledRecord {
	for i, bit := range r.onList {
		r.onList[i] = api.Mul(active, bit)
	}
	r.escrowKey = api.Mul(active, r.escrowKey)
	r.mintPolicy.threshold = api.Mul(active, r.mintPolicy.threshold)
	r.mintPolicy.cap = api.Mul(active, r.mintPolicy.cap)
	r.mintPolicy.cosignAbove = api.Mul(active, r.mintPolicy.cosignAbove)
	return r
}

func openSubjectPool(api frontend.API, records recordPool, subjects []PoolSubject) subjectPool {
	pool := subjectPool{pooledTable{active: records.active, table: lookup.New(api, 1+pooledColumns)}}
	for _, subject := range subjects {
		resolved := records.resolve(api, recordQuery{active: records.active, member: subject.Member, index: subject.RecordIndex})
		pool.table.Insert(resolved.columns(subject.Member))
	}
	return pool
}

func (p subjectPool) resolve(api frontend.API, query recordQuery) pooledRecord {
	row := p.lookup(api, query)
	api.AssertIsEqual(api.Mul(query.active, api.Sub(row[0], query.member)), 0)
	return pooledRecordAt(row[1:]).gated(api, query.active)
}
