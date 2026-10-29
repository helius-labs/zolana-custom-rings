// Package ringregistry is the host twin of circuits/registry for the Go tests.
package ringregistry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
)

// fieldMax is q-1, the sentinel's next, above every member.
var fieldMax = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

// Record list bits mirror ListId::record_bit in program-libs/policy/src/list.rs.
const (
	AllowBit  = 1 << 0
	BlockBit  = 1 << 1
	FrozenBit = 1 << 2
	EscrowBit = 1 << 7
)

// Record mirrors registry.Record.
type Record struct {
	Member, Next, Lists, EscrowKey, MintPolicy, WithdrawalThreshold *big.Int
	AssetLimits                                                     Limits
}

// Limits mirrors registry.Record.AssetLimits, a nil field reads as zero.
type Limits [registry.LimitFields]*big.Int

func (r Record) Hash(t testing.TB) *big.Int {
	t.Helper()
	fields := []*big.Int{r.Member, r.Next, r.Lists, r.EscrowKey, copied(r.MintPolicy), copied(r.WithdrawalThreshold)}
	for _, field := range r.AssetLimits {
		fields = append(fields, copied(field))
	}
	return ringtest.MustPoseidonHash(t, fields...)
}

func (r Record) Wires() registry.Record {
	return registry.Record{Member: copied(r.Member), Next: copied(r.Next), Lists: copied(r.Lists), EscrowKey: copied(r.EscrowKey), MintPolicy: copied(r.MintPolicy), WithdrawalThreshold: copied(r.WithdrawalThreshold), AssetLimits: r.AssetLimits.Wires()}
}

func VectorLimits(t testing.TB, fields []ringtest.Hex) Limits {
	t.Helper()
	var limits Limits
	if len(fields) != len(limits) {
		t.Fatalf("%d limit fields, want %d", len(fields), len(limits))
	}
	for i, field := range fields {
		limits[i] = field.Int
	}
	return limits
}

func (l Limits) Wires() [registry.LimitFields]frontend.Variable {
	var w [registry.LimitFields]frontend.Variable
	for i, field := range l {
		w[i] = copied(field)
	}
	return w
}

// EscrowKey mirrors registry.EscrowKey.
func EscrowKey(t testing.TB, nullifierPk, ctHash *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, nullifierPk, ctHash)
}

// Path mirrors registry.QuadPath.
type Path struct {
	Index    uint64
	Siblings [registry.Height][registry.Arity - 1]*big.Int
}

func (p Path) Wires() registry.QuadPath {
	w := registry.QuadPath{Index: p.Index}
	for level, siblings := range p.Siblings {
		for k, sibling := range siblings {
			w.Siblings[level][k] = new(big.Int).Set(sibling)
		}
	}
	return w
}

// Root mirrors registry.QuadPath.Root.
func (p Path) Root(t testing.TB, leaf *big.Int) *big.Int {
	t.Helper()
	node := leaf
	for level, siblings := range p.Siblings {
		digit := int(p.Index>>(2*level)) & (registry.Arity - 1)
		children := append(append(append([]*big.Int{}, siblings[:digit]...), node), siblings[digit:]...)
		node = ringtest.MustPoseidonHash(t, children...)
	}
	return node
}

// Opening opens Record, the member's own when Present, else the low record bracketing it.
type Opening struct {
	Present bool
	Record  Record
	Path    Path
}

// Wires zeroes the unused half.
func (o Opening) Wires() registry.QuadOpening {
	zero := Limits{}.Wires()
	w := registry.QuadOpening{Present: 0, Next: 0, Lists: 0, EscrowKey: 0, MintPolicy: 0, LowMintPolicy: 0, WithdrawalThreshold: 0, LowWithdrawalThreshold: 0, AssetLimits: zero, LowAssetLimits: zero, LowMember: 0, LowNext: 0, LowLists: 0, LowEscrow: 0, Path: o.Path.Wires()}
	r := o.Record
	if o.Present {
		w.Present, w.Next, w.Lists, w.EscrowKey, w.MintPolicy, w.WithdrawalThreshold, w.AssetLimits = 1, copied(r.Next), copied(r.Lists), copied(r.EscrowKey), copied(r.MintPolicy), copied(r.WithdrawalThreshold), r.AssetLimits.Wires()
		return w
	}
	w.LowMember, w.LowNext, w.LowLists, w.LowEscrow, w.LowMintPolicy, w.LowWithdrawalThreshold, w.LowAssetLimits = copied(r.Member), copied(r.Next), copied(r.Lists), copied(r.EscrowKey), copied(r.MintPolicy), copied(r.WithdrawalThreshold), r.AssetLimits.Wires()
	return w
}

// RecordWires expects a present member.
func (o Opening) RecordWires() registry.QuadRecordOpening {
	r := o.Record
	return registry.QuadRecordOpening{Next: copied(r.Next), Lists: copied(r.Lists), EscrowKey: copied(r.EscrowKey), MintPolicy: copied(r.MintPolicy), WithdrawalThreshold: copied(r.WithdrawalThreshold), AssetLimits: r.AssetLimits.Wires(), Path: o.Path.Wires()}
}

// UnreadRecordWires is the zero opening a proof assigns where it reads no record.
func UnreadRecordWires() registry.QuadRecordOpening {
	zero := big.NewInt(0)
	return Opening{Record: Record{Next: zero, Lists: zero, EscrowKey: zero}, Path: zeroPath()}.RecordWires()
}

// Value lies inside Mask, as the program queues an entry.
type Entry struct {
	Member, Mask, Value, EscrowKey, MintPolicy, WithdrawalThreshold *big.Int
	AssetLimits                                                     Limits
}

// Hash mirrors registry.QueueEntry.Hash.
func (e Entry) Hash(t testing.TB) *big.Int {
	t.Helper()
	fields := []*big.Int{big.NewInt(shared.QueueWriteDomain), e.Member, e.Mask, e.Value, e.EscrowKey, copied(e.MintPolicy), copied(e.WithdrawalThreshold)}
	for _, field := range e.AssetLimits {
		fields = append(fields, copied(field))
	}
	return ringtest.MustPoseidonHash(t, fields...)
}

type Write struct {
	Entry                                                               Entry
	Exists                                                              bool
	OldNext, OldLists, OldEscrow, OldMintPolicy, OldWithdrawalThreshold *big.Int
	OldAssetLimits                                                      Limits
	Slot                                                                Path // the member's leaf or the next empty leaf, after the relink for an insert
	Low                                                                 Record
	LowPath                                                             Path
}

// Registry keeps the sentinel at index 0 and appends every insert.
type Registry struct {
	records []Record
	nodes   [registry.Height + 1]map[uint64]*big.Int
	empty   [registry.Height + 1]*big.Int
}

func New(t testing.TB) *Registry {
	t.Helper()
	r := &Registry{}
	r.empty[0] = big.NewInt(0)
	for level := 1; level <= registry.Height; level++ {
		e := r.empty[level-1]
		r.empty[level] = ringtest.MustPoseidonHash(t, e, e, e, e)
	}
	for level := range r.nodes {
		r.nodes[level] = map[uint64]*big.Int{}
	}
	r.set(t, 0, Record{Member: big.NewInt(0), Next: fieldMax, Lists: big.NewInt(0), EscrowKey: big.NewInt(0)})
	return r
}

func (r *Registry) Root() *big.Int {
	return new(big.Int).Set(r.node(registry.Height, 0))
}

func (r *Registry) NextIndex() uint64 {
	return uint64(len(r.records))
}

func (r *Registry) Opening(member *big.Int) Opening {
	index, present := r.find(member)
	return Opening{Present: present, Record: r.records[index], Path: r.Path(index)}
}

// Apply mirrors the apply circuit and returns the write's witness.
func (r *Registry) Apply(t testing.TB, e Entry) Write {
	t.Helper()
	// The program queues only members in [1, q-2] and values inside their mask.
	if e.Member.Sign() <= 0 || e.Member.Cmp(fieldMax) >= 0 || new(big.Int).AndNot(e.Value, e.Mask).Sign() != 0 {
		t.Fatalf("ringregistry: the program never queues %+v", e)
	}
	zero := big.NewInt(0)
	index, present := r.find(e.Member)
	if present {
		old := r.records[index]
		w := Write{Entry: e, Exists: true, OldNext: old.Next, OldLists: old.Lists, OldEscrow: old.EscrowKey, OldMintPolicy: copied(old.MintPolicy), OldWithdrawalThreshold: copied(old.WithdrawalThreshold), OldAssetLimits: old.AssetLimits,
			Slot: r.Path(index), Low: Record{Member: zero, Next: zero, Lists: zero, EscrowKey: zero, MintPolicy: zero, WithdrawalThreshold: zero}, LowPath: zeroPath()}
		r.set(t, index, Record{Member: e.Member, Next: old.Next, Lists: masked(old.Lists, e), EscrowKey: fillOnce(old.EscrowKey, e.EscrowKey), MintPolicy: writtenPolicy(old.MintPolicy, e.MintPolicy), WithdrawalThreshold: writtenWithdrawal(old.WithdrawalThreshold, e), AssetLimits: writtenLimits(old.AssetLimits, e)})
		return w
	}
	low, next := r.records[index], r.NextIndex()
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldEscrow: zero, OldMintPolicy: zero, OldWithdrawalThreshold: zero, Slot: r.Path(next), Low: low, LowPath: r.Path(index)}
	if masked(zero, e).Sign() == 0 && e.EscrowKey.Sign() == 0 && writtenPolicy(zero, e.MintPolicy).Sign() == 0 && writtenWithdrawal(zero, e).Sign() == 0 && writtenLimits(Limits{}, e).IsZero() {
		return w
	}
	return r.Insert(t, e)
}

// Insert relinks the low record to e's member and appends e's record, an empty record included.
func (r *Registry) Insert(t testing.TB, e Entry) Write {
	t.Helper()
	zero := big.NewInt(0)
	index, _ := r.find(e.Member)
	low, next := r.records[index], r.NextIndex()
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldEscrow: zero, OldMintPolicy: zero, OldWithdrawalThreshold: zero, Low: low, LowPath: r.Path(index)}
	relinked := low
	relinked.Next = e.Member
	r.set(t, index, relinked)
	w.Slot = r.Path(next)
	r.set(t, next, Record{Member: e.Member, Next: low.Next, Lists: masked(zero, e), EscrowKey: e.EscrowKey, MintPolicy: writtenPolicy(zero, e.MintPolicy), WithdrawalThreshold: writtenWithdrawal(zero, e), AssetLimits: writtenLimits(Limits{}, e)})
	return w
}

// find returns member's index, or the index of the record with the largest member below it.
func (r *Registry) find(member *big.Int) (uint64, bool) {
	low := uint64(0)
	for i, record := range r.records {
		switch record.Member.Cmp(member) {
		case 0:
			return uint64(i), true
		case -1:
			if record.Member.Cmp(r.records[low].Member) > 0 {
				low = uint64(i)
			}
		}
	}
	return low, false
}

// Path opens the leaf at index, an empty leaf past the next index included.
func (r *Registry) Path(index uint64) Path {
	p := Path{Index: index}
	for level := range p.Siblings {
		node := index >> (2 * level)
		k := 0
		for child := node &^ (registry.Arity - 1); k < registry.Arity-1; child++ {
			if child != node {
				p.Siblings[level][k] = new(big.Int).Set(r.node(level, child))
				k++
			}
		}
	}
	return p
}

func zeroPath() Path {
	p := Path{}
	for level := range p.Siblings {
		for k := range p.Siblings[level] {
			p.Siblings[level][k] = big.NewInt(0)
		}
	}
	return p
}

func (r *Registry) node(level int, index uint64) *big.Int {
	if node, ok := r.nodes[level][index]; ok {
		return node
	}
	return r.empty[level]
}

func (r *Registry) set(t testing.TB, index uint64, record Record) {
	t.Helper()
	if index == uint64(len(r.records)) {
		r.records = append(r.records, record)
	} else {
		r.records[index] = record
	}
	r.nodes[0][index] = record.Hash(t)
	for level := 0; level < registry.Height; level++ {
		parent := index >> (2 * (level + 1))
		first := parent * registry.Arity
		r.nodes[level+1][parent] = ringtest.MustPoseidonHash(t, r.node(level, first), r.node(level, first+1), r.node(level, first+2), r.node(level, first+3))
	}
}

func masked(lists *big.Int, e Entry) *big.Int {
	return new(big.Int).Or(new(big.Int).AndNot(lists, e.Mask), e.Value)
}

func fillOnce(old, key *big.Int) *big.Int {
	if old.Sign() != 0 {
		return old
	}
	return key
}

func copied(v *big.Int) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(v)
}

func writtenPolicy(old, update *big.Int) *big.Int {
	if update == nil || update.Sign() == 0 {
		return copied(old)
	}
	return new(big.Int).Sub(update, new(big.Int).Lsh(big.NewInt(1), 192))
}

func writtenWithdrawal(old *big.Int, e Entry) *big.Int {
	if e.MintPolicy == nil || e.MintPolicy.Sign() == 0 {
		return copied(old)
	}
	return copied(e.WithdrawalThreshold)
}

func writtenLimits(old Limits, e Entry) Limits {
	if e.MintPolicy == nil || e.MintPolicy.Sign() == 0 {
		return old
	}
	return e.AssetLimits
}

func (l Limits) IsZero() bool {
	for _, field := range l {
		if field != nil && field.Sign() != 0 {
			return false
		}
	}
	return true
}
