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
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// fieldMax is q-1, the sentinel's next, above every member.
var fieldMax = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

// Record list bits mirror ListId::record_bit in program-libs/policy/src/list.rs.
const (
	AllowBit  = 1 << 0
	BlockBit  = 1 << 1
	FrozenBit = 1 << 2
	// PrivateBlockBit, PrivateAllowBit and PrivateFrozenBit are always salted.
	PrivateBlockBit  = 1 << 4
	ReaderBit        = 1 << 5
	ApprovalBit      = 1 << 6
	PrivateAllowBit  = 1 << 7
	PrivateFrozenBit = 1 << 8
)

// Record mirrors registry.Record.
type Record struct {
	Member, Next, Lists, MintPolicy, WithdrawalThreshold *big.Int
	AssetLimits                                          Limits
}

// Limits mirrors registry.Record.AssetLimits, a nil field reads as zero.
type Limits [registry.LimitFields]*big.Int

func (r Record) Hash(t testing.TB) *big.Int {
	t.Helper()
	fields := []*big.Int{r.Member, r.Next, r.Lists, copied(r.MintPolicy), copied(r.WithdrawalThreshold)}
	for _, field := range r.AssetLimits {
		fields = append(fields, copied(field))
	}
	return ringtest.MustPoseidonHash(t, fields...)
}

func (r Record) Wires() registry.Record {
	return registry.Record{Member: copied(r.Member), RecordBody: r.BodyWires()}
}

func (r Record) BodyWires() registry.RecordBody {
	return registry.RecordBody{Next: copied(r.Next), Lists: copied(r.Lists), MintPolicy: copied(r.MintPolicy), WithdrawalThreshold: copied(r.WithdrawalThreshold), AssetLimits: r.AssetLimits.Wires()}
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

// Value lies inside Mask, as the program requires of an entry.
type Entry struct {
	Member, Mask, Value, MintPolicy, WithdrawalThreshold *big.Int
	AssetLimits                                          Limits
}

// Hash mirrors registry.RecordWrite.Hash.
func (e Entry) Hash(t testing.TB) *big.Int {
	t.Helper()
	fields := []*big.Int{big.NewInt(shared.RecordWriteDomain), e.Member, e.Mask, e.Value, copied(e.MintPolicy), copied(e.WithdrawalThreshold)}
	for _, field := range e.AssetLimits {
		fields = append(fields, copied(field))
	}
	return ringtest.MustPoseidonHash(t, fields...)
}

// ChainStart mirrors chain_start in program-libs/interface/src/accounts/storage.rs.
func ChainStart(t testing.TB, registry []byte, revision uint64) *big.Int {
	t.Helper()
	return spptest.MustHashChain4(t, []*big.Int{big.NewInt(shared.ApplyRecordsDomain), ringtest.HashBytes(t, registry), new(big.Int).SetUint64(revision)})
}

type Write struct {
	Entry                                                    Entry
	Exists                                                   bool
	OldNext, OldLists, OldMintPolicy, OldWithdrawalThreshold *big.Int
	OldAssetLimits                                           Limits
	Slot                                                     Path // the member's leaf or the next empty leaf, after the relink for an insert
	Low                                                      Record
	LowPath                                                  Path
}

// Registry keeps the sentinel at index 0 and appends every insert.
type Registry struct {
	records []Record
	tree    quadTree
}

func New(t testing.TB) *Registry {
	t.Helper()
	r := &Registry{tree: newQuadTree(t, registry.Height)}
	r.set(t, 0, Record{Member: big.NewInt(0), Next: fieldMax, Lists: big.NewInt(0)})
	return r
}

func (r *Registry) Root() *big.Int {
	return r.tree.root()
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
	// The program takes only members in [1, q-2] and values inside their mask.
	if e.Member.Sign() <= 0 || e.Member.Cmp(fieldMax) >= 0 || new(big.Int).AndNot(e.Value, e.Mask).Sign() != 0 {
		t.Fatalf("ringregistry: the program refuses %+v", e)
	}
	zero := big.NewInt(0)
	index, present := r.find(e.Member)
	if present {
		old := r.records[index]
		w := Write{Entry: e, Exists: true, OldNext: old.Next, OldLists: old.Lists, OldMintPolicy: copied(old.MintPolicy), OldWithdrawalThreshold: copied(old.WithdrawalThreshold), OldAssetLimits: old.AssetLimits,
			Slot: r.Path(index), Low: Record{Member: zero, Next: zero, Lists: zero, MintPolicy: zero, WithdrawalThreshold: zero}, LowPath: zeroPath()}
		r.set(t, index, Record{Member: e.Member, Next: old.Next, Lists: masked(old.Lists, e), MintPolicy: writtenPolicy(old.MintPolicy, e.MintPolicy), WithdrawalThreshold: writtenWithdrawal(old.WithdrawalThreshold, e), AssetLimits: writtenLimits(old.AssetLimits, e)})
		return w
	}
	low, next := r.records[index], r.NextIndex()
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldMintPolicy: zero, OldWithdrawalThreshold: zero, Slot: r.Path(next), Low: low, LowPath: r.Path(index)}
	if masked(zero, e).Sign() == 0 && writtenPolicy(zero, e.MintPolicy).Sign() == 0 && writtenWithdrawal(zero, e).Sign() == 0 && writtenLimits(Limits{}, e).IsZero() {
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
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldMintPolicy: zero, OldWithdrawalThreshold: zero, Low: low, LowPath: r.Path(index)}
	relinked := low
	relinked.Next = e.Member
	r.set(t, index, relinked)
	w.Slot = r.Path(next)
	r.set(t, next, Record{Member: e.Member, Next: low.Next, Lists: masked(zero, e), MintPolicy: writtenPolicy(zero, e.MintPolicy), WithdrawalThreshold: writtenWithdrawal(zero, e), AssetLimits: writtenLimits(Limits{}, e)})
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
	copy(p.Siblings[:], r.tree.siblings(index))
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
	return r.tree.node(level, index)
}

func (r *Registry) set(t testing.TB, index uint64, record Record) {
	t.Helper()
	if index == uint64(len(r.records)) {
		r.records = append(r.records, record)
	} else {
		r.records[index] = record
	}
	r.tree.setLeaf(t, index, record.Hash(t))
}

func masked(lists *big.Int, e Entry) *big.Int {
	return new(big.Int).Or(new(big.Int).AndNot(lists, e.Mask), e.Value)
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
