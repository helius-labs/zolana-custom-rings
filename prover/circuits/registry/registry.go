// Defines how member records sit in a ring's policy registry. SPP has no lists, a
// ring reads an owner's or an asset's list bits and mint settings from these records
// inside its proofs. Every circuit that reads or writes a record hashes it here, and
// a leaf that differs from the Rust registry opens under no root the storage program
// holds.
//
// The tree carries the low element idea of SPP's BatchAddressTreeAppendCircuit in
// zolana/prover/server/circuits/nullifier_tree.go. Leaves sit in insert order and each
// record links to the next member in sort order, so a member is absent exactly when it
// falls strictly inside one link. Unlike an SPP nullifier leaf, a record holds data
// and a later write can change it.
//
// Read after ringgadget/canonical.go. Read before registry/shared_path.go,
// registry/apply_records.go, registry/tracking.go.

// Package registry proves a ring's member registry, a 4-ary Poseidon tree whose records form one list sorted by member, and the writes a storage `Update` carries to it.
package registry

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. A leaf covers its member, its link and every field a read or a write depends on, mirrored by MemberRecord::hash in program-libs/member-registry/src/record.rs.
// 2. A path puts one leaf at one index, Index is bound below Capacity and the node takes the child position its two index bits name at each level.
// 3. A node hashes four children and a leaf eight fields, Poseidon's constants differ per width and no node opens as a leaf.

// The tree shape mirrors program-libs/interface/src/accounts/member_registry.rs.
const (
	Height    = 10
	Arity     = 4
	IndexBits = 2 * Height
	Capacity  = 1 << IndexBits
	// ListBits is the width of a record's list bitmap, bit id-1 marks list id.
	ListBits = 64
	// LimitFields mirrors AssetLimits::fields in program-libs/policy/src/asset_limits.rs.
	LimitFields = 3
)

// The empty leaf is 0, and the sentinel (0, q-1, 0, 0, 0, 0, 0, 0) at index 0 brackets every member in [1, q-2].
// A record reaches the hash 0 only through a Poseidon preimage nobody can find, a written leaf never reads as empty.
type Record struct {
	Member frontend.Variable
	RecordBody
}

type RecordBody struct {
	Next                frontend.Variable
	Lists               frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
}

func (r Record) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{r.Member, r.Next}, r.contents()))
}

// contents keeps the record hash order.
// Next stays out, it belongs to the list and a record emptied of its contents keeps its link.
func (b RecordBody) contents() []frontend.Variable {
	return slices.Concat([]frontend.Variable{b.Lists, b.MintPolicy, b.WithdrawalThreshold}, b.AssetLimits[:])
}

// assertEmptyWhen leaves Next free, an absent member has no link until an insert gives it one.
func (b RecordBody) assertEmptyWhen(api frontend.API, cond frontend.Variable) {
	for _, field := range b.contents() {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: field})
	}
}

type QuadPath struct {
	Index    frontend.Variable
	Siblings [Height][Arity - 1]frontend.Variable // each level's other three children in child order, leaf level first
}

func (p QuadPath) Root(api frontend.API, leaf frontend.Variable) frontend.Variable {
	return p.fold(api, p.digits(api), leaf)
}

func (p QuadPath) Update(api frontend.API, oldLeaf, newLeaf frontend.Variable) (oldRoot, newRoot frontend.Variable) {
	// One index decomposition places the old and the new leaf in the same slot.
	digits := p.digits(api)
	return p.fold(api, digits, oldLeaf), p.fold(api, digits, newLeaf)
}

func (p QuadPath) digits(api frontend.API) []frontend.Variable {
	// IndexBits bits bound Index below Capacity, one index per leaf and no alias Index + Capacity.
	return api.ToBinary(p.Index, IndexBits)
}

func (p QuadPath) fold(api frontend.API, digits []frontend.Variable, leaf frontend.Variable) frontend.Variable {
	return foldQuadPath(api, p.Siblings[:], digits, leaf)
}

// foldQuadPath takes two bits per level, low bit first, and bits may run past siblings for a canopy to read.
func foldQuadPath(api frontend.API, siblings [][Arity - 1]frontend.Variable, bits []frontend.Variable, leaf frontend.Variable) frontend.Variable {
	node := leaf
	for level, siblings := range siblings {
		node = gadget.PoseidonHash(api, quadChildren(api, node, siblings, bits[2*level], bits[2*level+1]))
	}
	return node
}

func quadChildren(api frontend.API, node frontend.Variable, siblings [Arity - 1]frontend.Variable, b0, b1 frontend.Variable) []frontend.Variable {
	// The digit bits are boolean, so exactly one of the four position flags is set.
	// The node takes the child slot of its flag and the siblings fill the other three in order, one child order per digit.
	three := api.Mul(b0, b1)
	one := api.Sub(b0, three)
	two := api.Sub(b1, three)
	zero := api.Sub(api.Sub(1, b0), two)
	return []frontend.Variable{
		api.Select(zero, node, siblings[0]),
		api.Select(zero, siblings[0], api.Select(one, node, siblings[1])),
		api.Select(three, siblings[2], api.Select(two, node, siblings[1])),
		api.Select(three, node, siblings[2]),
	}
}
