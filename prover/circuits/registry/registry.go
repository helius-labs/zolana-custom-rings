// Defines how member records sit in the ring's Merkle tree. Every circuit that
// reads or updates a record uses these hashes, so they must match the Rust
// registry exactly.
//
// Read first. Read before registry/opening.go, registry/shared_path.go,
// registry/apply_records.go.

// Package registry proves a ring's member registry, a 4-ary Poseidon tree whose records form one list sorted by member, and the writes the ring program queues and applies to it.
package registry

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

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
type Record struct {
	Member frontend.Variable
	RecordBody
}

type RecordBody struct {
	Next                frontend.Variable
	Lists               frontend.Variable
	EscrowKey           frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
}

func (r Record) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{r.Member, r.Next}, r.contents()))
}

// contents keeps the record hash order.
func (b RecordBody) contents() []frontend.Variable {
	return append([]frontend.Variable{b.Lists, b.EscrowKey, b.MintPolicy, b.WithdrawalThreshold}, b.AssetLimits[:]...)
}

func (b RecordBody) selectWhen(api frontend.API, cond frontend.Variable, other RecordBody) RecordBody {
	selected := RecordBody{
		Next:                api.Select(cond, b.Next, other.Next),
		Lists:               api.Select(cond, b.Lists, other.Lists),
		EscrowKey:           api.Select(cond, b.EscrowKey, other.EscrowKey),
		MintPolicy:          api.Select(cond, b.MintPolicy, other.MintPolicy),
		WithdrawalThreshold: api.Select(cond, b.WithdrawalThreshold, other.WithdrawalThreshold),
	}
	for i := range selected.AssetLimits {
		selected.AssetLimits[i] = api.Select(cond, b.AssetLimits[i], other.AssetLimits[i])
	}
	return selected
}

func (b RecordBody) assertEmptyWhen(api frontend.API, cond frontend.Variable) {
	for _, field := range b.contents() {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: field})
	}
}

// EscrowKey is the record field RegisterKey fills, mirrored by EscrowKey::hash in program-libs/interface/src/accounts/member_registry.rs.
func EscrowKey(api frontend.API, nullifierPk, ciphertextHash frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, ciphertextHash})
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

func foldQuadPath(api frontend.API, siblings [][Arity - 1]frontend.Variable, bits []frontend.Variable, leaf frontend.Variable) frontend.Variable {
	node := leaf
	for level, siblings := range siblings {
		node = gadget.PoseidonHash(api, quadChildren(api, node, siblings, bits[2*level], bits[2*level+1]))
	}
	return node
}

func quadChildren(api frontend.API, node frontend.Variable, siblings [Arity - 1]frontend.Variable, b0, b1 frontend.Variable) []frontend.Variable {
	// The digit bits are boolean, so exactly one of the four position flags is set.
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
