// Proves that a batch of enrollments the program read from authorization accounts
// was applied to the tracking tree. Anyone may apply, the program computes each
// entry from its account, so the proof only moves the tree. An enrollment grants
// nothing until its leaf sits under a root, and transfers, deposits and merges read
// an owner's key or list tag from that root. A tree out of order would let an
// enrolled owner prove itself unenrolled and skip its private lists.
//
// Read after registry/tracking.go, registry/register_key.go, registry/apply_records.go.
// Read before policy/tracking.go, prover/ring/ring.go.

package registry

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. NewRoot, NewNextIndex and ChainEnd follow from applying, in the named order, exactly the Count entries whose chain runs from ChainStart to ChainEnd.
// 2. Every active write inserts an absent owner after its low record at exactly the next index, below capacity. A later insert moves only a leaf's Next, its member, nullifier key, ciphertext hash and list tag never change, a viewing key rotation touches only the owner's account.
// 3. An owner holds one leaf, an owner already in the tree falls inside no link and cannot insert again.
// 4. The statement binds both roots, both next indexes, both chain ends and the count.
//
// The program holds what the circuit takes as given. tracking_chain_start in program-libs/interface/src/accounts/tracking.rs names one registry at one revision in ChainStart, and TrackingAuthorization::apply refuses an applied account.

// TrackingEntry mirrors the entry the program computes from an authorization account.
type TrackingEntry struct {
	Member, NullifierPk, CtHash, ListTag frontend.Variable
}

func (e TrackingEntry) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.TrackingEntryDomain, e.Member, e.NullifierPk, e.CtHash, e.ListTag})
}

// EnrollmentWrite's Slot opens the empty leaf the insert takes.
type EnrollmentWrite struct {
	Entry   TrackingEntry
	Slot    TrackingPath
	Low     TrackingRecord
	LowSlot TrackingPath
}

// ApplyEnrollmentsCircuit only moves the tree, the program computes each entry and anyone may apply.
type ApplyEnrollmentsCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot      frontend.Variable
	NewRoot      frontend.Variable
	OldNextIndex frontend.Variable
	NewNextIndex frontend.Variable
	ChainStart   frontend.Variable
	ChainEnd     frontend.Variable
	Count        frontend.Variable
	Writes       []EnrollmentWrite
}

func NewApplyEnrollmentsCircuit(writes int) (*ApplyEnrollmentsCircuit, error) {
	if err := shared.ValidateWidth("tracking", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyEnrollmentsCircuit{NumWrites: writes, Writes: make([]EnrollmentWrite, writes)}, nil
}

func (c *ApplyEnrollmentsCircuit) Define(api frontend.API) error {
	if err := errors.Join(shared.ValidateWidth("tracking", c.NumWrites, ApplyWidths), shared.ValidateLength("tracking", "write", len(c.Writes), c.NumWrites)); err != nil {
		return err
	}
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	// 2. Every active write moves the running root, next index and chain in the named order.
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart}
	for i, w := range c.Writes {
		state = w.apply(api, count.Active[i], state)
	}
	// 3. The tree after the batch and the entries it consumed are the statement's.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement()))
	return nil
}

func (w EnrollmentWrite) apply(api frontend.API, active frontend.Variable, s registryState) registryState {
	// 1. The owner lies strictly inside its low record's link under the running root, a link no present owner falls inside.
	// The sort argument of registry/apply_records.go applies, the links descend from the sentinel's (0, q-1) by one split per insert. A present owner has no such link, so a second enrollment of one owner never proves.
	ringgadget.AssertOrderedWhen(api, active, w.Low.Member, w.Entry.Member, w.Low.Next)
	relinked := w.Low
	relinked.Next = w.Entry.Member
	lowRoot, linked := w.LowSlot.Update(api, w.Low.Hash(api), relinked.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: lowRoot, B: s.root})
	// 2. The insert takes the empty leaf 0 at the next index under the relinked root, linking on to the low record's old next.
	// At next = TrackingCapacity the index fails TrackingPath.digits, a full tree takes no new owner.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: w.Slot.Index, B: s.next})
	after := TrackingRecord{
		Member: w.Entry.Member, Next: w.Low.Next, NullifierPk: w.Entry.NullifierPk, CtHash: w.Entry.CtHash, ListTag: w.Entry.ListTag,
	}.Hash(api)
	opened, written := w.Slot.Update(api, 0, after)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: opened, B: linked})
	// 3. The chain absorbs every active entry, the program computed each from its account.
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, w.Entry.Hash(api)})
	return registryState{
		root:  api.Select(active, written, s.root),
		next:  api.Add(s.next, active),
		chain: api.Select(active, chain, s.chain),
	}
}

// statement mirrors ApplyEnrollmentsStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *ApplyEnrollmentsCircuit) statement() []frontend.Variable {
	return []frontend.Variable{
		shared.ApplyEnrollmentsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
	}
}
