package registry

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. NewRoot, NewNextIndex and ChainEnd follow from applying, in queue order, exactly the Count writes whose chain runs from ChainStart to ChainEnd.
// 2. A write keeps every list bit outside its mask while the program keeps Value inside Mask, and never replaces a registered escrow key.
// 3. An absent member is inserted after its low record at exactly the next index, and a write that would leave its record empty inserts nothing.
// 4. The statement binds both roots, both next indexes, both chain ends and the count.

// ApplyBatch is the wide apply key's write capacity, mirrored by APPLY_BATCH in program-libs/interface/src/accounts/member_registry.rs.
const ApplyBatch = 16

// ApplyWidths mirrors RingCircuit::apply_records in program-libs/interface/src/proof/key_catalog.rs.
var ApplyWidths = []int{1, 2, 4, 8, ApplyBatch}

// QueueEntry's EscrowKey is zero except on a RegisterKey write.
type QueueEntry struct {
	Member              frontend.Variable
	Mask                frontend.Variable
	Value               frontend.Variable
	EscrowKey           frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
}

// Hash is the entry the program chains at write time in program-libs/interface/src/accounts/member_registry.rs.
func (e QueueEntry) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, append([]frontend.Variable{shared.QueueWriteDomain, e.Member, e.Mask, e.Value, e.EscrowKey, e.MintPolicy, e.WithdrawalThreshold}, e.AssetLimits[:]...))
}

// RecordWrite's Slot opens the member's leaf, or the empty leaf an insert takes.
type RecordWrite struct {
	Entry   QueueEntry
	Exists  frontend.Variable
	Old     RecordBody
	Slot    QuadPath
	Low     Record
	LowSlot QuadPath
}

type ApplyRecordsCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot      frontend.Variable
	NewRoot      frontend.Variable
	OldNextIndex frontend.Variable
	NewNextIndex frontend.Variable
	ChainStart   frontend.Variable
	ChainEnd     frontend.Variable
	Count        frontend.Variable
	Writes       []RecordWrite
}

type registryState struct {
	root, next, chain frontend.Variable
}

func NewApplyRecordsCircuit(writes int) (*ApplyRecordsCircuit, error) {
	if err := shared.ValidateWidth("registry", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyRecordsCircuit{NumWrites: writes, Writes: make([]RecordWrite, writes)}, nil
}

func (c *ApplyRecordsCircuit) Define(api frontend.API) error {
	if err := errors.Join(shared.ValidateWidth("registry", c.NumWrites, ApplyWidths), transaction.ValidateLength("write", len(c.Writes), c.NumWrites)); err != nil {
		return err
	}
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	// 2. Every active write moves the running root, next index and chain in queue order.
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart}
	for i, w := range c.Writes {
		state = w.apply(api, count.Active[i], state)
	}
	// 3. The registry after the batch and the queue segment it consumed are the statement's.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement()))
	return nil
}

// apply moves s by w while active is set, an unset active leaves it.
func (w RecordWrite) apply(api frontend.API, active frontend.Variable, s registryState) registryState {
	// 1. List bits outside the mask keep their old value, the program keeps the chained Value inside the mask.
	updated := RecordBody{Next: w.Old.Next, Lists: api.Add(keptLists(api, w.Old.Lists, w.Entry.Mask), w.Entry.Value)}
	// 2. A registered escrow key is final, a later key leaves it.
	updated.EscrowKey = api.Select(api.IsZero(w.Old.EscrowKey), w.Entry.EscrowKey, w.Old.EscrowKey)
	// The 193 bit decomposition range-checks the entry.
	policyBits := api.ToBinary(w.Entry.MintPolicy, 193)
	updated.MintPolicy = api.Select(policyBits[192], api.FromBinary(policyBits[:192]...), w.Old.MintPolicy)
	updated.WithdrawalThreshold = api.Select(policyBits[192], w.Entry.WithdrawalThreshold, w.Old.WithdrawalThreshold)
	for i := range updated.AssetLimits {
		updated.AssetLimits[i] = api.Select(policyBits[192], w.Entry.AssetLimits[i], w.Old.AssetLimits[i])
	}
	// 3. An absent member has empty old fields and lies strictly inside its low record's link under the running root, a link no present member falls inside.
	api.AssertIsBoolean(w.Exists)
	absent := api.Mul(active, api.Sub(1, w.Exists))
	ringgadget.AssertOrderedWhen(api, absent, w.Low.Member, w.Entry.Member, w.Low.Next)
	w.Old.assertEmptyWhen(api, absent)
	relinked := w.Low
	relinked.Next = w.Entry.Member
	lowRoot, relinkedRoot := w.LowSlot.Update(api, w.Low.Hash(api), relinked.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: absent, A: lowRoot, B: s.root})
	// 4. Only a nonempty new record is inserted, an empty one leaves the member absent.
	var nonzero []frontend.Variable
	for _, field := range updated.contents() {
		nonzero = append(nonzero, ringgadget.IsNonZero(api, field))
	}
	insert := api.Mul(absent, ringgadget.IsAny(api, nonzero...))
	update := api.Mul(active, w.Exists)
	// 5. An insert relinks the low record to the member and takes the empty leaf at the next index, linking on to the low record's old next.
	linked := api.Select(insert, relinkedRoot, s.root)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.Slot.Index, B: s.next})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.Old.Next, B: w.Low.Next})
	// 6. An update or insert replaces the slot's old leaf under the running root, an insert's old leaf is the empty leaf 0.
	before := api.Select(w.Exists, Record{Member: w.Entry.Member, RecordBody: w.Old}.Hash(api), 0)
	after := Record{Member: w.Entry.Member, RecordBody: updated}.Hash(api)
	opened, written := w.Slot.Update(api, before, after)
	changes := api.Add(insert, update)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: changes, A: opened, B: linked})
	// 7. The chain absorbs every active entry, no write is skipped, added or reordered.
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, w.Entry.Hash(api)})
	return registryState{
		root:  api.Select(changes, written, s.root),
		next:  api.Add(s.next, insert),
		chain: api.Select(active, chain, s.chain),
	}
}

func keptLists(api frontend.API, old, mask frontend.Variable) frontend.Variable {
	// Both bitmaps hold ListBits bits, the width of every record and queued mask.
	oldBits := api.ToBinary(old, ListBits)
	maskBits := api.ToBinary(mask, ListBits)
	kept := frontend.Variable(0)
	for i := range oldBits {
		kept = api.Add(kept, api.Mul(oldBits[i], api.Sub(1, maskBits[i]), new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	return kept
}

// statement mirrors ApplyRecordsStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *ApplyRecordsCircuit) statement() []frontend.Variable {
	return []frontend.Variable{
		shared.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
	}
}
