package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type QuadOpening struct {
	Present frontend.Variable
	RecordBody
	Low  Record
	Path QuadPath
}

// Resolve returns zeros for an absent member or an unset cond, binding the opening to root while the boolean cond is set.
func (o QuadOpening) Resolve(api frontend.API, cond, root, member frontend.Variable) (lists, escrowKey, mintPolicy, withdrawalThreshold frontend.Variable) {
	// A fixed-shape circuit opens no record for a slot it never reads.
	if ringgadget.IsConstantZero(api, cond) {
		return 0, 0, 0, 0
	}
	// 1. Present is boolean, a fraction would blend the two records below.
	api.AssertIsBoolean(o.Present)
	// 2. The opened record is the member's own when present, its low record when absent.
	record := Record{Member: api.Select(o.Present, member, o.Low.Member), RecordBody: o.selectWhen(api, o.Present, o.Low.RecordBody)}
	// 3. An absent member lies strictly inside its low record's link, and its own record is empty.
	absent := api.Mul(cond, api.Sub(1, o.Present))
	ringgadget.AssertOrderedWhen(api, absent, o.Low.Member, member, o.Low.Next)
	o.assertEmptyWhen(api, absent)
	// 4. The opened record folds to root, a record of another registry or root fails.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: o.Path.Root(api, record.Hash(api)), B: root})
	return api.Mul(cond, o.Lists), api.Mul(cond, o.EscrowKey), api.Mul(cond, o.MintPolicy), api.Mul(cond, o.WithdrawalThreshold)
}

type QuadRecordOpening struct {
	RecordBody
	Path QuadPath
}

// AssertPresent opens the sentinel for member 0, the caller refuses member 0 directly or through the sentinel's zero escrow key.
func (o QuadRecordOpening) AssertPresent(api frontend.API, cond, root, member frontend.Variable) {
	leaf := Record{Member: member, RecordBody: o.RecordBody}.Hash(api)
	// The leaf names member, an absent member or another member's record fails the fold.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: o.Path.Root(api, leaf), B: root})
}
