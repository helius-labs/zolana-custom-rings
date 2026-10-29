package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type QuadOpening struct {
	Present                frontend.Variable
	Next                   frontend.Variable
	Lists                  frontend.Variable
	EscrowKey              frontend.Variable
	MintPolicy             frontend.Variable
	WithdrawalThreshold    frontend.Variable
	AssetLimits            [LimitFields]frontend.Variable
	LowMember              frontend.Variable
	LowNext                frontend.Variable
	LowLists               frontend.Variable
	LowEscrow              frontend.Variable
	LowMintPolicy          frontend.Variable
	LowWithdrawalThreshold frontend.Variable
	LowAssetLimits         [LimitFields]frontend.Variable
	Path                   QuadPath
}

// Resolve returns the member's lists and escrow key, zero for an absent member or an unset cond, binding the opening to root while the boolean cond is set.
func (o QuadOpening) Resolve(api frontend.API, cond, root, member frontend.Variable) (lists, escrowKey, mintPolicy, withdrawalThreshold frontend.Variable) {
	// A fixed-shape circuit opens no record for a slot it never reads.
	if ringgadget.IsConstantZero(api, cond) {
		return 0, 0, 0, 0
	}
	// 1. Present is boolean, a fraction would blend the two records below.
	api.AssertIsBoolean(o.Present)
	// 2. The opened record is the member's own when present, its low record when absent.
	record := Record{
		Member:              api.Select(o.Present, member, o.LowMember),
		Next:                api.Select(o.Present, o.Next, o.LowNext),
		Lists:               api.Select(o.Present, o.Lists, o.LowLists),
		EscrowKey:           api.Select(o.Present, o.EscrowKey, o.LowEscrow),
		MintPolicy:          api.Select(o.Present, o.MintPolicy, o.LowMintPolicy),
		WithdrawalThreshold: api.Select(o.Present, o.WithdrawalThreshold, o.LowWithdrawalThreshold),
	}
	for i := range record.AssetLimits {
		record.AssetLimits[i] = api.Select(o.Present, o.AssetLimits[i], o.LowAssetLimits[i])
	}
	// 3. An absent member lies strictly inside its low record's link, and its lists and escrow key are zero.
	absent := api.Mul(cond, api.Sub(1, o.Present))
	ringgadget.AssertOrderedWhen(api, absent, o.LowMember, member, o.LowNext)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: o.Lists})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: o.EscrowKey})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: o.MintPolicy})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: o.WithdrawalThreshold})
	// 4. The opened record folds to root, a record of another registry or root fails.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: o.Path.Root(api, record.Hash(api)), B: root})
	return api.Mul(cond, o.Lists), api.Mul(cond, o.EscrowKey), api.Mul(cond, o.MintPolicy), api.Mul(cond, o.WithdrawalThreshold)
}

type QuadRecordOpening struct {
	Next                frontend.Variable
	Lists               frontend.Variable
	EscrowKey           frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
	Path                QuadPath
}

// AssertPresent opens the sentinel for member 0, the caller refuses member 0 directly or through the sentinel's zero escrow key.
func (o QuadRecordOpening) AssertPresent(api frontend.API, cond, root, member frontend.Variable) {
	leaf := Record{Member: member, Next: o.Next, Lists: o.Lists, EscrowKey: o.EscrowKey, MintPolicy: o.MintPolicy, WithdrawalThreshold: o.WithdrawalThreshold, AssetLimits: o.AssetLimits}.Hash(api)
	// The leaf names member, an absent member or another member's record fails the fold.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: o.Path.Root(api, leaf), B: root})
}
