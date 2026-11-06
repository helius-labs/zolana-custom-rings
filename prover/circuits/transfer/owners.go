// Ties each spent note's nullifier key to its owner's enrollment, and gives every live input owner a row
// the policy reads.
//
// SPP takes any nullifier key an output names. A ring auditor must link every published nullifier to
// the note it spends, so a ring cannot spend a note whose key's secret the auditor never received.
// Enrollment seals an owner's nullifier secret to the auditor and writes its key to the tracking tree,
// and a spend passes under that key or under Poseidon(0), whose public zero secret derives the nullifier
// from the note opening.
// A ring output may carry any nonzero key, its note spends only once that key is its owner's enrolled key.
//
// Read after transfer/input.go, policy/tracking.go, registry/register_key.go. Read before
// policy/screen.go, policy/outflow.go.
//
// Properties:
// 1. Every live input's owner has a live row, the delegate's zero key note alone goes without.
// 2. A ring input's nonzero key is its row's enrolled key, a key the tracking root does not hold fails.
// 3. A zero key output requires owner absence at the accepted tracking root, and a literal zero key fails.
//
// A zero key note stays spendable after its owner enrolls, property 2 skips it. Its nullifier names its
// spender to anyone holding the opening, on the hidden rail too, the wallet decides whether to accept that.

package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// OwnerRows are the key's S rows, the policy and the input predicate read them and a constraint orders them.
type OwnerRows struct {
	Members  []frontend.Variable
	Live     []frontend.Variable
	Tracking []policy.TrackingView
}

// OpenOwnerRows reads each live row's enrollment, the policy holds the rows' order off the authority rail.
func OpenOwnerRows(api frontend.API, members, entries []frontend.Variable, pool policy.TrackingPool) OwnerRows {
	rows := OwnerRows{Members: members, Live: make([]frontend.Variable, len(members)), Tracking: make([]policy.TrackingView, len(members))}
	for j, member := range members {
		rows.Live[j] = ringgadget.IsNonZero(api, member)
		rows.Tracking[j] = pool.Row(api, rows.Live[j], member, entries[j])
	}
	return rows
}

// AssertInputOwners holds every live input to its row and enrolled key, an input past the rows would skip the sender rules and the auditor's nullifier.
func (r OwnerRows) AssertInputOwners(api frontend.API, delegate frontend.Variable, inputs []shared.Output) {
	for _, slot := range inputs {
		zeroKey := isZeroKey(api, slot.NullifierPk)
		found, key := r.find(api, slot.OwnerPkHash)
		// 1. Every live input has its owner's row, the sender rules and attribution read rows alone. Only the delegate's zero key note goes without. The check needs found to read exactly one, so a repeated row an input needs on the authority rail fails it as well.
		needsRow := api.Mul(slot.Utxo, api.Sub(1, api.Mul(delegate, zeroKey)))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: needsRow, V: api.Sub(1, found)})
		// 2. A ring note's key is the row's enrolled key, the auditor reads the nullifier through it. A default-ring note carries a key the ring never enrolled.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(slot.Ring, api.Sub(1, zeroKey)), A: slot.NullifierPk, B: key})
	}
}

// find is set on the one live row of owner, with that row's enrolled key, a zero owner matches no padding.
func (r OwnerRows) find(api frontend.API, owner frontend.Variable) (found, key frontend.Variable) {
	found, key = 0, 0
	for j, member := range r.Members {
		hit := api.Mul(r.Live[j], policy.IsSame(api, owner, member))
		found = api.Add(found, hit)
		key = api.Add(key, api.Mul(hit, r.Tracking[j].NullifierPk))
	}
	return found, key
}

// AssertOutputOwners binds zero key recipients to absence at the accepted tracking root.
func AssertOutputOwners(api frontend.API, pool policy.TrackingPool, outputs []shared.Output, entries []frontend.Variable) {
	for o, slot := range outputs {
		// 1. A zero key output goes only to an owner absent at the tracking root, an unread row reads zeros. An exit clears Ring and reads no row, the default ring enrolls nobody.
		zeroKey := api.Mul(slot.Ring, isZeroKey(api, slot.NullifierPk))
		api.AssertIsEqual(pool.Row(api, zeroKey, slot.OwnerPkHash, entries[o]).NullifierPk, 0)
		// 2. A literal zero key would read as an absent row, and nobody could spend it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Ring, V: api.IsZero(slot.NullifierPk)})
	}
}

func isZeroKey(api frontend.API, nullifierPk frontend.Variable) frontend.Variable {
	return policy.IsSame(api, nullifierPk, shared.ZeroNullifierPk)
}
