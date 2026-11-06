// Ties each note's nullifier key to its owner's enrollment, and gives every live input owner a row the
// policy reads.
//
// SPP takes any nullifier key an output names. A ring auditor must link every published nullifier to
// the note it spends, so a ring cannot let a note carry a key whose secret the auditor never received.
// Enrollment seals an owner's nullifier secret to the auditor and writes its key to the tracking tree,
// and only two keys pass here.
// An enrolled owner receives under the key its row holds. Any owner can receive under the zero key
// Poseidon(0), registry/register_key.go refuses to enroll it, and its preimage is public, so anyone
// holding the note's opening, the auditor included, can compute the nullifier. Without these checks a
// sender could pay a note under a free key, and its spend would stay unlinked for the auditor.
// Under a salted payee read a zero key output still proves its owner absent from the tracking root, as
// docs/spec.md requires.
//
// Read after transfer/input.go, policy/tracking.go, registry/register_key.go. Read before
// policy/screen.go, policy/outflow.go.
//
// Properties:
// 1. Every live input's owner has a live row, the delegate's zero key note alone goes without.
// 2. A ring input's nonzero key is its row's enrolled key, a key the tracking root does not hold fails.
// 3. A hidden owner spends no zero key note, its public nullifier would name the owner.
// 4. A live ring output's nonzero key is its owner's enrolled key, and a literal zero key fails.
// 5. Under a salted payee read a zero key output leaves its owner absent under the root, else an enrolled owner may take it.
//
// A zero key note stays spendable after its owner enrolls, property 2 skips it.

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

// InputRail is what the input predicate reads about the rail.
type InputRail struct {
	// Delegate moves a zero-key note with no row, no policy reads the rows there.
	Delegate frontend.Variable
	// Hidden is set while HiddenOwner spends privately.
	Hidden, HiddenOwner frontend.Variable
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
func (r OwnerRows) AssertInputOwners(api frontend.API, rail InputRail, inputs []shared.Output) {
	for _, slot := range inputs {
		zeroKey := isZeroKey(api, slot.NullifierPk)
		found, key := r.find(api, slot.OwnerPkHash)
		// 1. Every live input has its owner's row, the sender rules and attribution read rows alone. Only the delegate's zero key note goes without. The check needs found to read exactly one, so a repeated row an input needs on the authority rail fails it as well.
		needsRow := api.Mul(slot.Utxo, api.Sub(1, api.Mul(rail.Delegate, zeroKey)))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: needsRow, V: api.Sub(1, found)})
		// 2. A ring note's key is the row's enrolled key, the auditor reads the nullifier through it. A default-ring note carries a key the ring never enrolled.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(slot.Ring, api.Sub(1, zeroKey)), A: slot.NullifierPk, B: key})
		// 3. Anyone holding the opening computes a zero-key nullifier, that spend would name the hidden owner.
		hidden := api.Mul(rail.Hidden, slot.Utxo, zeroKey)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: policy.IsSame(api, slot.OwnerPkHash, rail.HiddenOwner)})
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

// AssertOutputOwners holds a live ring output to its owner's enrolled key, and a zero key to an owner with no row while saltedPayees is set.
func AssertOutputOwners(api frontend.API, pool policy.TrackingPool, outputs []shared.Output, entries []frontend.Variable, saltedPayees frontend.Variable) {
	for o, slot := range outputs {
		// An exit clears Ring and reads no row, the default ring enrolls nobody.
		row := pool.Row(api, slot.Ring, slot.OwnerPkHash, entries[o])
		zeroKey := isZeroKey(api, slot.NullifierPk)
		// 1. The row's key equals the slot's nonzero key, an absent owner cannot receive under a key the auditor never received.
		// 2. Under a salted payee read the row's key is zero under the zero key, an enrolled owner cannot take it. Off that read the zero key skips the row.
		bound := api.Mul(slot.Ring, api.Sub(1, api.Mul(zeroKey, api.Sub(1, saltedPayees))))
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: bound, A: row.NullifierPk, B: api.Mul(api.Sub(1, zeroKey), slot.NullifierPk)})
		// A literal zero key would read as an absent row, and nobody could spend it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Ring, V: api.IsZero(slot.NullifierPk)})
	}
}

func isZeroKey(api frontend.API, nullifierPk frontend.Variable) frontend.Variable {
	return policy.IsSame(api, nullifierPk, shared.ZeroNullifierPk)
}
