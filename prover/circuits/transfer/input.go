// Reopens the slots SPP spends and the signer run the program hashed, the two facts the rail's owner
// predicate reads.
//
// SPP holds each input's owner to its own signer vector or hidden owner, under the rail of the SPP
// circuit it runs. The ring binds rail bits of its own in its statement. For notes, the owner relation
// binds those bits to the owners the rows and policy read. On the signer rail, every note owner
// belongs to the published run. SPP alone authorizes address owners.
//
// Read after transfer/transfer.go, shared/utxo.go. Read before transfer/owners.go, policy/screen.go.
//
// Properties established for the transfer statement.
// 1. Notes and addresses retain SPP order before the dummy suffix, with no non-dummy slot past InputCount.
// 2. A note belongs to the bound ring, a default-ring note passes only on an entry key.
// 3. The run holds SignerCount members and zeros past them, its chain is the one the program hashed and zero on an empty run.
// 4. While active, every note owner is a counted member or the rail's private owner.
// 5. NullifierChain binds InputCount and the exact capacity of ordered nullifiers, with a zero tail past InputCount.
// 6. AddressChain selects the nonzero nullifiers at address positions from the same bound list.

package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Ownership stays with the rail's predicates.
type InputSection struct {
	Slots []shared.Output
	// utxo * hash per slot, the list private_tx_hash chains.
	Hashes         []frontend.Variable
	Count          ringgadget.Count
	AddressChain   frontend.Variable
	NullifierChain frontend.Variable
}

func OpenInputs(api frontend.API, inputs []shared.UtxoWires, inputCount frontend.Variable, nullifiers []frontend.Variable) InputSection {
	// 1. The capacity fits the audit bitmap, and InputCount selects one nonempty published prefix.
	if err := shared.ValidateInputCapacity(len(inputs)); err != nil {
		panic(err)
	}
	if err := shared.ValidateLength("transfer", "input nullifier", len(nullifiers), len(inputs)); err != nil {
		panic(err)
	}
	section := InputSection{
		Slots:  make([]shared.Output, len(inputs)),
		Hashes: make([]frontend.Variable, len(inputs)),
		Count:  ringgadget.SelectCount(api, inputCount, 1, len(inputs)),
	}
	addressNullifiers := make([]frontend.Variable, len(inputs))
	ordered := make([]transaction.UtxoCircuitFields, len(inputs))
	// 2. Every non-dummy slot has a published nullifier. A selected address cannot disappear from
	// NonZeroHashChain through a zero nullifier, and unpublished nullifiers cannot extend the statement digest.
	for i, input := range inputs {
		slot := input.OpenInput(api)
		active := section.Count.Active[i]
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: api.Add(slot.Utxo, slot.Address)})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: nullifiers[i]})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: active, V: api.IsZero(nullifiers[i])})
		ordered[i] = transaction.UtxoCircuitFields{Domain: input.Domain}
		section.Slots[i], section.Hashes[i] = slot, api.Mul(slot.Utxo, slot.Hash)
		addressNullifiers[i] = api.Mul(slot.Address, nullifiers[i])
	}
	// 3. SPP permits notes and addresses to interleave, but no non-dummy slot follows a dummy.
	// Once address positions are fixed, the note chain fills the remaining positions before the dummy suffix.
	transaction.AssertDummiesLast(api, ordered)
	// 4. The program binds the full nullifier list through NullifierChain, and PrivateTxHash binds
	// the selected address subsequence. SPP requires distinct published nullifiers, so equal address
	// subsequences select the same absolute positions under the hash binding assumption.
	section.AddressChain = gadget.NonZeroHashChain(api, addressNullifiers)
	section.NullifierChain = gadget.HashChain4(api, append([]frontend.Variable{inputCount}, nullifiers...))
	return section
}

// AssertRingNotes holds every note to the bound ring, a key with entry capacity also spends a default-ring note.
func (s InputSection) AssertRingNotes(api frontend.API, ringID frontend.Variable, entry bool) {
	for _, slot := range s.Slots {
		// Off an entry key the condition reads every note, so a default-ring note fails its zero ring id. The auditor stream of such a key has no evidence to open one.
		cond := slot.Utxo
		if entry {
			cond = slot.Ring
		}
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: slot.RingProgramID, B: ringID})
	}
}

// SignerSet is the SPP owner signer run the program rebuilds, in its order.
type SignerSet struct {
	Members []frontend.Variable
	Count   ringgadget.Count
	// Chain is zero at a count of zero, the value the in-proof and authority rails bind.
	Chain frontend.Variable
}

func OpenSigners(api frontend.API, members []frontend.Variable, signerCount frontend.Variable) SignerSet {
	count := ringgadget.SelectCount(api, signerCount, 0, len(members)+1)
	for k, member := range members {
		// A member past the count would extend the chain the program hashed.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, count.Active[k]), V: member})
	}
	return SignerSet{Members: members, Count: count, Chain: api.Mul(api.Sub(1, count.OneHot[0]), gadget.HashChain4(api, members))}
}

// AssertOwners holds every note owner to a counted member or to private while active is set.
func (s SignerSet) AssertOwners(api frontend.API, section InputSection, active, private frontend.Variable) {
	for _, slot := range section.Slots {
		// Either factor reads zero on a permitted owner. A zero owner would match a zero private here, AssertInputOwners refuses it for want of a row.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(active, slot.Utxo), V: api.Mul(s.missing(api, slot.OwnerPkHash), api.Sub(slot.OwnerPkHash, private))})
	}
}

// missing is zero exactly when owner is a counted member, a zero owner never matches padding.
func (s SignerSet) missing(api frontend.API, owner frontend.Variable) frontend.Variable {
	product := frontend.Variable(1)
	for k, member := range s.Members {
		active := s.Count.Active[k]
		product = api.Mul(product, api.Add(api.Mul(active, api.Sub(owner, member)), api.Sub(1, active)))
	}
	return product
}
