// Proves how many data-bearing output slots each entry of the published signer run owns.
//
// SPP takes one signature as authorization for every data-bearing output of that signer, and it
// publishes zero as a ring output's owner. A selective opening proves the slots it names and
// cannot show the sender named them all. The statement therefore carries one count per run entry,
// and a signer's off chain check demands exactly that many distinct openings.
//
// Scope. A slot with only a ring_data_hash needs no owner signature and never counts. The hidden
// owner stays outside the run and signs message_hash inside SPP's circuit. The delegate rail has an
// empty run, its element is zero.
//
// Added disclosure. The element publishes the public signers that receive data-bearing outputs and
// how many each receives. With one data-bearing output in the transaction, a count identifies its
// recipient and, because data-bearing slots are visible, its slot.
//
// The file proves the following.
//  1. The packed element is one 5 bit count per entry and fits its 60 bits.
//  2. Entry k equals the live data-bearing output slots owned by run member k, zero past the run.
//  3. A run member past the last entry owns no data-bearing output slot.
//
// Read after shared/utxo.go, audit/audit.go, transfer/input.go. Read before policy/policy.go.

package audit

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

const (
	// SignerDataEntries mirrors SignerDataCounts::ENTRIES, a v1 transaction's signature limit.
	SignerDataEntries = 12
	// SignerDataEntryBits mirrors SignerDataCounts::ENTRY_BITS, SPP's widest output count fits below 2^5.
	SignerDataEntryBits = 5
)

// SignerDataCounts is the statement's packed element over the opened run and output slots.
type SignerDataCounts struct {
	// Packed holds entry k at bits 5k up to 5k + 5.
	Packed frontend.Variable
	// Members is the run in the order its chain binds, the program deduplicates it.
	Members []frontend.Variable
	// Active[k] is set while entry k lies below the run's count.
	Active []frontend.Variable
	// Slots are the opened outputs. Open hashes their owner and data hash into the commitment, a
	// count over another owner or data hash needs another commitment than the one SPP publishes.
	Slots []shared.Output
}

// Assert mirrors SignerDataCounts in program-libs/interface/src/proof/statement.rs.
func (c SignerDataCounts) Assert(api frontend.API) {
	// 1. The decomposition range checks every entry to 5 bits and fails a value at or above 2^60,
	// so one packed value names one list of counts and a carry cannot move a count to its neighbor.
	bits := api.ToBinary(c.Packed, SignerDataEntries*SignerDataEntryBits)
	// 2. A slot counts as a live note with a nonzero data hash. A dummy and an ordinary payment read
	// zero here, so terms that carry payments never satisfy a count.
	bearing := make([]frontend.Variable, len(c.Slots))
	for o, slot := range c.Slots {
		bearing[o] = api.Mul(slot.Utxo, ringgadget.IsNonZero(api, slot.DataHash))
	}
	// 3. Each entry equals its signer's count, position by position in run order, a count moved to
	// another signer fails its own entry. An entry past the run reads zero. A CPI caller's PDAs can
	// sign past the transaction's signature limit. A member past the last entry has no bits to
	// publish a count, so it must own no data-bearing slot, the element would otherwise understate
	// what its signature authorizes.
	for entry := range max(SignerDataEntries, len(c.Members)) {
		published := frontend.Variable(0)
		if entry < SignerDataEntries {
			published = api.FromBinary(bits[entry*SignerDataEntryBits : (entry+1)*SignerDataEntryBits]...)
		}
		api.AssertIsEqual(published, c.count(api, entry, bearing))
	}
}

func (c SignerDataCounts) count(api frontend.API, entry int, bearing []frontend.Variable) frontend.Variable {
	if entry >= len(c.Members) {
		return 0
	}
	count := frontend.Variable(0)
	for o, slot := range c.Slots {
		count = api.Add(count, api.Mul(bearing[o], api.IsZero(api.Sub(slot.OwnerPkHash, c.Members[entry]))))
	}
	// The mask keeps an inactive entry at zero whatever a slot's owner opens to.
	return api.Mul(c.Active[entry], count)
}
