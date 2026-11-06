// Rebuilds each note's commitment exactly as the shielded pool does. Ring
// proofs tie to the pool's transfer through these commitments, so any
// difference breaks the link.
//
// The file proves the following.
//  1. Hash is SPP's commitment of the wires, a dummy's included.
//  2. Utxo is set on SPP's note domain alone, its owner field is Poseidon(OwnerPkHash, NullifierPk).
//  3. Ring and Exit split a note by its ring id, and SPP holds a nonzero ring id to the signing ring.
//  4. A slot OpenSlot reads is a note or a dummy, and a dummy carries nothing but its blinding.
//
// No ring slot opens an address. SPP chains its addresses apart from its notes, and the ring takes that
// chain as a private witness of private_tx_hash.
//
// Read after transfer/transfer.go. Read before audit/audit.go, audit/record.go, transfer/input.go.

package shared

import (
	"errors"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const InputBitmapBits = 64

// UtxoWires opens one transaction slot, its owner is Poseidon(OwnerPkHash, NullifierPk).
type UtxoWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

// Output is one slot's constrained opening, the wires its hash commits to beside the hash and the slot's class.
type Output struct {
	UtxoWires
	// Hash is the commitment SPP publishes or spends, a dummy's included.
	Hash frontend.Variable
	// Utxo is set on a note, Ring on a note of a ring and Exit on a note of the default ring, a dummy clears all three.
	Utxo, Ring, Exit frontend.Variable
}

// Open hashes the slot as SPP does and classifies it, so a ring proof binds the commitment SPP publishes or spends.
func (w UtxoWires) Open(api frontend.API) Output {
	utxo := api.IsZero(api.Sub(w.Domain, transaction.UtxoDomain))
	owner := api.Mul(utxo, gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk}))
	hash := transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         owner,
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	}, w.TreeID)
	// SPP holds every UTXO's ring id to 0 or the ring's on the same output hashes, AssertRingMemberOrFree in spp_transaction/shared/ring.go.
	ring := api.Mul(utxo, ringgadget.IsNonZero(api, w.RingProgramID))
	return Output{UtxoWires: w, Hash: hash, Utxo: utxo, Ring: ring, Exit: api.Sub(utxo, ring)}
}

// OpenSlot opens a note or a dummy, a dummy carries nothing but its blinding, as SPP's CheckDummy reads it.
func (w UtxoWires) OpenSlot(api frontend.API) Output {
	opened := w.Open(api)
	dummy := api.IsZero(api.Sub(w.Domain, transaction.DummyDomain))
	api.AssertIsEqual(api.Add(opened.Utxo, dummy), 1)
	// Open zeroes a dummy's owner hash before the hash reads it.
	transaction.AssertWhen(api, dummy, transaction.UtxoCircuitFields{
		Domain: w.Domain, Owner: 0, Asset: w.Asset, Amount: w.Amount, Blinding: w.Blinding,
		DataHash: w.DataHash, RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}.CheckDummy(api))
	return opened
}

// UtxoHashes is utxo * hash per slot, the output list private_tx_hash chains, zero on a dummy.
func UtxoHashes(api frontend.API, outputs []Output) []frontend.Variable {
	hashes := make([]frontend.Variable, len(outputs))
	for i, out := range outputs {
		hashes[i] = api.Mul(out.Utxo, out.Hash)
	}
	return hashes
}

func ValidateInputCapacity(capacity int) error {
	if capacity < 1 || capacity > InputBitmapBits {
		return errors.New("input capacity must fit the entry bitmap")
	}
	return nil
}
