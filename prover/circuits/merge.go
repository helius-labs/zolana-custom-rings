// Proves that a ring's SPP merge output opens to the ring's auditor.
//
// SPP's merge proof ties every input to one owner, one asset and the sum, and it seals nothing to an
// auditor. The ring proof adds one opening record of the output sealed to the ring's auditor key, and
// it opens no input, so one key serves every merge width. Without it the auditor holds no proven
// opening of a merged note.
//
// SPP derives the output blinding as TMOB(seed, n0). The seed is the owner's nullifier secret off the
// zero key, and a private merge seed under it, zolana/prover/server/circuits/spp_merge/ring.go. The
// record seals that seed. The auditor already holds a hidden owner's secret through enrollment, so the
// record gives it nothing new there, and a zero key's seed exists nowhere else for the auditor.
//
// The merge statement proves the following for one SPP merge output named by its hash and first nullifier.
//  1. The ciphertext is the output's opening record under the ring's auditor key, the auditor rebuilds
//     the published hash from the record, the first nullifier and the tree id and ring data hash SPP publishes.
//  2. A hidden owner's nullifier key is its enrolled row's under the tracking root and the public payer
//     is another account. A zero key reads no row, and the statement names that owner for SPP's signature.
//
// SPP's proof ties every input to that owner, asset and sum. No list, guard, cap or co-signer rule is proven.
//
// SPP's merge publishes no auditor message and no external data hash covers the record. The auditor
// reads the ciphertext from the ring instruction that called SPP in the confirmed transaction, and
// the statement alone binds those bytes.
//
// Read after shared/envelope.go, audit/record.go, registry/tracking.go. Read before ../ring/ring.go.

package circuits

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const MergeRecordLen = audit.OpeningRecordLen

// MergeCircuit binds a ring's SPP merge output to a record sealed to its auditor, SPP's proof ties every input to that owner, asset and sum.
type MergeCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OutputUtxoHash frontend.Variable
	FirstNullifier frontend.Variable
	RingProgramID  frontend.Variable
	AuditorPk      [32]frontend.Variable
	Payer          frontend.Variable
	TrackingRoot   frontend.Variable

	EphSk [32]frontend.Variable
	// The record's encoding binds OwnerPkHash to OwnerKey and Asset to MintChunks.
	OwnerKey    [32]frontend.Variable
	OwnerPkHash frontend.Variable
	MintChunks  [2]frontend.Variable
	Asset       frontend.Variable
	Amount      frontend.Variable
	NullifierPk frontend.Variable
	// The nullifier secret off ZeroNullifierPk, the private merge seed under it, SPP's proof holds it to the key.
	Seed               frontend.Variable
	OutputTreeID       frontend.Variable
	OutputRingDataHash frontend.Variable
	Tracking           registry.TrackingOpening
}

// No list, guard, cap or co-signer rule is proven, a merge keeps one owner's value in one asset.
func (c *MergeCircuit) Define(api frontend.API) error {
	zeroKey := api.IsZero(api.Sub(c.NullifierPk, shared.ZeroNullifierPk))
	hidden := api.Sub(1, zeroKey)
	// 1. A hidden owner cannot pay, the payer is public.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(api.Sub(c.OwnerPkHash, c.Payer))})
	// 2. A hidden owner's key is its row's, a zero key reads no row and its owner signs in SPP.
	row := c.Tracking.Resolve(api, hidden, c.TrackingRoot, c.OwnerPkHash)
	api.AssertIsEqual(row.Present, hidden)
	api.AssertIsEqual(row.NullifierPk, api.Mul(hidden, c.NullifierPk))

	// 3. The output is the SPP merge output, the program reads OutputUtxoHash from the SPP body it forwards and the auditor rebuilds it from the record.
	api.AssertIsEqual(c.OutputUtxoHash, transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHash, c.NullifierPk}),
		Asset: c.Asset, Amount: c.Amount, Blinding: mergeshared.MergeOutputBlinding(api, c.Seed, c.FirstNullifier),
		DataHash: 0, RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID))

	// 4. One encoding per record, a transfer's record followed by the seed, under the CRING/mrg label.
	plaintext := audit.OpeningRecord{RecordOpening: audit.RecordOpening{
		Live: 1, Kind: audit.KindRing, Amount: c.Amount, OwnerPkHash: c.OwnerPkHash, NullifierPk: c.NullifierPk, Asset: c.Asset,
		OwnerKey: c.OwnerKey, MintChunks: c.MintChunks,
	}, Secret: c.Seed}.Encode(api, rangecheck.New(api))
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.MergeEncInfo}.SealStream(api)

	// 5. The statement names the SPP merge, the ring, the record and the owner SPP makes sign, mirrored by MergePublicInput::elements in program-libs/interface/src/instructions/merge.rs.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, slices.Concat(
		[]frontend.Variable{shared.MergeStatementDomain, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID},
		sealed.StatementFields(api),
		[]frontend.Variable{c.Payer, api.Mul(zeroKey, c.OwnerPkHash), c.TrackingRoot},
	)))
	return nil
}
