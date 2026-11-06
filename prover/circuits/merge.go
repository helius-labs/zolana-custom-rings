// Proves that a ring's SPP merge output opens to the ring's auditor.
//
// SPP's merge proof ties every input to one owner, one asset and the sum, and it seals nothing to an
// auditor. The ring proof adds the transfer's output record of the merged note, followed by the merge
// seed, sealed to the owner's viewing key from a fresh ephemeral key. An envelope seals that ephemeral
// key and the viewing key to the ring's auditor. It opens no input, so one key serves every merge width.
// Without it the auditor holds no proven opening of a merged note.
//
// SPP derives the output blinding as TMOB(seed, n0). The seed is the owner's nullifier secret off the
// zero key, and a private merge seed under it, zolana/prover/server/circuits/spp_merge/ring.go. The
// record seals that seed. The auditor already holds a hidden owner's secret through enrollment, so the
// record gives it nothing new there, and a zero key's seed exists nowhere else for the auditor.
//
// The merge statement proves the following for one SPP merge output named by its hash and first nullifier.
//  1. The envelope seals eph_sk and the recipient key to the ring's auditor key, and the record is the
//     output's record and seed under the slot secret of eph_sk and that recipient key. The auditor rebuilds
//     the published hash from the record and the tree id and ring data hash SPP publishes.
//  2. A hidden owner's nullifier key is its enrolled row's under the tracking root. A zero key reads no
//     row, and the statement names that owner for SPP's signature. The payer may be the hidden owner, a
//     wallet that pays from its own account names itself to every chain reader.
//
// SPP's proof ties every input to that owner, asset and sum. No list, guard, cap or co-signer rule is proven.
//
// SPP's merge publishes no auditor message and no external data hash covers the record. The auditor
// reads both ciphertexts from the ring instruction that called SPP in the confirmed transaction, and
// the statement alone binds those bytes. The record's label CRING/mro keeps a merge record apart from a
// transfer record under one key pair.
//
// Read after shared/envelope.go, audit/record.go, registry/tracking.go. Read before ../ring/ring.go.

package circuits

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const (
	MergeRecordLen = audit.MergeRecordLen
	// MergeEnvelopeLen mirrors MERGE_ENVELOPE_LEN.
	MergeEnvelopeLen = audit.EnvelopeKeyLen + audit.KeyLen
)

// MergeCircuit binds a ring's SPP merge output to a record its owner and its auditor open, SPP's proof ties every input to that owner, asset and sum.
type MergeCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OutputUtxoHash frontend.Variable
	FirstNullifier frontend.Variable
	RingProgramID  frontend.Variable
	AuditorPk      [32]frontend.Variable
	Payer          frontend.Variable
	TrackingRoot   frontend.Variable

	EphSk [32]frontend.Variable
	// RecipientKey is the merged owner's viewing u, the envelope seals it for the auditor.
	RecipientKey [32]frontend.Variable
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
	// 1. A hidden owner's key is its row's, a zero key reads no row and its owner signs in SPP.
	row := c.Tracking.Resolve(api, hidden, c.TrackingRoot, c.OwnerPkHash)
	api.AssertIsEqual(row.Present, hidden)
	api.AssertIsEqual(row.NullifierPk, api.Mul(hidden, c.NullifierPk))

	// 2. The output is the SPP merge output, the program reads OutputUtxoHash from the SPP body it forwards and the auditor rebuilds it from the record.
	blinding := mergeshared.MergeOutputBlinding(api, c.Seed, c.FirstNullifier)
	api.AssertIsEqual(c.OutputUtxoHash, transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHash, c.NullifierPk}),
		Asset: c.Asset, Amount: c.Amount, Blinding: blinding,
		DataHash: 0, RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID))

	// 3. The envelope gives the auditor eph_sk and the recipient key, the record then opens as a transfer record does.
	envelope := shared.Envelope{Plaintext: slices.Concat(c.EphSk[:], c.RecipientKey[:]), EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.MergeEncInfo}.SealStream(api)
	rc := rangecheck.New(api)
	plaintext := audit.MergeRecord{RecordOpening: audit.RecordOpening{
		Live: 1, Kind: audit.KindRing, Amount: c.Amount, OwnerPkHash: c.OwnerPkHash, NullifierPk: c.NullifierPk, Asset: c.Asset, Blinding: blinding,
		OwnerKey: c.OwnerKey, MintChunks: c.MintChunks,
	}, Seed: c.Seed}.Encode(api, rc)
	// A zero salt and index leave the first nullifier to part two merges of one key pair.
	record := shared.SlotSeal{
		Plaintext: plaintext, EphSk: c.EphSk, Eph: envelope.Eph,
		RecipientPk: c.RecipientKey, Salt: 0, Index: 0, FirstNullifier: c.FirstNullifier, Info: shared.MergeOutputInfo,
	}.Seal(api)

	// 4. The statement names the SPP merge, the ring, both ciphertexts and the owner SPP makes sign, mirrored by MergePublicInput::elements in program-libs/interface/src/instructions/merge.rs.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, slices.Concat(
		[]frontend.Variable{shared.MergeStatementDomain, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID},
		envelope.StatementFields(api),
		[]frontend.Variable{gadget.HashBoundedBytes(api, record), c.Payer, api.Mul(zeroKey, c.OwnerPkHash), c.TrackingRoot},
	)))
	return nil
}
