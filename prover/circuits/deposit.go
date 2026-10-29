// Package circuits proves a ring deposit and an anonymous ring merge.
package circuits

import (
	"errors"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The first Count of 1..8 owner commitments open to (owner hash, blinding, owner key) AES-CTR encrypted to AuditorPk, the padding slots carry nothing.
// 2. Every blinding is Poseidon(CRDB, BlindingSecret), domain separated from every SPP output blinding.
// 3. An anonymous ring's deposit names the Ed25519 key behind each owner, any other deposit names none.
// 4. Under key escrow every owner's record lies under MemberRegistryRoot and escrows the key the owner's nullifier key and ciphertext hash name.
// 5. Under a nonzero PolicyHash every active asset rule of its table holds for each deposited asset on the lists its records under MemberRegistryRoot and CuratorRoot carry.

const (
	MaxDeposits = 8
	// DepositOpeningBytes is owner hash || blinding || owner key.
	DepositOpeningBytes = 96
)

// DepositCircuit binds every deposited owner commitment to an opening encrypted for the auditor.
type DepositCircuit struct {
	Capacity           int               `gnark:"-"`
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	OwnerPkHashes      []frontend.Variable
	OwnerKeys          [][32]frontend.Variable
	NullifierPks       []frontend.Variable
	BlindingSecrets    []frontend.Variable
	EphSk              [32]frontend.Variable
	AuditorPk          [32]frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	CtHashes           []frontend.Variable
	Members            []registry.QuadRecordOpening
	PolicyHash         frontend.Variable
	// Each asset is SPP's asset field of its deposit's group.
	Assets  []frontend.Variable
	Amounts []frontend.Variable
	policy.DepositAssets
}

var DepositCapacities = []int{1, 2, 4, 8}

func NewDepositCircuit(capacity int) (*DepositCircuit, error) {
	if err := shared.ValidateWidth("deposit", capacity, DepositCapacities); err != nil {
		return nil, err
	}
	return &DepositCircuit{
		Capacity: capacity, OwnerPkHashes: make([]frontend.Variable, capacity), OwnerKeys: make([][32]frontend.Variable, capacity), NullifierPks: make([]frontend.Variable, capacity), BlindingSecrets: make([]frontend.Variable, capacity), CtHashes: make([]frontend.Variable, capacity), Members: make([]registry.QuadRecordOpening, capacity),
		Assets: make([]frontend.Variable, capacity), Amounts: make([]frontend.Variable, capacity), DepositAssets: policy.NewDepositAssets(capacity),
	}, nil
}

func (c *DepositCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		shared.ValidateWidth("deposit", c.Capacity, DepositCapacities),
		shared.ValidateLength("deposit", "owner", len(c.OwnerPkHashes), c.Capacity),
		shared.ValidateLength("deposit", "owner key", len(c.OwnerKeys), c.Capacity),
		shared.ValidateLength("deposit", "nullifier key", len(c.NullifierPks), c.Capacity),
		shared.ValidateLength("deposit", "blinding secret", len(c.BlindingSecrets), c.Capacity),
		shared.ValidateLength("deposit", "ciphertext hash", len(c.CtHashes), c.Capacity),
		shared.ValidateLength("deposit", "member", len(c.Members), c.Capacity),
		shared.ValidateLength("deposit", "asset", len(c.Assets), c.Capacity),
		shared.ValidateLength("deposit", "amount", len(c.Amounts), c.Capacity),
		shared.ValidateLength("deposit", "asset record", len(c.AssetRecords), c.Capacity),
		shared.ValidateLength("deposit", "curator asset record", len(c.CuratorAssetRecords), c.Capacity),
	); err != nil {
		return err
	}
	// 1. Count selects 1..8 occupied slots, DepositPublicInput::hash builds both flags as 0 or 1.
	count := ringgadget.SelectCount(api, c.Count, 1, c.Capacity)
	rc := rangecheck.New(api)
	commitments := make([]frontend.Variable, c.Capacity)
	var plaintext []frontend.Variable
	deposits := make([]policy.DepositSlot, c.Capacity)
	for i := range commitments {
		active := count.Active[i]
		// 2. A padding slot carries no owner, key, blinding secret, asset or amount, the plaintext past Count stays fixed.
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.Assets[i], c.Amounts[i]} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: value})
		}
		// 3. Under escrow the owner's record exists and escrows Poseidon(nullifier_pk, ct_hash).
		escrowed := api.Mul(active, c.KeyEscrow)
		c.Members[i].AssertPresent(api, escrowed, c.MemberRegistryRoot, c.OwnerPkHashes[i])
		key := registry.EscrowKey(api, c.NullifierPks[i], c.CtHashes[i])
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: c.Members[i].EscrowKey, B: key})
		// 4. An anonymous slot's owner hash is its key's identity, the envelope bounds the key bytes, any other slot discloses no key.
		anonymous := api.Mul(c.Anonymous, active)
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: anonymous, A: c.OwnerPkHashes[i], B: gadget.SolanaOwnerIdentityBounded(api, c.OwnerKeys[i])})
		for _, b := range c.OwnerKeys[i] {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, anonymous), V: b})
		}
		// 5. The blinding is derived in the CRDB domain, the commitment is the deposited UTXO's owner part.
		owner := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		blinding := shared.DepositBlinding(api, c.BlindingSecrets[i])
		commitments[i] = gadget.PoseidonHash(api, []frontend.Variable{owner, blinding})
		// 6. The canonical field encodings keep one plaintext per opening.
		ownerBytes, blindingBytes := ringgadget.FieldToBytesBEWith(api, rc, owner), ringgadget.FieldToBytesBEWith(api, rc, blinding)
		plaintext = slices.Concat(plaintext, ownerBytes[:], blindingBytes[:], c.OwnerKeys[i][:])
		deposits[i] = policy.DepositSlot{Owner: c.OwnerPkHashes[i], Asset: c.Assets[i], Amount: c.Amounts[i], Active: active}
	}
	// 7. On a policy ring every deposited asset meets the asset rules under the bound roots.
	c.DepositAssets.Assert(api, rc, c.PolicyHash, c.MemberRegistryRoot, deposits)
	// 8. The statement binds each commitment SPP receives to the ciphertext the auditor opens, the cipher bounds its bytes.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.DepositEncInfo}.Seal(api)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.statement(api, count, commitments, sealed)))
	return nil
}

// statement mirrors DepositPublicInput::elements in program-libs/interface/src/instructions/deposit.rs.
func (c *DepositCircuit) statement(api frontend.API, count ringgadget.Count, commitments []frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	chain := []frontend.Variable{shared.DepositStatementDomain, c.ContextHash, c.Count, c.Anonymous}
	for i, commitment := range commitments {
		ciphertext := gadget.HashBoundedBytes(api, sealed.Ciphertext[i*DepositOpeningBytes:(i+1)*DepositOpeningBytes])
		chain = append(chain, api.Mul(count.Active[i], commitment), api.Mul(count.Active[i], ciphertext))
	}
	// The public statement keeps all eight pairs. Missing slots are constants.
	for i := len(commitments); i < MaxDeposits; i++ {
		chain = append(chain, 0, 0)
	}
	chain = slices.Concat(chain, sealed.Auditor, sealed.Eph, []frontend.Variable{c.KeyEscrow, c.MemberRegistryRoot, c.CuratorRoot, c.PolicyHash})
	for i := range MaxDeposits {
		if i < len(c.Assets) {
			chain = append(chain, c.Assets[i], c.Amounts[i])
		} else {
			chain = append(chain, 0, 0)
		}
	}
	return chain
}
