// Package ringmerge is the host twin of the ring merge circuit for the Go tests.
package ringmerge

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	realInputs   = 2
	InputTreeID  = 7
	outputTreeID = 9
)

type Statement struct {
	Keys    ringaudit.Keys
	Circuit *circuits.MergeCircuit
	// Registry holds the owner's escrow record on an escrowed merge, nil otherwise.
	Registry       *ringregistry.Registry
	CtHash         *big.Int
	ownerKey       [32]byte
	OwnerPkHash    *big.Int
	NullifierPk    *big.Int
	secret         *big.Int
	Mint           [32]byte
	Amounts        []*big.Int
	InputHashes    []*big.Int
	FirstNf        *big.Int
	OutputHash     *big.Int
	OutputBlinding *big.Int
	PrivateTxHash  *big.Int
	DisclosureKey  [32]byte
	// SPP output ciphertext salt, the disclosure pad reuses it.
	Salt      [16]byte
	Plaintext []byte
	// Masked disclosure chunks the ring instruction carries.
	Fields []*big.Int
}

// Build is a two-input merge padded to width slots under the default audit keys, on a ring without key escrow.
func Build(t testing.TB, width int) *Statement {
	t.Helper()
	return build(t, width, false)
}

// BuildEscrowed is Build on a key escrow ring, the owner's record escrows the nullifier key the merge spends under.
func BuildEscrowed(t testing.TB, width int) *Statement {
	t.Helper()
	return build(t, width, true)
}

func build(t testing.TB, width int, escrow bool) *Statement {
	t.Helper()
	s := &Statement{Keys: ringaudit.DefaultKeys(t), secret: big.NewInt(19), CtHash: big.NewInt(0)}
	for i := range s.Salt {
		s.Salt[i] = byte(0x50 + i)
	}
	for i := range s.Mint {
		s.Mint[i] = byte(0xc0 + i)
	}
	for i := range s.DisclosureKey {
		s.DisclosureKey[i] = byte(0x40 ^ i)
	}
	for i := range s.ownerKey {
		s.ownerKey[i] = byte(0xa0 + i)
	}
	c, err := circuits.NewMergeCircuit(width)
	if err != nil {
		t.Fatal(err)
	}
	s.Circuit = c
	s.OwnerPkHash = ringtest.MustSolanaPkField(t, s.ownerKey)
	s.NullifierPk = spptest.MustNullifierPk(t, s.secret)
	c.KeyEscrow, c.MemberRegistryRoot, c.CtHash, c.Member = 0, 0, 0, ringregistry.UnreadRecordWires()
	if escrow {
		s.Registry, s.CtHash = ringregistry.New(t), big.NewInt(0xc7)
		s.Registry.Apply(t, ringregistry.Entry{
			Member: s.OwnerPkHash, Mask: big.NewInt(ringregistry.EscrowBit), Value: big.NewInt(ringregistry.EscrowBit),
			EscrowKey: ringregistry.EscrowKey(t, s.NullifierPk, s.CtHash),
		})
		c.KeyEscrow, c.MemberRegistryRoot, c.CtHash = 1, s.Registry.Root(), s.CtHash
		c.Member = s.Registry.Opening(s.OwnerPkHash).RecordWires()
	}
	ownerHash := spptest.MustOwnerHash(t, s.OwnerPkHash, s.NullifierPk)
	asset := ringtest.AssetField(t, s.Mint)
	ringProgramID := big.NewInt(0x5a0e)
	ringData := big.NewInt(0xd0)

	s.Amounts = []*big.Int{big.NewInt(5), big.NewInt(7)}
	s.InputHashes = make([]*big.Int, width)
	for i := range width {
		s.InputHashes[i] = big.NewInt(0)
		c.Inputs[i] = circuits.MergeInput{Domain: protocol.DummyDomain, TreeID: 0, Amount: 0, Blinding: 0, RingDataHash: 0}
		if i >= realInputs {
			continue
		}
		blinding := big.NewInt(int64(0x1111 * (i + 1)))
		utxo := protocol.Utxo{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: ownerHash, Asset: asset, Amount: s.Amounts[i],
			Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: ringData, RingProgramID: ringProgramID,
		}
		s.InputHashes[i] = spptest.MustUtxoHash(t, utxo, big.NewInt(InputTreeID))
		c.Inputs[i] = circuits.MergeInput{Domain: protocol.UtxoDomain, TreeID: InputTreeID, Amount: s.Amounts[i], Blinding: blinding, RingDataHash: ringData}
		if i == 0 {
			s.FirstNf = spptest.MustNullifier(t, s.InputHashes[0], blinding, s.secret)
		}
	}
	sum := new(big.Int).Add(s.Amounts[0], s.Amounts[1])
	s.OutputBlinding = ringtest.MustPoseidonHash(t, big.NewInt(mergeshared.MergeOutputBlindingDomainV1), s.secret, s.FirstNf)
	s.OutputHash = spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: ownerHash, Asset: asset, Amount: sum, Blinding: s.OutputBlinding,
		DataHash: big.NewInt(0), RingDataHash: ringData, RingProgramID: ringProgramID,
	}, big.NewInt(outputTreeID))
	s.PrivateTxHash = s.PrivateTx(t, s.InputHashes)

	eph, auditor := s.Keys.EphSk(), s.Keys.AuditorPk()
	ringtest.SetBytes(c.OwnerKey[:], s.ownerKey[:])
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	ringtest.SetBytes(c.DisclosureKey[:], s.DisclosureKey[:])
	c.NullifierSecret = s.secret
	chunks := protocol.MintChunks(s.Mint)
	c.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	c.OutputTreeID = outputTreeID
	c.OutputRingDataHash = ringData
	c.RingProgramID = ringProgramID
	c.Salt = s.saltField()
	c.PrivateTxHash = s.PrivateTxHash
	c.OutputUtxoHash = s.OutputHash
	c.FirstNullifier = s.FirstNf
	c.PartyIdentities = [3]frontend.Variable{11, 12, 0}
	s.bind(t)
	return s
}

// PrivateTx binds no address nullifier, as SPP's merge spends none.
func (s *Statement) PrivateTx(t testing.TB, inputHashes []*big.Int) *big.Int {
	t.Helper()
	addresses := make([]*big.Int, len(inputHashes))
	for i := range addresses {
		addresses[i] = big.NewInt(0)
	}
	blinding, err := protocol.PrivateTxBlinding(s.FirstNf, s.secret)
	return spptest.MustPrivateTxHash(t, inputHashes, []*big.Int{s.OutputHash}, addresses, spptest.MustHash(t, blinding, err))
}

func (s *Statement) bind(t testing.TB) {
	t.Helper()
	nullifierPk, outputBlinding := spptest.MustFieldBytes(t, s.NullifierPk), spptest.MustFieldBytes(t, s.OutputBlinding)
	var amount [8]byte
	new(big.Int).Add(s.Amounts[0], s.Amounts[1]).FillBytes(amount[:])
	plaintext := slices.Concat(s.ownerKey[:], nullifierPk[:], s.Mint[:], amount[:], outputBlinding[:])
	for _, hash := range s.InputHashes {
		hashBytes := spptest.MustFieldBytes(t, hash)
		plaintext = append(plaintext, hashBytes[:]...)
	}
	if want := disclosureBytes(len(s.Circuit.Inputs)); len(plaintext) != want {
		t.Fatalf("plaintext %d bytes, want %d", len(plaintext), want)
	}
	s.Plaintext = plaintext
	s.Fields = ringprotocol.Disclose(t, shared.MergeDisclosureDomain, s.DisclosureKey, s.Salt, ringprotocol.PackDisclosure(plaintext))
	s.Rebind(t)
}

// saltField is the salt right aligned in one field, as SPP binds it.
func (s *Statement) saltField() *big.Int {
	return new(big.Int).SetBytes(s.Salt[:])
}

// Elements mirrors MergePublicInput::elements.
func (s *Statement) Elements(t testing.TB) []*big.Int {
	t.Helper()
	sealed := s.Keys.Seal(t, s.DisclosureKey[:], shared.MergeEncInfo)
	return []*big.Int{
		big.NewInt(shared.MergeStatementDomain), s.PrivateTxHash, s.OutputHash, s.FirstNf, ringtest.AsBigInt(s.Circuit.RingProgramID),
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash, s.saltField(), spptest.MustHashChain4(t, s.Fields),
		ringtest.AsBigInt(s.Circuit.PartyIdentities[0]), ringtest.AsBigInt(s.Circuit.PartyIdentities[1]), ringtest.AsBigInt(s.Circuit.PartyIdentities[2]),
		ringtest.AsBigInt(s.Circuit.KeyEscrow), ringtest.AsBigInt(s.Circuit.MemberRegistryRoot),
	}
}

// Rebind rehashes the statement over the host values as set, Fields included.
func (s *Statement) Rebind(t testing.TB) {
	t.Helper()
	s.Circuit.PublicInputHash = spptest.MustHashChain(t, s.Elements(t))
}

// disclosureBytes mirrors merge_disclosure_len in program-libs/interface/src/instructions/merge.rs.
func disclosureBytes(inputs int) int {
	return 32 + 32 + 32 + 8 + 32 + 32*inputs
}
