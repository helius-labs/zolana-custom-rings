// Package ringmerge is the host twin of the ring merge circuit for the Go tests.
package ringmerge

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	OutputTreeID = 9
	secret       = 19
	zeroKeySeed  = 0x5eed
	amount       = 12
)

// RingProgramID is the ring the fixture merge settles under.
var RingProgramID = big.NewInt(0x5a0e)

// FirstNullifier names the SPP merge, the ring proof opens no input.
var FirstNullifier = big.NewInt(0x1f1f)

// RingData is the output ring data hash SPP publishes.
var RingData = big.NewInt(0xd0)

// Payer is an identity no owner of the fixture holds.
var Payer = big.NewInt(11)

type Statement struct {
	Keys           ringaudit.Keys
	Circuit        *circuits.MergeCircuit
	OwnerKey       [32]byte
	OwnerPkHash    *big.Int
	NullifierPk    *big.Int
	Seed           *big.Int
	Mint           [32]byte
	Amount         *big.Int
	OutputHash     *big.Int
	OutputBlinding *big.Int
	// Tracking holds the owner's row, nil under a zero key.
	Tracking *ringregistry.Tracking
	Record   []byte
	// PublishedOwner is what the program reads from the SPP body.
	PublishedOwner *big.Int
}

// Build merges under an enrolled nonzero key, the seed is the nullifier secret.
func Build(t testing.TB) *Statement {
	t.Helper()
	s := build(t, big.NewInt(secret), spptest.MustNullifierPk(t, big.NewInt(secret)))
	s.Tracking = ringregistry.NewTracking(t)
	s.Tracking.Apply(t, s.TrackingEntry(s.OwnerPkHash, s.NullifierPk))
	s.Circuit.Tracking = s.Tracking.Opening(s.OwnerPkHash).Wires()
	s.Circuit.TrackingRoot = s.Tracking.Root()
	s.Rebind(t)
	return s
}

// TrackingEntry enrolls member under nullifierPk.
func (s *Statement) TrackingEntry(member, nullifierPk *big.Int) ringregistry.TrackingEntry {
	return ringregistry.TrackingEntry{Member: member, NullifierPk: nullifierPk, CtHash: big.NewInt(0xc7), ListTag: big.NewInt(0xb7)}
}

// BuildZeroKey merges under ZeroNullifierPk with a private seed, the owner is published and no row is read.
func BuildZeroKey(t testing.TB) *Statement {
	t.Helper()
	s := build(t, big.NewInt(zeroKeySeed), new(big.Int).Set(shared.ZeroNullifierPk))
	s.PublishedOwner = s.OwnerPkHash
	s.Circuit.TrackingRoot = 0
	s.Circuit.Tracking = UnreadTracking()
	s.Rebind(t)
	return s
}

// UnreadTracking is the all zero opening a zero key carries.
func UnreadTracking() registry.TrackingOpening {
	zero := big.NewInt(0)
	return ringregistry.TrackingOpening{
		Record: ringregistry.TrackingRecord{Member: zero, Next: zero, NullifierPk: zero, CtHash: zero, ListTag: zero},
		Path:   ringregistry.ZeroTrackingWrite().Slot,
	}.Wires()
}

func build(t testing.TB, seed, nullifierPk *big.Int) *Statement {
	t.Helper()
	s := &Statement{Keys: ringaudit.DefaultKeys(t), Seed: seed, NullifierPk: nullifierPk, Amount: big.NewInt(amount), PublishedOwner: big.NewInt(0)}
	for i := range s.Mint {
		s.Mint[i] = byte(0xc0 + i)
		s.OwnerKey[i] = byte(0xa0 + i)
	}
	s.OwnerPkHash = ringtest.MustSolanaPkField(t, s.OwnerKey)
	s.OutputBlinding = ringtest.MustPoseidonHash(t, big.NewInt(mergeshared.MergeOutputBlindingDomainV1), seed, FirstNullifier)
	s.OutputHash = s.outputHash(t, s.OutputBlinding)

	c := &circuits.MergeCircuit{}
	eph, auditor := s.Keys.EphSk(), s.Keys.AuditorPk()
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	ringtest.SetBytes(c.OwnerKey[:], s.OwnerKey[:])
	c.OwnerPkHash, c.Asset = s.OwnerPkHash, ringtest.AssetField(t, s.Mint)
	c.MintChunks = [2]frontend.Variable{new(big.Int).SetBytes(s.Mint[:31]), new(big.Int).SetBytes(s.Mint[31:])}
	c.Amount, c.NullifierPk, c.Seed = s.Amount, nullifierPk, seed
	c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID, c.Payer = s.OutputHash, FirstNullifier, RingProgramID, Payer
	c.OutputTreeID, c.OutputRingDataHash = OutputTreeID, RingData
	s.Circuit = c
	s.Record = s.PlainRecord(t)
	return s
}

func (s *Statement) outputHash(t testing.TB, blinding *big.Int) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: spptest.MustOwnerHash(t, s.OwnerPkHash, s.NullifierPk), Asset: ringtest.AssetField(t, s.Mint), Amount: s.Amount,
		Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: RingData, RingProgramID: RingProgramID,
	}, big.NewInt(OutputTreeID))
}

// PlainRecord mirrors OpeningRecord::encode.
func (s *Statement) PlainRecord(t testing.TB) []byte {
	t.Helper()
	record := make([]byte, 9, circuits.MergeRecordLen)
	record[0] = 1
	binary.BigEndian.PutUint64(record[1:], s.Amount.Uint64())
	record = append(append(record, s.OwnerKey[:]...), s.Mint[:]...)
	nullifierPk, seed := spptest.MustFieldBytes(t, s.NullifierPk), spptest.MustFieldBytes(t, s.Seed)
	record = append(append(record, nullifierPk[:]...), make([]byte, audit.RecordStride-audit.RecordLen)...)
	return append(record, seed[:]...)
}

// Ciphertext is the record under the one-time envelope, the auditor reverses it.
func (s *Statement) Ciphertext(t testing.TB) []byte {
	t.Helper()
	return s.Keys.StreamCiphertext(t, s.Record, shared.MergeEncInfo)
}

// Elements mirrors MergePublicInput::elements.
func (s *Statement) Elements(t testing.TB) []*big.Int {
	t.Helper()
	sealed := s.Keys.Sealed(t, s.Ciphertext(t))
	return []*big.Int{
		big.NewInt(shared.MergeStatementDomain), ringtest.AsBigInt(s.Circuit.OutputUtxoHash), ringtest.AsBigInt(s.Circuit.FirstNullifier), ringtest.AsBigInt(s.Circuit.RingProgramID),
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
		ringtest.AsBigInt(s.Circuit.Payer), s.PublishedOwner, ringtest.AsBigInt(s.Circuit.TrackingRoot),
	}
}

// Rebind rehashes the statement over the host values as set.
func (s *Statement) Rebind(t testing.TB) {
	t.Helper()
	s.Circuit.PublicInputHash = spptest.MustHashChain(t, s.Elements(t))
}

// Opened is what the auditor reads, and all it needs beside the published merge.
type Opened struct {
	Plain       []byte
	OwnerKey    [32]byte
	Mint        [32]byte
	Amount      uint64
	NullifierPk *big.Int
	Seed        *big.Int
}

// Open reverses the envelope's stream, CTR is its own inverse.
func Open(t testing.TB, s *Statement) Opened {
	t.Helper()
	plain := s.Keys.StreamCiphertext(t, s.Ciphertext(t), shared.MergeEncInfo)
	return Opened{
		Plain:       plain,
		Amount:      binary.BigEndian.Uint64(plain[1:9]),
		OwnerKey:    [32]byte(plain[9:41]),
		Mint:        [32]byte(plain[41:73]),
		NullifierPk: new(big.Int).SetBytes(plain[73:audit.RecordLen]),
		Seed:        new(big.Int).SetBytes(plain[audit.RecordStride:circuits.MergeRecordLen]),
	}
}

// Hash rebuilds the output from the record and what SPP publishes.
func (o Opened) Hash(t testing.TB) *big.Int {
	t.Helper()
	blinding := ringtest.MustPoseidonHash(t, big.NewInt(mergeshared.MergeOutputBlindingDomainV1), o.Seed, FirstNullifier)
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: spptest.MustOwnerHash(t, ringtest.MustSolanaPkField(t, o.OwnerKey), o.NullifierPk), Asset: ringtest.AssetField(t, o.Mint), Amount: new(big.Int).SetUint64(o.Amount),
		Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: RingData, RingProgramID: RingProgramID,
	}, big.NewInt(OutputTreeID))
}
