package ring

import (
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const (
	transferKey  common.CircuitType = "custom-ring-transfer-2-in24-w4-s4"
	transfer4Key common.CircuitType = "custom-ring-transfer-4-in24-w4-s4"
	transfer8Key common.CircuitType = "custom-ring-transfer-8-in16-w4-s4"
	wideKey      common.CircuitType = "custom-ring-transfer-wide-8-in24-w32-s13"
	wide40Key    common.CircuitType = "custom-ring-transfer-wide-2-in40-w4-s8"
	entryKey     common.CircuitType = "custom-ring-transfer-entry-4-in8-w4-s8"
	entryWideKey common.CircuitType = "custom-ring-transfer-entry-8-in8-w32-s8"
	entry8Key    common.CircuitType = "custom-ring-transfer-entry-8-in2-w4-s2"
	applyKey     common.CircuitType = "custom-ring-apply-records-1"
	batchKey     common.CircuitType = "custom-ring-apply-records-16"
	privateKey   common.CircuitType = "custom-ring-apply-records-private-1"
	enrollKey    common.CircuitType = "custom-ring-apply-enrollments-2"
	registerKey  common.CircuitType = "custom-ring-register-key"
	mergeKey     common.CircuitType = "custom-ring-merge"
)

func TestHostRequestsDecodeAndSolve(t *testing.T) {
	for _, circuit := range []common.CircuitType{transferKey, transfer4Key, transfer8Key, wideKey, wide40Key, entryKey, entry8Key, entryWideKey, applyKey, batchKey, privateKey, enrollKey, registerKey, mergeKey} {
		t.Run(string(circuit), func(t *testing.T) {
			payload := mustMarshal(t, hostRequest(t, keyOf(t, circuit)))
			circuitOf := extensionOf(t, circuit).Circuit
			if err := test.IsSolved(circuitOf(), decodePayload(t, circuit, payload), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			raw["publicInputHash"] = fi(1)
			if test.IsSolved(circuitOf(), decodePayload(t, circuit, mustMarshal(t, raw)), ecc.BN254.ScalarField()) == nil {
				t.Fatal("another public input solved")
			}
		})
	}
}

// Each apply family decodes only its own body, a request names its family by its fields.
func TestApplyRequestsDecodeOnlyUnderTheirMode(t *testing.T) {
	public := applyRequest(t, privateKey, 1)
	if _, err := decode(privateKey, mustMarshal(t, public)); err == nil {
		t.Fatal("a private key decoded a body without private fields")
	}
	private := requestOf[PrivateApplyRecordsParams](t, applyKey, ringregistry.PrivateBatch(t, 1, ringregistry.PrivateBlockBit))
	if _, err := decode(applyKey, mustMarshal(t, private)); err == nil {
		t.Fatal("a public key decoded a body with private fields")
	}
}

func hostRequest(t testing.TB, k Key) any {
	t.Helper()
	switch k.Family {
	case Transfer:
		w := ringtransfer.Signed(k.transferShape())
		w.Withdrawals, w.Public = fixtureLeg(t)
		w.DefaultInput = k.Entry
		return requestOf[TransferParams](t, k.Circuit, w.Build(t).Circuit)
	case ApplyRecords:
		if k.Private {
			return requestOf[PrivateApplyRecordsParams](t, k.Circuit, ringregistry.PrivateBatch(t, k.Inputs, ringregistry.PrivateBlockBit))
		}
		return applyRequest(t, k.Circuit, k.Inputs)
	case ApplyEnrollments:
		return enrollmentsRequest(t, k.Circuit, k.Inputs)
	case RegisterKey:
		return registerKeyRequest(t, k.Circuit, big.NewInt(0x0b))
	case Merge:
		return requestOf[MergeParams](t, k.Circuit, ringmerge.Build(t).Circuit)
	}
	t.Fatalf("no host request for ring family %d", k.Family)
	return nil
}

// fixtureLeg withdraws one leg of the fixture asset, so every transfer request carries a withdrawal.
func fixtureLeg(t testing.TB) ([]ringtransfer.Withdrawal, []ringtransfer.PublicSlot) {
	t.Helper()
	asset := ringtransfer.Asset(t)
	return []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: asset, Amount: 10}}, []ringtransfer.PublicSlot{{Asset: asset, Net: -10, Gross: 10}}
}

func keyOf(t testing.TB, circuit common.CircuitType) Key {
	t.Helper()
	for _, key := range Keys {
		if key.Circuit == circuit {
			return key
		}
	}
	t.Fatalf("%s is no catalog key", circuit)
	return Key{}
}

// applyRequest inserts members up to the key's capacity, a full batch then rewrites one of them and skips an empty record.
func applyRequest(t testing.TB, circuit common.CircuitType, capacity int) *ApplyRecordsParams {
	t.Helper()
	entry := func(member, mask int64) ringregistry.Entry {
		return ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(mask)}
	}
	entries := []ringregistry.Entry{entry(0x100, ringregistry.AllowBit)}
	if capacity > 1 {
		entries = nil
		for i := range capacity - 2 {
			entries = append(entries, entry(int64(0x100+i), ringregistry.AllowBit))
		}
		empty := ringregistry.Entry{Member: big.NewInt(0x200), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(0)}
		entries = append(entries, entry(0x100, ringregistry.BlockBit), empty)
	}
	// A nonzero chain start, as `chain_start` derives from the registry and revision.
	request, _ := (registryBatch{circuit, capacity, ringregistry.New(t), entries, big.NewInt(0x5eed)}).request(t)
	return request
}

type registryBatch struct {
	circuit    common.CircuitType
	capacity   int
	members    *ringregistry.Registry
	entries    []ringregistry.Entry
	chainStart *big.Int
}

// request also returns the restrictive bit its statement binds.
func (batch registryBatch) request(t testing.TB) (*ApplyRecordsParams, bool) {
	t.Helper()
	members, entries := batch.members, batch.entries
	p := &ApplyRecordsParams{
		RequestHead: RequestHead{CircuitType: batch.circuit}, OldRoot: fb(members.Root()), OldNextIndex: uint32(members.NextIndex()),
		ChainStart: fb(batch.chainStart), Count: uint8(len(entries)), Writes: make([]*RecordWriteProofInput, batch.capacity),
	}
	chain := p.ChainStart.Int
	wires := make([]registry.RecordWriteProofInput, len(entries))
	for i, e := range entries {
		wires[i] = members.Apply(t, e).Wires()
		chain = ringtest.MustPoseidonHash(t, chain, e.Hash(t))
		p.Writes[i] = requestValue[RecordWriteProofInput](t, wires[i])
	}
	p.NewRoot, p.NewNextIndex, p.ChainEnd = fb(members.Root()), uint32(members.NextIndex()), fb(chain)
	fields := []*big.Int{
		big.NewInt(shared.ApplyRecordsDomain), p.OldRoot.Int, p.NewRoot.Int, big.NewInt(int64(p.OldNextIndex)),
		big.NewInt(int64(p.NewNextIndex)), p.ChainStart.Int, p.ChainEnd.Int, big.NewInt(int64(p.Count)),
		big.NewInt(ringregistry.Restrictive(wires, len(wires))),
	}
	p.PublicInputHash = fb(spptest.MustHashChain4(t, fields))
	return p, fields[len(fields)-1].Sign() != 0
}

// enrollmentsRequest inserts one owner per slot.
func enrollmentsRequest(t testing.TB, circuit common.CircuitType, capacity int) *ApplyEnrollmentsParams {
	t.Helper()
	tree := ringregistry.NewTracking(t)
	entry := func(i int) ringregistry.TrackingEntry {
		owner := big.NewInt(0x100 + int64(i))
		return ringregistry.TrackingEntry{Member: owner, NullifierPk: spptest.MustNullifierPk(t, owner), CtHash: big.NewInt(0xc0), ListTag: big.NewInt(0xd0)}
	}
	assignment, err := registry.NewApplyEnrollmentsCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	assignment.OldRoot, assignment.OldNextIndex, assignment.ChainStart = tree.Root(), tree.NextIndex(), big.NewInt(0x5eed)
	chain := big.NewInt(0x5eed)
	for i := range assignment.Writes {
		e := entry(i)
		assignment.Writes[i] = tree.Apply(t, e).Wires()
		chain = ringtest.MustPoseidonHash(t, chain, e.Hash(t))
	}
	assignment.NewRoot, assignment.NewNextIndex, assignment.ChainEnd, assignment.Count = tree.Root(), tree.NextIndex(), chain, capacity
	assignment.PublicInputHash = spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(shared.ApplyEnrollmentsDomain), ringtest.AsBigInt(assignment.OldRoot), ringtest.AsBigInt(assignment.NewRoot),
		ringtest.AsBigInt(assignment.OldNextIndex), ringtest.AsBigInt(assignment.NewNextIndex), ringtest.AsBigInt(assignment.ChainStart), chain, big.NewInt(int64(capacity)),
	})
	return requestOf[ApplyEnrollmentsParams](t, circuit, assignment)
}

func flatPath(path ringregistry.Path) []Field {
	var flat []Field
	for _, row := range path.Siblings {
		for _, sibling := range row {
			flat = append(flat, fb(sibling))
		}
	}
	return flat
}

func registerKeyRequest(t testing.TB, circuit common.CircuitType, member *big.Int) *RegisterKeyParams {
	t.Helper()
	keys := ringaudit.DefaultKeys(t)
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	salt := ringtest.Scalar(0x09)
	salt[0] = 0
	sealed := keys.SealStream(t, slices.Concat(secret[:], salt[:]), shared.NfKeyEncInfo)
	secretField := new(big.Int).SetBytes(secret[1:])
	nullifierPk := spptest.MustNullifierPk(t, secretField)
	ringID := big.NewInt(0x7711)
	listTag := ringregistry.ListTag(t, new(big.Int).SetBytes(salt[1:]))
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	return &RegisterKeyParams{
		RequestHead: RequestHead{
			CircuitType: circuit,
			PublicInputHash: fb(spptest.MustHashChain4(t, []*big.Int{
				big.NewInt(shared.RegisterKeyDomain), ringID, member, nullifierPk, listTag,
				sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
			})),
		},
		RingID: fb(ringID), Member: fb(member), NullifierSecret: secret[:], ListSalt: salt[:], EphSk: eph[:], AuditorPk: auditor[:],
	}
}

func fi(v int64) Field    { return Field{big.NewInt(v)} }
func fb(v *big.Int) Field { return Field{new(big.Int).Set(v)} }

// fz reads nil as zero, ringregistry leaves unset settings nil.
func fz(v *big.Int) Field {
	if v == nil {
		return fi(0)
	}
	return fb(v)
}

func limitFields(limits ringregistry.Limits) []Field {
	fields := make([]Field, len(limits))
	for i, limit := range limits {
		fields[i] = fz(limit)
	}
	return fields
}

func fieldsOf(values []*big.Int) []Field {
	out := make([]Field, len(values))
	for i, value := range values {
		out[i] = fb(value)
	}
	return out
}
