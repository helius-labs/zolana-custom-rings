package ring

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestMergeCatalogShipsSppWidths(t *testing.T) {
	for _, width := range circuits.MergeWidths {
		if !slices.Contains(mergeshared.SupportedInputCounts, width) {
			t.Fatalf("ring merge width %d, SPP merges %v", width, mergeshared.SupportedInputCounts)
		}
		key := keyOf(t, Key{Family: Merge, Inputs: width}.circuitType())
		if common.KeyFileCircuit(key.KeyFile()) != key.Circuit {
			t.Fatalf("%s does not round trip through its key file", key.Circuit)
		}
	}
	for _, kind := range []common.CircuitType{"custom-ring-merge-v3-9", "custom-ring-merge-v3-52", "custom-ring-merge-anonymous-v2-8"} {
		if kind.IsExtension() {
			t.Fatalf("%s is registered", kind)
		}
	}
}

// Rust and TypeScript pin the same file.
const mergeVectorPath = "../../test-vectors/merge/ring-merge.json"

const mergeVectorDescription = "Known-answer vector for the ring merge disclosure and statement, width 8, under key escrow. " +
	"plaintext = owner_key(32) || nullifier_pk(32) || mint(32) || amount u64 big-endian || output_blinding(32) || input_commitments(8 x 32), " +
	"zero padded to 31-byte chunks, chunk i a big-endian field. seed = Poseidon(0x4352_5f4d44, key_lo, key_hi, salt_field) with key_lo and key_hi " +
	"PackBytesBE(disclosure_key) and salt_field the 16 salt bytes right aligned, fields[i] = (chunk[i] + Poseidon(seed, i)) mod r. " +
	"envelope_ciphertext seals disclosure_key from eph to auditor under info CRING/mrg1 as the base Envelope does. " +
	"elements = CRMG, private_tx_hash, output_utxo_hash, first_nullifier, ring_program_id, auditor lo, hi, eph lo, hi, " +
	"hash_bytes(envelope_ciphertext), salt_field, hash_chain_4(fields), the three party identities, key_escrow, member_registry_root, " +
	"public_input_hash = hash_chain(elements). Under key_escrow the owner's record under member_registry_root escrows Poseidon(nullifier_pk, ct_hash). " +
	"request is the prover body. Produced by prover/ring/merge_test.go with WRITE_AUDIT_VECTORS=1."

type mergeVector struct {
	Description        string       `json:"description"`
	Width              int          `json:"width"`
	AuditorSk          Bytes        `json:"auditor_sk"`
	AuditorPk          Bytes        `json:"auditor_pk"`
	EphPk              Bytes        `json:"eph_pk"`
	Salt               Bytes        `json:"salt"`
	Mint               Bytes        `json:"mint"`
	NullifierPk        Field        `json:"nullifier_pk"`
	Amount             uint64       `json:"amount"`
	OutputBlinding     Field        `json:"output_blinding"`
	InputCommitments   []Field      `json:"input_commitments"`
	Plaintext          Bytes        `json:"plaintext"`
	Fields             []Field      `json:"fields"`
	EnvelopeCiphertext Bytes        `json:"envelope_ciphertext"`
	Elements           []Field      `json:"elements"`
	PublicInputHash    Field        `json:"public_input_hash"`
	Request            *MergeParams `json:"request"`
}

func TestMergeVectorPinsHostAndCircuit(t *testing.T) {
	s := ringmerge.BuildEscrowed(t, 8)
	auditorSk := ringaudit.AuditorSk()
	auditorU := s.Keys.AuditorPk()
	auditorPk := ringprotocol.Tagged(auditorU[:])
	ephPk := s.Keys.EphPk()
	want := mergeVector{
		Description:        mergeVectorDescription,
		Width:              8,
		AuditorSk:          auditorSk[:],
		AuditorPk:          auditorPk[:],
		EphPk:              ephPk[:],
		Salt:               s.Salt[:],
		Mint:               s.Mint[:],
		NullifierPk:        Field{s.NullifierPk},
		Amount:             new(big.Int).Add(s.Amounts[0], s.Amounts[1]).Uint64(),
		OutputBlinding:     Field{s.OutputBlinding},
		InputCommitments:   fieldsOf(s.InputHashes),
		Plaintext:          s.Plaintext,
		Fields:             fieldsOf(s.Fields),
		EnvelopeCiphertext: s.Keys.EnvelopeCiphertext(t, s.DisclosureKey[:], shared.MergeEncInfo),
		Elements:           fieldsOf(s.Elements(t)),
		PublicInputHash:    Field{ringtest.AsBigInt(s.Circuit.PublicInputHash)},
		Request:            requestOf[MergeParams](t, mergeKey, s.Circuit),
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("WRITE_AUDIT_VECTORS") != "" {
		if err := os.WriteFile(mergeVectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(mergeVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(encoded) {
		t.Fatal("the host mirror disagrees with test-vectors/merge/ring-merge.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}
	var pinned mergeVector
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatal(err)
	}
	if _, err := solvedWitness(t, mergeKey, mustMarshal(t, pinned.Request)); err != nil {
		t.Fatal(err)
	}
}
