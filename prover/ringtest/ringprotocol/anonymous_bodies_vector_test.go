package ringprotocol

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

const anonymousBodiesDescription = "One ring body and one sender bundle of an honest 4 slot frame, change in slot 0, payments in slots 1 and 3, an exit in slot 2. " +
	"Body plaintext be32(blinding) || u64be(amount) || mint under label CRING/rcp and the CRDS slot secret of recipient_key and index. " +
	"Bundle plaintext output_seed || (mint || u64be(amount)) per bodiless slot || recipient_u per body-bearing slot under label CRING/snd and the CRDS slot secret of sender_viewing_key and index m, recipient_u zero on exit. " +
	"bundle_digest = ciphertext_digest(bundle). body_tag = Poseidon(CRRT, body_slot_secret), bundle_tag = Poseidon(CRST, bundle_slot_secret), dummy_tag = Poseidon(CRRT, dummy_tag_preimage). " +
	"body, bundle and bundle_digest produced by prover/ringtest/ringprotocol/anonymous_bodies_vector_test.go with WRITE_AUDIT_VECTORS=1, slot secrets and tags stay pinned in the file."

func TestAnonymousBodiesVector(t *testing.T) {
	var vector map[string]any
	ringtest.ReadVector(t, "audit/anonymous_bodies.json", &vector)
	text := func(name string) string { return vector[name].(string) }
	bytes32 := func(name string) [32]byte {
		decoded, err := hex.DecodeString(text(name))
		if err != nil {
			t.Fatal(err)
		}
		return [32]byte(decoded)
	}
	field := func(name string) *big.Int { return ringtest.VectorField(t, text(name)) }
	body := RecipientBody{
		Blinding: field("body_blinding"),
		Amount:   uint64(vector["body_amount"].(float64)),
		Mint:     bytes32("body_mint"),
	}.Seal(t, field("body_slot_secret"))
	var keys [][32]byte
	for _, key := range vector["recipient_keys"].([]any) {
		var recipient [32]byte
		if text := key.(string); text != "" {
			decoded, err := hex.DecodeString(text)
			if err != nil {
				t.Fatal(err)
			}
			recipient = [32]byte(decoded)
		}
		keys = append(keys, recipient)
	}
	bundle := SenderBundle{
		OutputSeed:    field("output_seed"),
		Change:        []ChangeCell{{Mint: bytes32("change_mint"), Amount: uint64(vector["change_amount"].(float64))}},
		RecipientKeys: keys,
	}.Seal(t, field("bundle_slot_secret"))
	vector["description"] = anonymousBodiesDescription
	vector["body"] = hex.EncodeToString(body[:])
	vector["bundle"] = hex.EncodeToString(bundle)
	vector["bundle_digest"] = ringtest.FieldHex(EnvelopeDigest(t, bundle))
	ringtest.PinVector(t, "audit/anonymous_bodies.json", vector)
}
