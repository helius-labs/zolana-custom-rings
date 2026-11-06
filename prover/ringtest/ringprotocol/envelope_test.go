package ringprotocol

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func TestAuditStreamKDFVector(t *testing.T) {
	key, nonce := AuditStreamKeys(t, big.NewInt(0x12345), shared.AuditEncInfo)
	for _, vector := range []struct{ name, got, want string }{
		{"key", hex.EncodeToString(key[:]), "176f7641c75eea4933a690ab9e31024e02a87caa727c9610438505ffa4c6ecc8"},
		{"nonce", hex.EncodeToString(nonce[:]), "41df863d421d99dc6f69a16c"},
		{"ciphertext", hex.EncodeToString(CTREncrypt(t, key, nonce, make([]byte, 32))), "1bdac2890094c5e4113d9e5b60b17aca409d3f9baba3912c65c8fc76bef1ae3c"},
	} {
		if vector.got != vector.want {
			t.Errorf("%s: got %s want %s", vector.name, vector.got, vector.want)
		}
	}
}

type streamVector struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	Secret     string `json:"secret"`
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	Counter    uint32 `json:"counter"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

func TestAuditorStreamMatchesRustVector(t *testing.T) {
	var vectors struct {
		Labels  []streamVector `json:"labels"`
		Records []streamVector `json:"records"`
	}
	ringtest.ReadVector(t, "audit/auditor-stream.json", &vectors)
	for _, v := range append(vectors.Labels, vectors.Records...) {
		t.Run(v.Name, func(t *testing.T) {
			label := v.Label
			if label == "" {
				label = shared.AuditEncInfo
			}
			key, nonce := AuditStreamKeys(t, ringtest.VectorField(t, v.Secret), label)
			if got := hex.EncodeToString(key[:]); v.Key != "" && got != v.Key {
				t.Errorf("key %s, the vector holds %s", got, v.Key)
			}
			if got := hex.EncodeToString(nonce[:]); v.Nonce != "" && got != v.Nonce {
				t.Errorf("nonce %s, the vector holds %s", got, v.Nonce)
			}
			plaintext, err := hex.DecodeString(v.Plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(CTREncryptAt(t, key, nonce, v.Counter, plaintext)); got != v.Ciphertext {
				t.Errorf("ciphertext %s, the vector holds %s", got, v.Ciphertext)
			}
		})
	}
}
