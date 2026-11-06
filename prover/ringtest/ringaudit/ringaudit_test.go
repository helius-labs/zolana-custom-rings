package ringaudit

import (
	"encoding/hex"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func TestAuditEnvelopeVector(t *testing.T) {
	k := DefaultKeys(t)
	ciphertext := k.StreamCiphertext(t, k.txViewingSk[:], shared.AuditEncInfo)
	if got := hex.EncodeToString(ciphertext); got != "48537b94c6262ed3b45768a5d0f065edbb25515039bef17bacf99386f7f55e6a" {
		t.Fatalf("auditor ciphertext: %s", got)
	}
	if got := hex.EncodeToString(ringtest.HashBytes(t, ciphertext).FillBytes(make([]byte, 32))); got != "1da03a7817d9c952830c64ded3b58801fdd1174ea9f69e46f99afa37a871fd22" {
		t.Fatalf("auditor ciphertext hash: %s", got)
	}
}
