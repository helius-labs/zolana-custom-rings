package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AuditHead is what the program holds for the head of an audit statement, mirrors AuditHead in program-libs/interface/src/proof/statement.rs.
type AuditHead struct {
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	TxViewingU     [32]byte
	AuditorPubkey  [33]byte
	// Envelope and Keys are the transmitted envelope and recipient key ciphertexts, their digest head element 7.
	Envelope []byte
	Keys     []byte
	Salt     [16]byte
	Layout   int64
}

// ElementsUnder is the head under domain.
func (h AuditHead) ElementsUnder(t testing.TB, domain int64) []*big.Int {
	t.Helper()
	txLo, txHi := ringprotocol.Pack33(ringprotocol.Tagged(h.TxViewingU[:]))
	auditorLo, auditorHi := ringprotocol.Pack33(h.AuditorPubkey)
	return []*big.Int{
		big.NewInt(domain), h.FirstNullifier, h.RingProgramID, txLo, txHi,
		auditorLo, auditorHi, ringtest.MustPoseidonHash(t, ringprotocol.EnvelopeDigest(t, h.Envelope), ringprotocol.EnvelopeDigest(t, h.Keys)), new(big.Int).SetBytes(h.Salt[:]), big.NewInt(h.Layout),
	}
}

// StatementOutput is one output slot as an audit statement reads it, an omitted one reads zero.
type StatementOutput struct {
	Record  []byte
	Omitted bool
}

// SignerChain mirrors transfer.OpenSigners over a run of the key's slots, zero at a count of zero.
func SignerChain(t testing.TB, signers []*big.Int, slots int) *big.Int {
	t.Helper()
	if len(signers) == 0 {
		return big.NewInt(0)
	}
	cells := make([]*big.Int, slots)
	for i := range cells {
		cells[i] = big.NewInt(0)
	}
	copy(cells, signers)
	return spptest.MustHashChain4(t, cells)
}

func OutputCount(outputs []StatementOutput) int {
	count := 0
	for _, output := range outputs {
		if !output.Omitted {
			count++
		}
	}
	return count
}

// RecordChain mirrors record_chain, zero past m.
func RecordChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = big.NewInt(0)
		if !output.Omitted {
			hashes[i] = ringtest.HashBytes(t, output.Record)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}
