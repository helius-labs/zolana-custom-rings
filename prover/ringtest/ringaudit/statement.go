package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
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
	EphU           [32]byte
	Sealed         []byte
	Salt           [16]byte
	// Layout is the raw statement value, Layout.Value of the transfer's flags.
	Layout int64
}

func (h AuditHead) Elements(t testing.TB) []*big.Int {
	t.Helper()
	txLo, txHi := ringprotocol.Pack33(ringprotocol.Tagged(h.TxViewingU[:]))
	auditorLo, auditorHi := ringprotocol.Pack33(h.AuditorPubkey)
	ephLo, ephHi := ringprotocol.Pack33(ringprotocol.Tagged(h.EphU[:]))
	return []*big.Int{
		big.NewInt(shared.AuditStatementDomain), h.FirstNullifier, h.RingProgramID, txLo, txHi,
		auditorLo, auditorHi, ephLo, ephHi, ringtest.HashBytes(t, h.Sealed), new(big.Int).SetBytes(h.Salt[:]), big.NewInt(h.Layout),
	}
}

// Layout is a transfer's layout flags, mirrors the Layout flags of package audit.
type Layout struct {
	Exits        bool
	Escrow       bool
	Reserved     bool
	FullOpenings bool
}

func (l Layout) Value() int64 {
	return ringtest.Bit(l.Exits)*audit.LayoutExits | ringtest.Bit(l.Escrow)*audit.LayoutEscrow |
		ringtest.Bit(l.Reserved)*audit.LayoutReserved | ringtest.Bit(l.FullOpenings)*audit.LayoutFullOpenings
}

func hasExit(utxos []Utxo) bool {
	return slices.ContainsFunc(utxos, Utxo.isExit)
}

// StatementOutput is one published output as an audit statement reads it.
type StatementOutput struct {
	Hash *big.Int
	// Exit chains zero for its body and recipient key.
	Exit bool
	U    [32]byte
	Body []byte
}

// AnonymousTail is what only an anonymous audit statement binds.
type AnonymousTail struct {
	PrivateTxHash    *big.Int
	SenderCommitment *big.Int
	PartyIdentities  [3]*big.Int
}

// DeliveredStatement mirrors AuditKind::Delivered.
func DeliveredStatement(t testing.TB, head AuditHead, outputs []StatementOutput, disclosure []*big.Int) []*big.Int {
	t.Helper()
	var keys []*big.Int
	for _, output := range outputs {
		lo, hi := ringprotocol.Pack32(output.U)
		if output.Exit {
			lo, hi = big.NewInt(0), big.NewInt(0)
		}
		keys = append(keys, lo, hi)
	}
	return append(head.Elements(t),
		outputChain(t, outputs), bodyChain(t, outputs), spptest.MustHashChain4(t, disclosure), spptest.MustHashChain4(t, keys))
}

// AnonymousStatement mirrors AuditKind::Anonymous.
func AnonymousStatement(t testing.TB, head AuditHead, outputs []StatementOutput, disclosure []*big.Int, tail AnonymousTail) []*big.Int {
	t.Helper()
	return append(head.Elements(t),
		outputChain(t, outputs), spptest.MustHashChain4(t, disclosure), tail.PrivateTxHash, tail.SenderCommitment,
		tail.PartyIdentities[0], tail.PartyIdentities[1], tail.PartyIdentities[2])
}

func outputChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = output.Hash
	}
	return spptest.MustHashChain4(t, hashes)
}

// bodyChain chains hash_bytes(body), zero on an exit.
func bodyChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = big.NewInt(0)
		if !output.Exit {
			hashes[i] = ringtest.HashBytes(t, output.Body)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}
