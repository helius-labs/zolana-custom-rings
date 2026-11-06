package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

// Statement is what the program holds for a transfer statement.
type Statement struct {
	Head                                           ringaudit.AuditHead
	RailBits                                       [3]bool
	ApprovalMask, ApprovalTotals                   *big.Int
	SignerDataCounts                               *big.Int
	NoSpend                                        bool
	Outputs                                        []ringaudit.StatementOutput
	InputCount                                     int
	InputNullifierChain                            *big.Int
	PrivateTxHash                                  *big.Int
	Cells                                          []*big.Int
	SignerCount                                    int
	SignerChain                                    *big.Int
	PolicyHash, OwnRoot, CuratorRoot, TrackingRoot *big.Int
	PublicAssets, PublicNets, PublicGross          [3]*big.Int
	WithdrawalHash                                 *big.Int
}

func railValues(t testing.TB, c *transfer.TransferCircuit, a Assembled) Statement {
	t.Helper()
	s := values(t, &c.Sections, a)
	s.RailBits = [3]bool{ringtest.AsBigInt(c.InProof).Sign() != 0, ringtest.AsBigInt(c.Hidden).Sign() != 0, ringtest.AsBigInt(c.Delegate).Sign() != 0}
	s.Cells = []*big.Int{ringtest.AsBigInt(c.Sender)}
	for _, party := range c.PartyIdentities {
		s.Cells = append(s.Cells, ringtest.AsBigInt(party))
	}
	return s
}

// Elements mirrors TransferStatement::elements.
func (s Statement) Elements(t testing.TB) []*big.Int {
	t.Helper()
	elements := append(s.Head.ElementsUnder(t, shared.TransferStatementDomain),
		bitField(s.RailBits[0]), bitField(s.RailBits[1]), bitField(s.RailBits[2]), s.ApprovalMask, s.ApprovalTotals, s.SignerDataCounts, bitField(s.NoSpend),
		big.NewInt(int64(ringaudit.OutputCount(s.Outputs))),
		ringaudit.OutputChain(t, s.Outputs), ringaudit.RecordChain(t, s.Outputs), ringaudit.TailChain(t, s.Outputs),
		big.NewInt(int64(s.InputCount)), s.InputNullifierChain, s.PrivateTxHash,
	)
	elements = append(elements, s.Cells...)
	elements = append(elements, big.NewInt(int64(s.SignerCount)), s.SignerChain, s.PolicyHash, s.OwnRoot, s.CuratorRoot, s.TrackingRoot)
	for k := range s.PublicAssets {
		elements = append(elements, s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k])
	}
	elements = append(elements, s.WithdrawalHash)
	return append(elements, big.NewInt(int64(len(elements)+1)))
}

func bitField(set bool) *big.Int {
	if set {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}
