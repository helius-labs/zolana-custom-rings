package ringpolicy

import (
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"math/big"
	"testing"
)

// Exemption opens the ninth and tenth mints in a registry of twelve thresholds.
func Exemption(t testing.TB) *policy.WithdrawalExemptionCircuit {
	t.Helper()
	tree := ringregistry.New(t)
	for mint := int64(1); mint <= 12; mint++ {
		tree.Apply(t, ringregistry.Entry{Member: big.NewInt(mint), Mask: big.NewInt(0), Value: big.NewInt(0), EscrowKey: big.NewInt(0), MintPolicy: new(big.Int).Lsh(big.NewInt(1), 192), WithdrawalThreshold: big.NewInt(100)})
	}
	c := &policy.WithdrawalExemptionCircuit{Root: tree.Root()}
	for i := range c.Assets {
		c.Assets[i], c.Amounts[i], c.Entries[i] = 0, 0, tree.Opening(big.NewInt(0)).Wires()
	}
	for i, mint := range []int64{9, 10} {
		c.Assets[i], c.Amounts[i], c.Entries[i] = mint, 100, tree.Opening(big.NewInt(mint)).Wires()
	}
	BindExemption(t, c)
	return c
}
func BindExemption(t testing.TB, c *policy.WithdrawalExemptionCircuit) {
	fields := []*big.Int{big.NewInt(shared.WithdrawalExemptionDomain), ringtest.AsBigInt(c.Root)}
	for i := range c.Assets {
		fields = append(fields, ringtest.AsBigInt(c.Assets[i]), ringtest.AsBigInt(c.Amounts[i]))
	}
	c.PublicInputHash = spptest.MustHashChain4(t, fields)
}
