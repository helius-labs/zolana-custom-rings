package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// WithdrawalExemptionCircuit binds the gross withdrawals the program computes to
// authenticated per-mint thresholds. Missing records cannot exempt a positive withdrawal.
type WithdrawalExemptionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Root            frontend.Variable
	Assets          [transaction.NPublicSlots]frontend.Variable
	Amounts         [transaction.NPublicSlots]frontend.Variable
	Entries         [transaction.NPublicSlots]registry.QuadOpening
}

func (c *WithdrawalExemptionCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	fields := []frontend.Variable{shared.WithdrawalExemptionDomain, c.Root}
	for i, asset := range c.Assets {
		amount := c.Amounts[i]
		active := api.Sub(1, api.IsZero(asset))
		api.AssertIsEqual(api.Mul(api.Sub(1, active), amount), 0)
		_, _, _, threshold := c.Entries[i].Resolve(api, active, c.Root, asset)
		rc.Check(amount, 64)
		rc.Check(threshold, 64)
		// Both operands are u64; a negative difference cannot fit in 64 bits modulo q.
		rc.Check(api.Sub(threshold, amount), 64)
		fields = append(fields, asset, amount)
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
