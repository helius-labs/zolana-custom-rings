// Exposes package internals to the black box tests.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

var PeakHint = peakHint

func DecodeTable(t Table, api frontend.API, rc frontend.Rangechecker, policyHash frontend.Variable) {
	t.decodeWhen(api, rc, 1, policyHash)
}

// Quantities are one row's flows of one asset.
type Quantities struct{ Debit, Kept, Charge, ChargedOutflow frontend.Variable }

// RowFlows runs flowsOf over the rows for one asset.
func RowFlows(api frontend.API, rc frontend.Rangechecker, rows []frontend.Variable, inputs, outputs []shared.Output, publicAssets, gross []frontend.Variable, asset frontend.Variable) []Quantities {
	flows := newFlowSource(api, Spend{Senders: rows, Inputs: inputs}, outputs, publicAssets, gross).flowsOf(api, newComparator(rc), asset)
	quantities := make([]Quantities, len(flows))
	for j, flow := range flows {
		quantities[j] = Quantities{Debit: flow.debit, Kept: flow.kept, Charge: flow.charge, ChargedOutflow: flow.chargedOutflow}
	}
	return quantities
}

// PaymentGuards returns each payment's owner guard and asset guard.
func PaymentGuards(api frontend.API, rc frontend.Rangechecker, payments []Payment, inputs []shared.Output) (owner, asset []frontend.Variable) {
	for _, guard := range paymentGuards(api, newComparator(rc), payments, inputs) {
		owner, asset = append(owner, guard.owner), append(asset, guard.asset)
	}
	return owner, asset
}
