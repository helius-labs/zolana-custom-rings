// Attributes a transfer's flows to the owners who spent, and holds each owner's charged outflow of each
// asset to the asset's cap.
//
// SPP conserves each asset over the whole transaction and publishes a signed net per public slot. It
// says nothing about who lost what, and a net hides a withdrawal that a deposit offsets. A per owner cap
// needs a per owner number, and no prover input may choose it. Every quantity below reads the opened
// slots, the rows and the statement's gross. Without the section a ring's caps and approval bits would
// bind nothing on a private transfer.
//
// Read after policy/screen.go, policy/subjects.go, policy/comparator.go, transfer/owners.go. Read before
// program-libs/policy/src/quantities.rs, its mirror.
//
// The quantities, per row and asset unless named per asset.
//   held             the row's live inputs, a default-ring note included. Rows key on owner identity,
//                    so one owner's notes add across nullifier keys.
//   returned         the row's live ring outputs.
//   debit            held less returned, never below zero. The owner's net outflow, its actual decrease.
//   kept             held less debit.
//   leaving          per asset, every exit whoever receives it, plus the statement's gross with no
//                    deposit subtracted.
//   displaced        per asset, min(leaving, total held) less min(leaving, total debit). What leaves
//                    beyond the debits, capped at what the rows held.
//   charge           displaced split over kept by the running floors in flowsOf.
//   charged outflow  debit plus charge, at most held. The cap and cosign_above read it.
//   peak             per asset, the largest charged outflow of any row.
//
// Why a charge exists. S spends 1000, a public deposit of 1000 joins, S receives 1000 back and 1000
// exits to X. S's debit is zero and no debit pays for what left. S's charge is 1000, and a cap of 100
// refuses the transfer. Public funds that pass straight through charge only what the rows held.
//
// The charge is a policy definition, not a trace of whose funds left. Leaving names no payer, so a
// transaction that composes payments charges an owner for exits another party funds. A spends 100 and
// receives 100 back, B's public deposit of 100 joins, and the transaction withdraws 100 in public. A's
// net outflow is zero and its charged outflow is 100. The SDKs report each owner's charged outflow
// before signing, a caller splits independent payments into separate transactions to avoid the charge.
//
// The withdrawal threshold reads each public slot's gross and no row. It bounds what the transaction
// withdraws in public whoever funds it, and the charge bounds what one owner's funds answer for.
//
// Properties:
// 1. Every row's debit, kept, charge and charged outflow follow from the slots, the gross and the row order alone.
// 2. The charges sum to displaced exactly, and no row's charge passes its kept.
// 3. While active, every live output's asset and every public asset holds its peak charged outflow to a nonzero cap.
// 4. ApprovalOutflow is set exactly when such a peak passes a nonzero cosign_above, ApprovalWithdrawal exactly when a gross passes a nonzero withdrawal threshold, and both read zero off active.
// 5. The rows ascend strictly while the rail reads them, one owner holds one row.
//
// The program folds the gross from the settled legs, PublicSlots in program-libs/interface/src/codec/spp.rs, and the circuit consumes it as a statement value.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type mintPolicyWires struct{ threshold, cap, cosignAbove frontend.Variable }

type publicAsset struct {
	limitedAsset
	// withdrawalThreshold reads zero off a record.
	withdrawalThreshold frontend.Variable
}

// Approval mask bits, mirrored by ApprovalMask in program-libs/policy/src/quantities.rs.
const (
	ApprovalOutflow    = 1
	ApprovalWithdrawal = 2
)

// Every output and public asset opens its own record, including absence.
type limitedAsset struct {
	asset, active frontend.Variable
	policy        mintPolicyWires
}

// held = debit + kept.
type ownerFlow struct{ debit, kept, charge, chargedOutflow frontend.Variable }

type assetTotals struct{ peak, chargedOutflow frontend.Variable }

type flowSource struct {
	inputs, outputs []shared.Output
	// Keyed by row then slot.
	heldBy, returnedBy [][]frontend.Variable
	// Zero on a zero owner, a zero row matches it.
	held, returned []frontend.Variable
	exits          []frontend.Variable
	publicAssets   []frontend.Variable
	// Statement-bound, zero while the section is off.
	gross []frontend.Variable
}

type slotFlags struct{ inputs, outputs []frontend.Variable }

type assetSplit struct {
	// A row's charged outflow reads its debit until flowsOf charges it.
	rows              []ownerFlow
	held, debit, kept frontend.Variable
}

// constrainOutflow holds each row's charged outflow per asset to the asset's cap, the proven approval mask reads zero while active is off.
func (p *PolicyInputs) constrainOutflow(api frontend.API, cmp comparator, active frontend.Variable, spend Spend, outputs []shared.Output, resolved subjects) Screening {
	// 1. The program binds gross to settled withdrawal legs. The bound at debitBits admits gross above u64 and keeps policy comparisons over integers.
	// Leg amounts, thresholds and net magnitudes have separate u64 bounds. Gross reads zero while inactive.
	gross := make([]frontend.Variable, len(p.PublicGross))
	for k := range gross {
		gross[k] = api.Mul(active, p.PublicGross[k])
		cmp.rc.Check(gross[k], cmp.width)
	}
	source := newFlowSource(api, spend, outputs, p.PublicAssets[:], gross)
	// 2. One peak per asset stands for one comparison per row. A peak within the cap holds every row within it, and the peak equals some row's charged outflow.
	overOutflow := frontend.Variable(0)
	bound := func(limit limitedAsset, flows []ownerFlow) assetTotals {
		outflows, total := make([]frontend.Variable, len(flows)), frontend.Variable(0)
		for j, flow := range flows {
			outflows[j] = flow.chargedOutflow
			total = api.Add(total, flow.chargedOutflow)
		}
		peak := cmp.peak(api, outflows)
		bounded := api.Mul(active, limit.active)
		transaction.AssertWhen(api, api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cap)), cmp.atMost(api, peak, limit.policy.cap))
		cosigned := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cosignAbove))
		overOutflow = api.Or(overOutflow, api.Mul(cosigned, cmp.above(api, peak, limit.policy.cosignAbove)))
		return assetTotals{peak: peak, chargedOutflow: total}
	}
	// 3. Every live output's asset meets its bound with the charge included.
	totals := make([]frontend.Variable, 0, 3*len(outputs)+4*len(resolved.publicAssets))
	for o, out := range outputs {
		slot := bound(limitedAsset{asset: out.Asset, active: out.Utxo, policy: resolved.mintPolicies[o]}, source.flowsOf(api, cmp, out.Asset))
		// An unpublished slot's asset stays free and may share a live one, zeros keep its slot from reading as live.
		totals = append(totals, api.Mul(out.Utxo, out.Asset), api.Mul(out.Utxo, slot.peak), api.Mul(out.Utxo, slot.chargedOutflow))
	}
	// 4. Every public asset meets its bound over the debits. SPP's balance leaves an asset with neither a live output nor a public slot holding zero, so steps 3 and 4 cover every asset that moves.
	for k, public := range resolved.publicAssets {
		// An asset any row keeps is a live output's asset, whose flow above holds the charge.
		slot := bound(public.limitedAsset, source.splitOf(api, cmp, source.flagsOf(api, public.asset)).rows)
		totals = append(totals, public.asset, slot.peak, slot.chargedOutflow, gross[k])
	}
	// 5. A gross past the asset's withdrawal threshold sets its bit whatever the debits read, a paired deposit lowers no gross.
	overWithdrawal := frontend.Variable(0)
	for k, asset := range resolved.publicAssets {
		threshold := api.Mul(active, asset.withdrawalThreshold)
		cmp.rc.Check(threshold, transaction.AmountBits)
		watched := api.Mul(active, asset.active, ringgadget.IsNonZero(api, threshold))
		overWithdrawal = api.Or(overWithdrawal, api.Mul(watched, cmp.above(api, gross[k], threshold)))
	}
	return Screening{
		ApprovalMask: api.Add(api.Mul(ApprovalOutflow, overOutflow), api.Mul(ApprovalWithdrawal, overWithdrawal)),
		totals:       totals,
		outflow:      active,
	}
}

func newFlowSource(api frontend.API, spend Spend, outputs []shared.Output, publicAssets, gross []frontend.Variable) flowSource {
	// A default-ring input is a held input.
	held, heldBy := ownedAmounts(api, spend.Senders, spend.Inputs, func(input shared.Output) frontend.Variable { return input.Utxo })
	// An exit reads no Ring flag, it leaves the ring whoever receives it.
	returned, returnedBy := ownedAmounts(api, spend.Senders, outputs, func(out shared.Output) frontend.Variable { return out.Ring })
	exits := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		exits[o] = api.Mul(out.Exit, out.Amount)
	}
	return flowSource{
		inputs: spend.Inputs, outputs: outputs,
		heldBy: heldBy, returnedBy: returnedBy,
		held: held, returned: returned, exits: exits,
		publicAssets: publicAssets, gross: gross,
	}
}

// flowsOf attributes the asset's displaced amount over the rows in their constrained order, no prover input selects a share.
func (s flowSource) flowsOf(api frontend.API, cmp comparator, asset frontend.Variable) []ownerFlow {
	flags := s.flagsOf(api, asset)
	// 1. Every exit and public withdrawal of the asset leaves.
	leaving := frontend.Variable(0)
	for o, exit := range s.exits {
		leaving = api.Add(leaving, api.Mul(flags.outputs[o], exit))
	}
	for k, public := range s.publicAssets {
		leaving = api.Add(leaving, api.Mul(IsSame(api, public, asset), s.gross[k]))
	}
	// 2. Each row splits its held funds into a net debit and the part returned to it.
	split := s.splitOf(api, cmp, flags)
	flows := split.rows
	// 3. displaced <= split.kept since split.debit + split.kept = split.held, a zero kept total forces a zero displaced and a divisor of one.
	displaced := api.Sub(cmp.min(api, leaving, split.held), cmp.min(api, leaving, split.debit))
	divisor := api.Add(split.kept, api.IsZero(split.kept))
	// 4. Running floors telescope to displaced and a difference of floors keeps charge <= kept, the last floor is displaced itself.
	//
	// A row's share is floor(displaced * running / total kept), with running the kept of the rows up to it. Shares never fall, so a charge is never negative. The last row takes displaced itself, so the charges sum to displaced and rounding loses nothing. A charge is a difference of floors, at most the ceiling of displaced * kept / total kept, and displaced <= total kept holds that to the row's kept. The rows' order alone decides where a remainder lands.
	running, previous := frontend.Variable(0), frontend.Variable(0)
	for j := range flows {
		share := displaced
		if j < len(flows)-1 {
			running = api.Add(running, flows[j].kept)
			share = cmp.floorDiv(api, api.Mul(displaced, running), divisor)
		}
		flows[j].charge = api.Sub(share, previous)
		flows[j].chargedOutflow = api.Add(flows[j].debit, flows[j].charge)
		previous = share
	}
	return flows
}

func (s flowSource) flagsOf(api frontend.API, asset frontend.Variable) slotFlags {
	return slotFlags{inputs: assetFlags(api, asset, s.inputs), outputs: assetFlags(api, asset, s.outputs)}
}

func (s flowSource) splitOf(api frontend.API, cmp comparator, flags slotFlags) assetSplit {
	heldAmounts, returnedAmounts := weighted(api, s.held, flags.inputs), weighted(api, s.returned, flags.outputs)
	split := assetSplit{rows: make([]ownerFlow, len(s.heldBy)), held: 0, debit: 0, kept: 0}
	for j := range split.rows {
		held := innerProduct(api, s.heldBy[j], heldAmounts)
		debit := cmp.saturatingSub(api, held, innerProduct(api, s.returnedBy[j], returnedAmounts))
		kept := api.Sub(held, debit)
		split.rows[j] = ownerFlow{debit: debit, kept: kept, charge: 0, chargedOutflow: debit}
		split.held, split.debit, split.kept = api.Add(split.held, held), api.Add(split.debit, debit), api.Add(split.kept, kept)
	}
	return split
}

// Keyed by identity alone, a zero owner reads no amount so a zero row holds nothing.
func ownedAmounts(api frontend.API, rows []frontend.Variable, slots []shared.Output, flag func(shared.Output) frontend.Variable) (amounts []frontend.Variable, ownedBy [][]frontend.Variable) {
	amounts, ownedBy = make([]frontend.Variable, len(slots)), make([][]frontend.Variable, len(rows))
	for i, slot := range slots {
		amounts[i] = api.Mul(flag(slot), ringgadget.IsNonZero(api, slot.OwnerPkHash), slot.Amount)
	}
	for j, row := range rows {
		ownedBy[j] = make([]frontend.Variable, len(slots))
		for i, slot := range slots {
			ownedBy[j][i] = IsSame(api, slot.OwnerPkHash, row)
		}
	}
	return amounts, ownedBy
}

func assetFlags(api frontend.API, asset frontend.Variable, slots []shared.Output) []frontend.Variable {
	flags := make([]frontend.Variable, len(slots))
	for i, slot := range slots {
		flags[i] = IsSame(api, slot.Asset, asset)
	}
	return flags
}

func weighted(api frontend.API, values, flags []frontend.Variable) []frontend.Variable {
	products := make([]frontend.Variable, len(values))
	for i, value := range values {
		products[i] = api.Mul(value, flags[i])
	}
	return products
}

func innerProduct(api frontend.API, values, flags []frontend.Variable) frontend.Variable {
	total := frontend.Variable(0)
	for i, value := range values {
		total = api.Add(total, api.Mul(value, flags[i]))
	}
	return total
}

// assertRowsAscending holds live rows strictly ascending with zero rows last, attribution reads the order and a repeated row would count its funds twice.
func assertRowsAscending(api frontend.API, enabled frontend.Variable, rows, liveRows []frontend.Variable) {
	for j := 1; j < len(rows); j++ {
		// 0 < rows[j-1] < rows[j], a live row after a zero row fails its lower bound.
		ringgadget.AssertOrderedWhen(api, api.Mul(enabled, liveRows[j]), 0, rows[j-1], rows[j])
	}
}
