package ringpolicy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// SectionCircuit proves the policy section alone under rail wires, no key proves it.
type SectionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	policy.Policy
	policy.Tracking
	Outputs []shared.UtxoWires
	// Inputs and Senders are what a transfer key's input section fixes.
	Inputs  []shared.UtxoWires
	Senders []frontend.Variable
	// InputChain stays opaque, a transfer key's audit section binds the inputs.
	InputChain        frontend.Variable
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	ThresholdsActive  frontend.Variable
	Delegate          frontend.Variable
	ApprovalMask      frontend.Variable
	ApprovalTotals    frontend.Variable
	ApprovalBlinder   frontend.Variable
}

// sectionSenders is the sender rows of the transfer keys the harness stands for.
const sectionSenders = 4

// SectionShape sizes a harness, Records zero takes the shape's limits.
type SectionShape struct {
	Outputs, Withdrawals, SaltedKeys int
	Records                          policy.RecordPoolShape
}

func NewSectionCircuit(shape SectionShape) (*SectionCircuit, error) {
	inputs := shape.Outputs + transaction.NPublicSlots
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: sectionSenders, SaltedKeys: shape.SaltedKeys, Spent: inputs}.Inputs(), shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	tracking, err := policy.NewTracking(sectionSenders, shape.Outputs, shape.Withdrawals)
	if err != nil {
		return nil, err
	}
	return &SectionCircuit{Policy: p, Tracking: tracking, Outputs: make([]shared.UtxoWires, shape.Outputs), Inputs: make([]shared.UtxoWires, inputs), Senders: make([]frontend.Variable, sectionSenders)}, nil
}

func (c *SectionCircuit) Define(api frontend.API) error {
	if err := c.Validate(transaction.NPublicSlots); err != nil {
		return err
	}
	if err := shared.ValidateLength("policy", "output", len(c.Outputs), c.Policy.Outputs); err != nil {
		return err
	}
	if err := c.ValidateTracking(sectionSenders, c.Policy.Outputs, len(c.Withdrawals)); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	outputs := make([]shared.Output, len(c.Outputs))
	for o, w := range c.Outputs {
		outputs[o] = w.Open(api)
	}
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{c.InputChain, gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs)), 0, c.PrivateTxBlinding}))
	inputs := make([]shared.Output, len(c.Inputs))
	for i, w := range c.Inputs {
		inputs[i] = w.Open(api)
	}
	g := policy.Rail{ThresholdsActive: c.ThresholdsActive, Delegate: c.Delegate}.Gates(api, c.PolicyHash)
	screening := c.Screen(api, rc, g, policy.Spend{Senders: c.Senders, Inputs: inputs, Tracking: c.OpenTracking(api)}, outputs)
	api.AssertIsEqual(c.ApprovalMask, screening.ApprovalMask)
	screening.AssertApprovalTotals(api, c.ApprovalTotals, c.ApprovalBlinder)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.Statement()))
	return nil
}

// Statement binds every value the section reads from the program, in the harness's own order.
func (c *SectionCircuit) Statement() []frontend.Variable {
	fields := []frontend.Variable{c.ThresholdsActive, c.Delegate, c.ApprovalMask, c.ApprovalTotals, c.PrivateTxHash, c.PolicyHash, c.RingProgramID, c.OwnRoot, c.CuratorRoot, c.TrackingRoot}
	fields = append(fields, c.Senders...)
	for k := range c.PublicAssets {
		fields = append(fields, c.PublicAssets[k], c.PublicAmounts[k], c.PublicGross[k])
	}
	return append(fields, c.WithdrawalHash)
}
