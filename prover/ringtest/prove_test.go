package ringtest_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

func TestAuditAndPolicySectionsProve(t *testing.T) {
	shape := audit.StreamShape{InputClass: 4, Outputs: 2}
	requireProves(t, ringaudit.NewSectionCircuit(shape), ringaudit.NewSection(t, shape).Circuit(t))
	section, err := ringpolicy.NewSectionCircuit(ringpolicy.SectionShape{Outputs: 2})
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, section, ringpolicy.Confidential().Build(t).Assignment())
}

func TestAnonymousTransferProves(t *testing.T) {
	shape := transfer.Shape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4}
	circuit, err := transfer.NewTransferCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, circuit, ringtransfer.Hidden(shape).Build(t).Circuit)
}

func requireProves(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	cs := ringkey.Compile(t, circuit)
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("honest proof refused: %v", err)
	}
	inputs := public.Vector().(fr.Vector)
	one := fr.One()
	inputs[0].Add(&inputs[0], &one)
	if groth16.Verify(proof, vk, public) == nil {
		t.Fatal("proof verified under another public input")
	}
}
