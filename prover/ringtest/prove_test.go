package ringtest_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func TestDeliveredAuditAndMemberPolicyProve(t *testing.T) {
	delivered, err := audit.NewDeliveredAuditCircuit(2)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, delivered, ringaudit.DeliveredAuditOf(t, 2).Circuit(t))
	member, err := policy.NewMemberPolicyCircuit(policy.MemberShape{Outputs: 2})
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, member, ringpolicy.Confidential().Build(t).Assignment())
}

func TestAnonymousAuditTransferProves(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	anonymous, err := audit.NewAnonymousAuditCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, anonymous, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
}

func TestAuditsPinBlindingAndRingData(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	anonymous, err := audit.NewAnonymousAuditCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("delivered ring data", func(t *testing.T) {
		delivered, err := audit.NewDeliveredAuditCircuit(8)
		if err != nil {
			t.Fatal(err)
		}
		d := ringaudit.NewDeliveredAudit(t, 8)
		honest := d.Circuit(t)
		d.Outputs[0].Utxo.RingDataHash = big.NewInt(7)
		requireRefused(t, delivered, honest, d.Circuit(t))
	})
	t.Run("anonymous ring data", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, shape)
		honest := a.Circuit(t)
		a.Outputs[0].Utxo.RingDataHash = big.NewInt(7)
		requireRefused(t, anonymous, honest, a.Circuit(t))
	})
	t.Run("anonymous blinding off the CRBS seed", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, shape)
		honest := a.Circuit(t)
		a.Outputs[0].Utxo.Blinding = big.NewInt(7)
		requireRefused(t, anonymous, honest, a.Circuit(t))
	})
}

// requireRefused fails unless honest solves and forged, the same fixture with one value changed, does not.
func requireRefused(t *testing.T, circuit, honest, forged frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, honest, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("the honest witness failed: %v", err)
	}
	if test.IsSolved(circuit, forged, ecc.BN254.ScalarField()) == nil {
		t.Fatal("the circuit accepted the forged witness")
	}
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
