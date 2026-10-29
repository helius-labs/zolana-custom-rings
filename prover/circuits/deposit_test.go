package circuits_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringdeposit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func solveDeposit(c *circuits.DepositCircuit) error {
	shape, err := circuits.NewDepositCircuit(c.Capacity)
	if err != nil {
		return err
	}
	return test.IsSolved(shape, c, ecc.BN254.ScalarField())
}

// The program builds one flag combination per ring mode, escrow only on a registry ring.
func TestDepositSolvesEveryRingMode(t *testing.T) {
	for _, tc := range []struct {
		count int
		mode  ringdeposit.RingMode
	}{{1, ringdeposit.ModeRegistry}, {circuits.MaxDeposits, ringdeposit.ModeRegistry}, {2, ringdeposit.ModeAnonymous}, {2, ringdeposit.ModeOff}} {
		if err := solveDeposit(ringdeposit.Build(t, tc.count, tc.mode).Circuit); err != nil {
			t.Fatalf("count %d mode %d: %v", tc.count, tc.mode, err)
		}
	}
}

// Each case changes one value of an honest deposit, rebinding the statement when the value is a statement element.
func TestDepositRefusals(t *testing.T) {
	define := []string{"circuits.(*DepositCircuit).Define"}
	tests := []struct {
		name   string
		mode   ringdeposit.RingMode
		tamper func(*testing.T, *ringdeposit.Deposit)
		frames []string
	}{
		{"a commitment whose blinding is not in the CRDB domain", ringdeposit.ModeRegistry, func(t *testing.T, d *ringdeposit.Deposit) {
			// The commitments and the auditor's openings all use the raw secret as the blinding.
			*d = *ringdeposit.BuildBlinded(t, 2, ringdeposit.ModeRegistry, func(_ testing.TB, secret *big.Int) *big.Int { return secret })
		}, append([]string{"[assertIsEqual]"}, define...)},
		{"an escrowed owner opened through another member's record", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.Members[0] = d.Circuit.Members[1]
		}, []string{"gadget.AssertEqualWhen", "registry.QuadRecordOpening.AssertPresent"}},
		{"a record escrowing another key", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.CtHashes[0] = big.NewInt(0xdd)
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a padding slot with a blinding secret", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.BlindingSecrets[circuits.MaxDeposits-1] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"an anonymous owner hash of another key", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][1] = 0
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a key disclosed by a ring that is not anonymous", ringdeposit.ModeOff, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][0] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"owner key bytes outside 0..255 with the same owner identity", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			// Moving 256 between adjacent bytes keeps the identity, the envelope's byte table refuses the encoding.
			key := &d.Circuit.OwnerKeys[0]
			key[3], key[4] = key[3].(int)-1, key[4].(int)+256
		}, append([]string{"shared.Envelope.Seal"}, define...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ringdeposit.Build(t, 2, tt.mode)
			tt.tamper(t, d)
			ringtest.RequireRefused(t, solveDeposit(d.Circuit), tt.frames...)
		})
	}
}

// A policy requiring the allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringpolicy.AssetA)).Circuit); err != nil {
		t.Fatalf("listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringpolicy.AssetB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), "policy.paymentScreen.assert", "policy.DepositAssets.Assert")
}

// A curator served allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsCuratorRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringpolicy.AssetA)).Circuit); err != nil {
		t.Fatalf("curator listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringpolicy.AssetB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), "policy.paymentScreen.assert", "policy.DepositAssets.Assert")
}

func TestDepositKey(t *testing.T) {
	ringkey.RequirePinned(t, "custom_ring_deposit_8", ringkey.Compile(t, depositCircuit(t, circuits.MaxDeposits)))
}

func depositCircuit(t *testing.T, capacity int) *circuits.DepositCircuit {
	t.Helper()
	c, err := circuits.NewDepositCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDepositCapacitiesPreserveStatementsAndBoundCounts(t *testing.T) {
	for _, capacity := range circuits.DepositCapacities {
		for _, count := range []int{1, capacity} {
			for _, mode := range []ringdeposit.RingMode{ringdeposit.ModeRegistry, ringdeposit.ModeAnonymous, ringdeposit.ModeOff} {
				small := ringdeposit.BuildCapacity(t, capacity, count, mode)
				full := ringdeposit.Build(t, count, mode)
				if ringtest.AsBigInt(small.Circuit.PublicInputHash).Cmp(ringtest.AsBigInt(full.Circuit.PublicInputHash)) != 0 {
					t.Fatal("capacity changed deposit statement")
				}
				if err := solveDeposit(small.Circuit); err != nil {
					t.Fatalf("capacity %d count %d: %v", capacity, count, err)
				}
			}
		}
		for _, count := range []int{0, capacity + 1} {
			bad := ringdeposit.BuildCapacity(t, capacity, 1, ringdeposit.ModeRegistry)
			bad.Circuit.Count = count
			if solveDeposit(bad.Circuit) == nil {
				t.Fatalf("capacity %d accepted count %d", capacity, count)
			}
		}
	}
}
