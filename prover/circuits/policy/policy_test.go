package policy_test

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// Budgets bound every key of two or four outputs, transaction size bounds the wider keys.
const (
	memberBudget   = 100_000
	delegateBudget = 150_000
)

// delegateWidths mirrors RING_AUTHORITY_WIDTHS in zolana/program-libs/interface/src/shape.rs.
var delegateWidths = []int{2, 4}

type policyKey struct {
	name    string
	budget  int
	circuit func() (frontend.Circuit, error)
	honest  func() ringpolicy.World
}

func TestPolicyKeys(t *testing.T) {
	for _, key := range policyKeys() {
		t.Run(key.name, func(t *testing.T) {
			cs := compiled(t, key.name, key.circuit)
			if _, pinned := ringkey.Pinned[key.name]; pinned {
				ringkey.RequirePinned(t, key.name, cs)
			}
			if got := cs.GetNbConstraints(); key.budget != 0 && got >= key.budget {
				t.Errorf("%d constraints, budget %d", got, key.budget)
			}
			requireCompiledSolved(t, cs, key.honest().Build(t))
		})
	}
	t.Run("anonymous", func(t *testing.T) {
		requireCompiledSolved(t, compiled(t, memberKeyName(2), member(2)), ringpolicy.Anonymous().Build(t))
	})
	t.Run("curator", func(t *testing.T) {
		requireCompiledSolved(t, compiled(t, memberKeyName(2), member(2)), curated().Build(t))
	})
	for _, outputs := range policy.MemberOutputs {
		name := memberKeyName(outputs)
		t.Run(name+" u64 extremes", func(t *testing.T) {
			requireCompiledSolved(t, compiled(t, name, member(outputs)), extremes(t, outputs))
		})
	}
	for _, r := range refusals {
		capacities := []int{0}
		if r.wide {
			capacities = append(capacities, 8, 16)
		}
		for _, outputs := range capacities {
			name := r.name
			if outputs != 0 {
				name = fmt.Sprintf("%s on the %d-output key", r.name, outputs)
			}
			honest := func() ringpolicy.World {
				w := r.honest()
				if outputs != 0 {
					w.Outputs = outputs
				}
				return w
			}
			t.Run(name, func(t *testing.T) {
				requireSolved(t, honest().Build(t))
				w := honest()
				if r.world != nil {
					r.world(&w)
				}
				b := w.Build(t)
				if r.witness != nil {
					r.witness(t, b)
				}
				ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), r.in)
			})
		}
	}
	for _, f := range forgeries {
		t.Run(f.name, func(t *testing.T) {
			requireForgeryRefused(t, ringtest.RegisteredHint(t, f.hint), f.forge)
		})
	}
}

const (
	comparisonHint = "/policy.comparisonHint"
	rulePartsHint  = "/policy.rulePartsHint"
)

// forgeries each rewrite the outputs of one hint on the honest 2-output member witness.
var forgeries = []struct {
	name  string
	hint  string
	forge func(q *big.Int, in, out []*big.Int)
}{
	{name: "comparison bit flipped", hint: comparisonHint, forge: func(_ *big.Int, _, out []*big.Int) {
		if out[1].Sign() == 0 {
			out[1].SetInt64(1)
		}
	}},
	{name: "comparison low part wrapped", hint: comparisonHint, forge: func(_ *big.Int, in, out []*big.Int) {
		if out[1].Sign() == 0 {
			out[0].Sub(out[0], new(big.Int).Lsh(big.NewInt(1), uint(in[1].Uint64())))
			out[1].SetInt64(1)
		}
	}},
	{name: "comparison bit off the bits", hint: comparisonHint, forge: func(q *big.Int, in, out []*big.Int) {
		if out[1].Sign() == 0 {
			step := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), uint(in[1].Uint64())), q)
			out[0].Add(out[0], big.NewInt(1))
			out[1].Sub(out[1], step).Mod(out[1], q)
		}
	}},
	{name: "rule part carried into its neighbour", hint: rulePartsHint, forge: func(_ *big.Int, _, out []*big.Int) {
		out[0].Add(out[0], big.NewInt(1<<8))
		out[1].Sub(out[1], big.NewInt(1))
	}},
	{name: "rule subject dropped", hint: rulePartsHint, forge: func(_ *big.Int, _, out []*big.Int) {
		out[0].SetInt64(0)
	}},
}

// refusals each mutate one honest value, the circuit refuses inside the named function, a wide one also on the 8- and 16-output keys.
var refusals = []struct {
	name    string
	honest  func() ringpolicy.World
	world   func(*ringpolicy.World)
	witness func(testing.TB, ringpolicy.Witness)
	in      string
	wide    bool
}{
	{name: "owner record claiming a list it lacks", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) {
		b.OwnRecord(b.Policy().OwnerEntries[0]).Lists = ringregistry.AllowBit | ringregistry.BlockBit
	}, in: "registry.SharedQuadProof.AssertLeavesWhen", wide: true},
	{name: "public deposit above the outflow to others", honest: deposited, world: func(w *ringpolicy.World) { w.Public[0].Amount = 400 }, in: "policy.(*PolicyInputs).constrainOutflow", wide: true},
	{name: "dummy amount covering a public deposit", honest: dummyDeposit, world: func(w *ringpolicy.World) { w.Public[0].Amount = 150 }, in: "policy.(*PolicyInputs).constrainOutflow"},
	{name: "withdrawal past the cap", honest: withdrawn, world: func(w *ringpolicy.World) { w.Public[0].Amount = -800 }, in: "policy.(*PolicyInputs).constrainOutflow", wide: true},
	{name: "approval bit 0 past the co-sign bound", honest: cosigned, world: func(w *ringpolicy.World) { w.ApprovalRequired = false }, in: "policy.(*MemberPolicyCircuit).assertApproval", wide: true},
	{name: "approval bit 1 within every co-sign bound", honest: ringpolicy.Four, world: func(w *ringpolicy.World) { w.ApprovalRequired = true }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "approval bit 1 under a cap without a co-sign bound", honest: capOnly, world: func(w *ringpolicy.World) { w.ApprovalRequired = true }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "exit to the sender counted as outflow", honest: exited, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 201 }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "anonymous sender that is not the commitment", honest: ringpolicy.Anonymous, witness: func(t testing.TB, b ringpolicy.Witness) {
		b.Member.Sender = ringpolicy.Sender
		b.Rebind(t)
	}, in: "policy.(*MemberPolicyCircuit).sender", wide: true},
	{name: "delegate move with a second member's input", honest: delegate2, world: func(w *ringpolicy.World) {
		w.Inputs[1] = ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}
	}, in: "policy.(*DelegatePolicyCircuit).sender"},
	{name: "delegate move without a spent input", honest: delegate2, world: func(w *ringpolicy.World) { w.Inputs[0] = ringpolicy.Slot{} }, in: "policy.(*DelegatePolicyCircuit).sender"},
	{name: "output owner other than its public recipient", honest: ringpolicy.Confidential, witness: func(t testing.TB, b ringpolicy.Witness) {
		b.Policy().Recipients[0] = ringpolicy.Bob
		b.Rebind(t)
	}, in: "policy.(*PolicyInputs).assertRecipients", wide: true},
	{name: "owner off a required list", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) { w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0) }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "owner on a forbidden list", honest: blocked, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringregistry.AllowBit | ringregistry.BlockBit)
	}, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "sender on a forbidden list", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Sender] = ringpolicy.Escrowed(ringregistry.AllowBit | ringregistry.FrozenBit)
	}, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "asset off a required list", honest: ringpolicy.Four, world: func(w *ringpolicy.World) { delete(w.Own, ringpolicy.AssetB) }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "curator list missing from the curator registry", honest: curated, world: func(w *ringpolicy.World) { delete(w.Curator, ringpolicy.Alice) }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "subject on an alternative list", honest: alternative, world: func(w *ringpolicy.World) { w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringregistry.BlockBit) }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "scalar guard above its threshold", honest: scalarGuarded, world: func(w *ringpolicy.World) { w.Slots[0].Amount = 600 }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "scalar guard over two assets", honest: scalarGuarded, world: func(w *ringpolicy.World) { w.Slots[1].Asset = ringpolicy.AssetB }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "asset guard above the inline limit", honest: assetGuarded, world: func(w *ringpolicy.World) { w.Slots[0].Amount = 600 }, in: "policy.(*PolicyInputs).assertRules", wide: true},
	{name: "asset guard without an inline limit", honest: assetGuardedListed, world: func(w *ringpolicy.World) { w.Slots[0].Asset = ringpolicy.AssetB }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "scalar guard over split outputs", honest: scalarSplit, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 300 }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "asset scalar guard above its threshold", honest: assetScalarGuarded, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 300 }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "escrow of another key ciphertext", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().Outputs[0].CtHash = 7 }, in: "policy.(*PolicyInputs).assertEscrow"},
	{name: "escrow without a registered key", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: ringregistry.AllowBit}
	}, in: "policy.(*PolicyInputs).assertEscrow", wide: true},
	{name: "delegate output owner without a registered key", honest: delegate2, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: ringregistry.AllowBit}
	}, in: "policy.(*PolicyInputs).assertEscrow"},
	{name: "table row the program never hashed", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) {
		b.Policy().Rules[1] = ringpolicy.Require(policy.SubjectSender, ringregistry.FrozenBit).Packed()
	}, in: "policy.Table.decode"},
	{name: "output SPP never settled", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().Outputs[0].Amount = 301 }, in: "policy.(*PolicyInputs).openOutputs", wide: true},
	{name: "opening under another root", honest: ringpolicy.Confidential, witness: func(t testing.TB, b ringpolicy.Witness) {
		b.Policy().OwnRoot = 5
		b.Rebind(t)
	}, in: "registry.SharedQuadProof.AssertLeavesWhen"},
	{name: "curator root outside the statement", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().CuratorRoot = 5 }, in: "policy.bindStatement"},
}

func curated() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
	for _, m := range []int64{ringpolicy.Sender, ringpolicy.Alice} {
		w.Own[m] = ringpolicy.Escrowed(0)
		w.Curator[m] = ringpolicy.Record{Lists: ringregistry.AllowBit}
	}
	return w
}

func deposited() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

// withdrawn moves an outflow of 800 past the co-sign bound, within the cap, beside a deposit of another asset.
func withdrawn() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -500}, {Asset: ringpolicy.AssetB, Amount: 1000}}
	w.ApprovalRequired = true
	return w
}

// extremes pays alice the u64 maximum on every output beside a u64 maximum withdrawal, the widest differences the key compares.
func extremes(t testing.TB, outputs int) ringpolicy.Witness {
	w := ringpolicy.Four()
	w.Outputs = outputs
	w.Table.Rules[0].Guard, w.Table.Rules[0].Threshold = policy.GuardAboveAmount, 500
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 1}}
	w.Slots = nil
	for range outputs {
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: math.MaxUint64})
	}
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -1}}
	w.ApprovalRequired = true
	b := w.Build(t)
	// A world's int64 public amounts stop short of a u64 maximum withdrawal.
	b.Policy().PublicAmounts[0] = protocol.SignedToField(new(big.Int).Neg(new(big.Int).SetUint64(math.MaxUint64)))
	b.Rebind(t)
	return b
}

func capOnly() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 1000}}
	return w
}

func dummyDeposit() ringpolicy.World {
	w := ringpolicy.Four()
	w.Slots = append(w.Slots, ringpolicy.Slot{Asset: ringpolicy.AssetA, Amount: 50})
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func cosigned() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Slots[0].Amount = 600
	w.ApprovalRequired = true
	return w
}

// exited sends the change out of the ring, an outflow of 500 at the co-sign bound.
func exited() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Slots[1].Exit = true
	return w
}

func blocked() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit))
	return w
}

func alternative() ringpolicy.World {
	w := ringpolicy.Confidential()
	rule := ringpolicy.Require(policy.SubjectOutputOwner, ringregistry.AllowBit)
	rule.Alternative = ringregistry.BlockBit
	w.Table.Rules[0] = rule
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func scalarGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules[0].Guard, w.Table.Rules[0].Threshold = policy.GuardAboveAmount, 500
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func assetGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules[0].Guard = policy.GuardAboveAmountByAsset
	w.Table.Inline = []ringpolicy.InlineLimit{{Asset: ringpolicy.AssetA, Limit: 500}}
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func assetGuardedListed() ringpolicy.World {
	w := assetGuarded()
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringregistry.AllowBit)
	return w
}

func scalarSplit() ringpolicy.World {
	w := scalarGuarded()
	w.Table.Limits = nil
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 300}, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func assetScalarGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	rule := ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)
	rule.Guard, rule.Threshold = policy.GuardAboveAmount, 500
	w.Table.Rules = append(w.Table.Rules, rule)
	w.Table.Limits = nil
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 300}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func delegate2() ringpolicy.World {
	return ringpolicy.Delegate(transaction.Shape{NInputs: 2, NOutputs: 2})
}

// policyKeys lists every member key and the delegate key of each ring authority width, with the honest world it solves.
func policyKeys() []policyKey {
	budget := func(limit, outputs int) int {
		if outputs > 4 {
			return 0
		}
		return limit
	}
	var keys []policyKey
	for _, outputs := range policy.MemberOutputs {
		keys = append(keys, policyKey{
			name:    memberKeyName(outputs),
			budget:  budget(memberBudget, outputs),
			circuit: member(outputs),
			honest:  ringpolicy.MemberWorlds[outputs],
		})
	}
	for _, width := range delegateWidths {
		shape := transaction.Shape{NInputs: width, NOutputs: width}
		keys = append(keys, policyKey{
			name:    fmt.Sprintf("custom_ring_policy_delegate_v3_%dx%d_curator", width, width),
			budget:  budget(delegateBudget, width),
			circuit: delegate(shape),
			honest:  func() ringpolicy.World { return ringpolicy.Delegate(shape) },
		})
	}
	return keys
}

func memberKeyName(outputs int) string {
	return fmt.Sprintf("custom_ring_policy_member_v3_%d_w0_curator", outputs)
}

func member(outputs int) func() (frontend.Circuit, error) {
	return func() (frontend.Circuit, error) {
		return policy.NewMemberPolicyCircuit(policy.MemberShape{Outputs: outputs})
	}
}

func delegate(shape transaction.Shape) func() (frontend.Circuit, error) {
	return func() (frontend.Circuit, error) {
		return policy.NewDelegatePolicyCircuit(policy.DelegateShape{Shape: shape})
	}
}

func requireCompiledSolved(t *testing.T, cs constraint.ConstraintSystem, b ringpolicy.Witness) {
	t.Helper()
	witness, err := frontend.NewWitness(b.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

func requireSolved(t *testing.T, b ringpolicy.Witness) {
	t.Helper()
	if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

var compiledKeys sync.Map

func compiled(t *testing.T, name string, circuit func() (frontend.Circuit, error)) constraint.ConstraintSystem {
	t.Helper()
	if cs, ok := compiledKeys.Load(name); ok {
		return cs.(constraint.ConstraintSystem)
	}
	c, err := circuit()
	if err != nil {
		t.Fatal(err)
	}
	cs := ringkey.Compile(t, c)
	compiledKeys.Store(name, cs)
	return cs
}

// requireForgeryRefused solves the honest 2-output member witness with every call of hint forged, a constraint must refuse it.
func requireForgeryRefused(t *testing.T, hint solver.Hint, forge func(q *big.Int, in, out []*big.Int)) {
	cs := compiled(t, memberKeyName(2), member(2))
	witness, err := frontend.NewWitness(ringpolicy.Confidential().Build(t).Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	var forged atomic.Bool
	err = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(hint), func(q *big.Int, in, out []*big.Int) error {
		if err := hint(q, in, out); err != nil {
			return err
		}
		forge(q, in, out)
		forged.Store(true)
		return nil
	}), hintattack.SkipMissingLookupQueries(t))
	if !forged.Load() {
		t.Fatal("the forgery never ran")
	}
	hintattack.RequireConstraintRejection(t, err)
}

func TestMintThresholdsAndOutflowHaveNoEightRecordLimit(t *testing.T) {
	world := func() ringpolicy.World {
		w := assetGuarded()
		w.Table.Inline = nil
		w.Table.Limits = nil
		for i := int64(0); i < 12; i++ {
			asset := int64(3000) + i
			w.Table.Inline = append(w.Table.Inline, ringpolicy.InlineLimit{Asset: asset, Limit: 500})
			w.Table.Limits = append(w.Table.Limits, ringpolicy.OutflowLimit{Asset: asset, Cap: 1000, CosignAbove: 500})
		}
		for i := range w.Slots {
			w.Slots[i].Asset = 3009
		}
		return w
	}
	requireSolved(t, world().Build(t))
	t.Run("ninth threshold still enforces lists", func(t *testing.T) {
		w := world()
		w.Slots[0].Amount = 501
		w.ApprovalRequired = true
		b := w.Build(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("unlisted recipient above threshold admitted")
		}
	})
	t.Run("public-only mint cannot omit its cap", func(t *testing.T) {
		w := world()
		w.Public = []ringpolicy.PublicSlot{{Asset: 3011, Amount: -1001}}
		w.ApprovalRequired = true
		b := w.Build(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("twelfth mint's cap ignored")
		}
	})
	t.Run("public-only mint requires co-sign approval", func(t *testing.T) {
		w := world()
		w.Public = []ringpolicy.PublicSlot{{Asset: 3011, Amount: -501}}
		w.ApprovalRequired = true
		requireSolved(t, w.Build(t))
		w.ApprovalRequired = false
		b := w.Build(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("twelfth mint's co-sign threshold ignored")
		}
	})
	t.Run("settings cannot be forged", func(t *testing.T) {
		b := world().Build(t)
		b.OwnRecord(b.Member.AssetEntries[0]).MintPolicy = 0
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("forged settings admitted")
		}
	})
}
