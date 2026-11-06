// Solves every key on the signer and hidden rails, and refuses the composed statement's input and output predicates, the delegate bypass and every bound element.

package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var (
	confidential2 = transfer.Shape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4}
	wideOwners2   = transfer.Shape{Inputs: 24, Outputs: 8, Withdrawals: 32, Owners: 13, Wide: true}
	dataKey2      = confidential2
	confEntry2    = transfer.Shape{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true}
	anonymous2    = confidential2
	anonData2     = confidential2
	entry2        = confEntry2
	coOwner       = big.NewInt(0x0c0c)
	otherOwner    = big.NewInt(0x0d0d)
)

func requireSolved(t *testing.T, circuit frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func refused(t *testing.T, circuit frontend.Circuit, frames ...string) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()), frames...)
}

func onRail(shape transfer.Shape, rail ringtransfer.Rail) ringtransfer.Confidential {
	w := ringtransfer.Signed(shape)
	w.Rail = rail
	return w
}

func onAnonymous(shape transfer.Shape, rail ringtransfer.AnonymousRail) ringtransfer.Anonymous {
	w := ringtransfer.Hidden(shape)
	w.Rail = rail
	return w
}

func plain(w ringtransfer.World) ringtransfer.World {
	w.Policy = ringtransfer.Policy{}
	return w
}

func zeroKeyNote(t testing.TB, owner *big.Int, ring *big.Int, amount uint64, blinding int64) ringaudit.Input {
	t.Helper()
	return ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, owner, shared.ZeroNullifierPk, ring, amount, blinding)}
}

func ringID(t testing.TB) *big.Int {
	t.Helper()
	return ringaudit.NewAudit(t, audit.StreamShape{InputClass: 24, Outputs: 2}).RingProgramID
}

func senderNote(t testing.TB, blinding int64) ringaudit.Input {
	t.Helper()
	return ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ringID(t), 100, blinding), OwnerKey: ringtransfer.SenderKey(), Mint: ringaudit.FixtureMint}
}

// Every rail solves its honest witness and binds the public input.
func TestRailsSolve(t *testing.T) {
	inProof := onRail(confidential2, ringtransfer.InProof)
	coOwned := ringtransfer.Signed(confidential2)
	coOwned.CoOwners = []*big.Int{coOwner}
	inProofCoOwned := onRail(confidential2, ringtransfer.InProof)
	inProofCoOwned.CoOwners = []*big.Int{coOwner}
	plainSigner := ringtransfer.Signed(confidential2)
	plainSigner.World = plain(plainSigner.World)
	for name, b := range map[string]func(t *testing.T) frontend.Circuit{
		"signer":                   func(t *testing.T) frontend.Circuit { return ringtransfer.Signed(confidential2).Build(t).Circuit },
		"signer with a co-owner":   func(t *testing.T) frontend.Circuit { return coOwned.Build(t).Circuit },
		"in-proof":                 func(t *testing.T) frontend.Circuit { return inProof.Build(t).Circuit },
		"in-proof beside a signer": func(t *testing.T) frontend.Circuit { return inProofCoOwned.Build(t).Circuit },
		"delegate": func(t *testing.T) frontend.Circuit {
			return onRail(confidential2, ringtransfer.Delegate).Build(t).Circuit
		},
		"plain ring":    func(t *testing.T) frontend.Circuit { return plainSigner.Build(t).Circuit },
		"hidden sender": func(t *testing.T) frontend.Circuit { return ringtransfer.Hidden(anonymous2).Build(t).Circuit },
		"public owners": func(t *testing.T) frontend.Circuit {
			return onAnonymous(anonymous2, ringtransfer.PublicOwners).Build(t).Circuit
		},
		"anonymous delegate": func(t *testing.T) frontend.Circuit {
			return onAnonymous(anonymous2, ringtransfer.AnonymousDelegate).Build(t).Circuit
		},
	} {
		t.Run(name, func(t *testing.T) {
			circuit := b(t)
			ringtest.RequirePublicInputBound(t, circuit, circuit)
		})
	}
}

// Every base shape solves at each owner capacity.
func TestEveryKeySolves(t *testing.T) {
	if testing.Short() {
		t.Skip("solves every catalog key")
	}
	for _, shape := range transfer.Shapes {
		t.Run(shape.String()+"/signer", func(t *testing.T) {
			w := ringtransfer.Signed(shape)
			w.DefaultInput = shape.Entry
			requireSolved(t, w.Build(t).Circuit)
		})
		if shape.SingleAssetPayout {
			continue
		}
		t.Run(shape.String()+"/hidden", func(t *testing.T) {
			w := ringtransfer.Hidden(shape)
			w.DefaultInput = shape.Entry && shape.Inputs > 2
			requireSolved(t, w.Build(t).Circuit)
		})
	}
}

// Every key compiles with one public input and one BSB22 commitment over private wires.
func TestCatalogCompilesToTheVerifiedShape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the transfer keys")
	}
	compile := func(name string, build func() (frontend.Circuit, error)) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			circuit, err := build()
			if err != nil {
				t.Fatal(err)
			}
			cs := ringkey.Compile(t, circuit)
			t.Logf("%s: %d constraints", name, cs.GetNbConstraints())
			if public := cs.GetNbPublicVariables() - 1; public != 1 {
				t.Errorf("%d public inputs, the program verifies one", public)
			}
		})
	}
	for _, shape := range transfer.Shapes {
		compile(shape.String(), func() (frontend.Circuit, error) { return transfer.NewTransferCircuit(shape) })
	}
}

// A live input stays under its enrolled key on every rail.
func TestInputPredicateOnEveryRail(t *testing.T) {
	// The witness swaps input 0's key after the world enrolled the honest one.
	wrongKey := spptest.MustNullifierPk(t, big.NewInt(99))
	mutate := func(w ringtransfer.World) ringtransfer.World {
		w.Enrolled = map[string]*big.Int{ringtransfer.Sender(t).String(): wrongKey}
		return w
	}
	unenrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Unenrolled = []*big.Int{ringtransfer.Sender(t)}
		return w
	}
	frame := "transfer.OwnerRows.AssertInputOwners"
	for _, tc := range []struct {
		name  string
		world func(ringtransfer.World) ringtransfer.World
	}{{"a key other than the registered one", mutate}, {"a nonzero key with no row", unenrolled}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
				w := onRail(confidential2, rail)
				w.World = tc.world(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
				w := onAnonymous(anonymous2, rail)
				w.World = tc.world(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			entry := ringtransfer.Signed(confEntry2)
			entry.World = tc.world(entry.World)
			refused(t, entry.Build(t).Circuit, frame)
		})
	}
}

// A zero key reads no row key, the spend path decides who may use it.
func TestZeroKeyInputs(t *testing.T) {
	ring := ringID(t)
	sender := ringtransfer.Sender(t)
	t.Run("a public signer spends it", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("the public owner rail spends it with recipients unpublished", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a hidden sender's own is refused", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		refused(t, w.Build(t).Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
	t.Run("a public co-owner's beside a hidden sender", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner}
		w.Inputs = []ringaudit.Input{senderNote(t, 51), zeroKeyNote(t, coOwner, ring, 100, 52)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an anonymous delegate moves one in slot 0 with no row", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		b := w.Build(t)
		if ringtest.AsBigInt(b.Circuit.Rows[0]).Sign() != 0 {
			t.Fatal("the delegate's zero key opened a row")
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("a zero key needs a row off the delegate rail", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		b := w.Build(t)
		b.Circuit.Rows[0] = 0
		b.Refill(t)
		refused(t, b.Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
}

// No wire names the delegate's identity, its own note and another's solve alike.
func TestDelegateInputOwners(t *testing.T) {
	ring := ringID(t)
	owner := big.NewInt(0x0a11ce)
	other := big.NewInt(0x0b0b)
	key := big.NewInt(0x77)
	keyed := func(t testing.TB, holder *big.Int, blinding int64) ringaudit.Input {
		t.Helper()
		return ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, holder, key, ring, 100, blinding)}
	}
	rails := map[string]func(t *testing.T, inputs []ringaudit.Input) frontend.Circuit{
		"confidential": func(t *testing.T, inputs []ringaudit.Input) frontend.Circuit {
			w := onRail(confidential2, ringtransfer.Delegate)
			w.Inputs = inputs
			return w.Build(t).Circuit
		},
		"anonymous": func(t *testing.T, inputs []ringaudit.Input) frontend.Circuit {
			w := onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)
			w.Inputs = inputs
			return w.Build(t).Circuit
		},
	}
	for name, build := range rails {
		t.Run(name, func(t *testing.T) {
			t.Run("one owner", func(t *testing.T) {
				requireSolved(t, build(t, []ringaudit.Input{keyed(t, owner, 51)}))
			})
			t.Run("two owners", func(t *testing.T) {
				requireSolved(t, build(t, []ringaudit.Input{keyed(t, owner, 51), keyed(t, other, 52)}))
			})
			t.Run("a keyed owner beside a zero key note", func(t *testing.T) {
				requireSolved(t, build(t, []ringaudit.Input{keyed(t, owner, 51), zeroKeyNote(t, other, ring, 100, 52)}))
			})
		})
	}
	t.Run("a note off its tracking key", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.Inputs = []ringaudit.Input{keyed(t, owner, 51), keyed(t, other, 52)}
		w.Enrolled = map[string]*big.Int{other.String(): big.NewInt(0x78)}
		refused(t, w.Build(t).Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
}

// The authority rail reads no policy and keeps every auditor check.
func TestDelegateBypass(t *testing.T) {
	frozen := func(w ringtransfer.World) ringtransfer.World {
		w.Policy.Frozen = true
		return w
	}
	t.Run("moves a frozen owner's note", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.World = frozen(w.World)
		requireSolved(t, w.Build(t).Circuit)
		anon := onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)
		anon.World = frozen(anon.World)
		requireSolved(t, anon.Build(t).Circuit)
	})
	t.Run("withdraws with empty legs and pays no threshold", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.Policy.Cap, w.Policy.CosignAbove, w.Policy.WithdrawalThreshold = 1, 1, 1
		w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -500, Gross: 500}}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("exits with the owner published by SPP", func(t *testing.T) {
		shape := transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4}
		requireSolved(t, onAnonymous(shape, ringtransfer.AnonymousDelegate).Build(t).Circuit)
	})
	t.Run("several victims move in one transfer", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.CoOwners = []*big.Int{coOwner}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("the statement holds every policy root at zero", func(t *testing.T) {
		for name, set := range map[string]func(*policy.Policy){
			"policy hash":  func(p *policy.Policy) { p.PolicyHash = 7 },
			"own root":     func(p *policy.Policy) { p.OwnRoot = 7 },
			"curator root": func(p *policy.Policy) { p.CuratorRoot = 7 },
		} {
			t.Run(name, func(t *testing.T) {
				b := onRail(confidential2, ringtransfer.Delegate).Build(t)
				set(&b.Circuit.Policy)
				b.Rebind(t)
				refused(t, b.Circuit, "transfer.(*Sections).assertBypass")
			})
		}
	})
	t.Run("a mask on the authority rail", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.ApprovalMask = policy.ApprovalOutflow
		refused(t, w.Build(t).Circuit, "transfer.(*TransferCircuit).Define")
	})
	t.Run("a run on the authority rail", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = []*big.Int{b.Sender}, 1, b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*TransferCircuit).Define")
	})
	t.Run("an output still reads its row", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.Unenrolled = []*big.Int{ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 1, 1, 1).OwnerKey)}
		refused(t, w.Build(t).Circuit, "transfer.AssertOutputOwners")
	})
}

// The output predicate binds a live ring output on every rail, an exit keeps its own exception.
func TestOutputPredicateOnEveryRail(t *testing.T) {
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 1, 1, 1).OwnerKey)
	frame := "transfer.AssertOutputOwners"
	unenrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Unenrolled = []*big.Int{recipient}
		return w
	}
	zeroToEnrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) {
			slot.OwnerKey = ringtransfer.SenderKey()
			slot.Utxo.OwnerPkHash, slot.Utxo.NullifierPk = ringtransfer.Sender(t), shared.ZeroNullifierPk
		}}
		return w
	}
	t.Run("a nonzero key with no row", func(t *testing.T) {
		for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
			w := onRail(confidential2, rail)
			w.World = unenrolled(w.World)
			refused(t, w.Build(t).Circuit, frame)
		}
		for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
			w := onAnonymous(anonymous2, rail)
			w.World = unenrolled(w.World)
			refused(t, w.Build(t).Circuit, frame)
		}
	})
	// The delegate rails screen nothing and read no salted payee.
	t.Run("a zero key under a row", func(t *testing.T) {
		for _, salted := range []bool{false, true} {
			mutate := func(w ringtransfer.World) ringtransfer.World {
				w = zeroToEnrolled(w)
				if salted {
					w.SaltedBlock = []*big.Int{}
				}
				return w
			}
			for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
				w := onRail(confidential2, rail)
				w.World = mutate(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
				w := onAnonymous(anonymous2, rail)
				w.World = mutate(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
		}
	})
	t.Run("a zero key to an owner with no row", func(t *testing.T) {
		zeroToAbsent := func(w ringtransfer.World) ringtransfer.World {
			w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) { slot.Utxo.NullifierPk = shared.ZeroNullifierPk }}
			return w
		}
		for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
			w := onRail(confidential2, rail)
			w.World = zeroToAbsent(w.World)
			requireSolved(t, w.Build(t).Circuit)
		}
		for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
			w := onAnonymous(anonymous2, rail)
			w.World = zeroToAbsent(w.World)
			requireSolved(t, w.Build(t).Circuit)
		}
	})
	t.Run("an exit to an owner with no row", func(t *testing.T) {
		w := ringtransfer.Signed(transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4})
		requireSolved(t, w.Build(t).Circuit)
	})
}

// The program sets the delegate bit and the signer and delegate rails share a key, a signer proof with the bit set is the wall.
func TestDelegateBitIsTheProgramsWall(t *testing.T) {
	circuit, err := transfer.NewTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	honest := ringtransfer.Signed(confidential2).Build(t)
	bound := ringkey.Bind(t, circuit, honest.Circuit)
	statement := honest.Statement(t)
	forged := onRail(confidential2, ringtransfer.Delegate).Build(t)
	forged.Circuit.PublicInputHash = spptest.MustHashChain4(t, statement)
	bound.RefuseStatement(t, forged.Circuit, statement)
	// The bit moves the same statement cell the program writes.
	moved := ringtransfer.Signed(confidential2).Build(t)
	moved.Circuit.Delegate, moved.Circuit.SignerCount, moved.Circuit.Signers[0] = 1, 0, 0
	moved.Circuit.PolicyHash, moved.Circuit.OwnRoot, moved.Circuit.CuratorRoot = 0, 0, 0
	moved.Run = nil
	moved.Circuit.PublicInputHash = spptest.MustHashChain4(t, statement)
	if bound.Solve(t, moved.Circuit) == nil {
		t.Fatal("a signer statement admitted the delegate bit")
	}
}

// The public owner rail has no hidden sender, the hidden rail keeps input 0 out of the run.
func TestAnonymousOwnerRails(t *testing.T) {
	t.Run("bits exclude each other", func(t *testing.T) {
		b := ringtransfer.Hidden(anonymous2).Build(t)
		b.Circuit.Delegate = 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*TransferCircuit).assertRail")
	})
	t.Run("a hidden frame with no live input", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.PublicFunded = true
		refused(t, w.Build(t).Circuit, "transfer.(*TransferCircuit).hiddenOwner")
	})
	t.Run("public owners spend no input", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		w.PublicFunded = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a hidden sender inside the run", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = []*big.Int{b.Sender}, 1, b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*TransferCircuit).hiddenOwner")
	})
	t.Run("a public owner rail input off the run", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = nil, 0, 0
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.SignerSet.AssertOwners")
	})
	for slot := range shared.AnonymousParties {
		t.Run("a hidden sender as a party", func(t *testing.T) {
			b := ringtransfer.Hidden(anonymous2).Build(t)
			b.Circuit.PartyIdentities[slot] = b.Sender
			b.Rebind(t)
			refused(t, b.Circuit, "shared.AssertAnonymousParties")
		})
	}
}

// Every owner opens a row, any rail, up to the key's capacity.
func TestOwnerCapacity(t *testing.T) {
	owners := func(n int) []*big.Int {
		out := make([]*big.Int, n)
		for i := range out {
			out[i] = big.NewInt(0x1000 + int64(i))
		}
		return out
	}
	policied := func(w ringtransfer.World, n int) ringtransfer.World {
		w.CoOwners = owners(n)
		return w
	}
	t.Run("four and thirteen owners, plain and policy", func(t *testing.T) {
		for _, n := range []int{3, 12} {
			shape := confidential2
			if n > 3 {
				shape = wideOwners2
			}
			w := ringtransfer.Signed(shape)
			w.World = policied(w.World, n)
			requireSolved(t, w.Build(t).Circuit)
			w.World = plain(w.World)
			w.World = policied(w.World, n)
			requireSolved(t, w.Build(t).Circuit)
		}
	})
	t.Run("a subject past the key's rows fails closed", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.World = policied(w.World, 4)
		refused(t, w.Build(t).Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
	t.Run("rows out of order", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner, otherOwner}
		b := w.Build(t)
		b.Circuit.Rows[0], b.Circuit.Rows[1] = b.Circuit.Rows[1], b.Circuit.Rows[0]
		b.Refill(t)
		refused(t, b.Circuit, "policy.assertRowsAscending")
	})
	t.Run("a co-owner on a frozen list screens through its row", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners, w.FrozenCoOwner = []*big.Int{coOwner}, true
		refused(t, w.Build(t).Circuit, "policy.assertSenderRules")
	})
	t.Run("a hidden sender and public co-owners", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner, otherOwner, big.NewInt(0x0e0e)}
		requireSolved(t, w.Build(t).Circuit)
	})
}

// An entry key spends default-ring notes beside ring notes under different owners.
func TestEntry(t *testing.T) {
	ring := ringID(t)
	defaultOwnerKey := ringtest.Repeat(0xa2)
	defaultOwner := ringtest.MustSolanaPkField(t, defaultOwnerKey)
	defaultNote := ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, defaultOwner, spptest.MustNullifierPk(t, big.NewInt(8)), big.NewInt(0), 70, 53), OwnerKey: defaultOwnerKey, Mint: ringaudit.FixtureMint}
	ringNote := ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ring, 100, 51), OwnerKey: ringtransfer.SenderKey(), Mint: ringaudit.FixtureMint}
	t.Run("a public default owner beside a hidden ring sender", func(t *testing.T) {
		w := ringtransfer.Hidden(entry2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a confidential rail spends both", func(t *testing.T) {
		w := ringtransfer.Signed(confEntry2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a default owner off the run", func(t *testing.T) {
		w := ringtransfer.Signed(confEntry2)
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		refused(t, w.Build(t).Circuit, "transfer.SignerSet.AssertOwners")
	})
	t.Run("a default note on a key with no entry capacity", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		refused(t, w.Build(t).Circuit, "transfer.InputSection.AssertRingNotes")
	})
	t.Run("a note of another ring on an entry key", func(t *testing.T) {
		other := ringNote
		other.Utxo.RingProgramID = big.NewInt(0x5151)
		w := ringtransfer.Signed(confEntry2)
		w.Inputs = []ringaudit.Input{other}
		refused(t, w.Build(t).Circuit, "transfer.InputSection.AssertRingNotes")
	})
}

// A data output settles and the records open it.
func TestDataOutputs(t *testing.T) {
	t.Run("a confidential rail", func(t *testing.T) {
		w := ringtransfer.Signed(dataKey2)
		w.HasData = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an anonymous rail", func(t *testing.T) {
		w := ringtransfer.Hidden(anonData2)
		w.HasData = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("the bit clear pays no tails", func(t *testing.T) {
		requireSolved(t, ringtransfer.Signed(dataKey2).Build(t).Circuit)
	})
}

// Dummies stay last and an input past the published count opens nothing.
func TestInputOrder(t *testing.T) {
	sender := ringtransfer.Sender(t)
	nk := ringtransfer.SenderNullifierPk(t)
	ring := ringID(t)
	t.Run("a dummy between spent inputs", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{
			{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)},
			{Utxo: ringaudit.SpareInput(1)},
			{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 60, 52)},
		}
		refused(t, w.Build(t).Circuit, "transfer.OpenInputs")
	})
	t.Run("a note past the published count", func(t *testing.T) {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Audit.InputCount, b.Circuit.InputCount = 1, 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.OpenInputs")
	})
}

func TestAddressSlots(t *testing.T) {
	sender, nk, ring := ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ringID(t)
	addressSlot := func() ringaudit.Input {
		slot := ringaudit.SpareInput(1)
		slot.Domain, slot.OwnerPkHash = transaction.AddressDomain, sender
		return ringaudit.Input{Utxo: slot}
	}
	world := func(t *testing.T) ringtransfer.Confidential {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)}, addressSlot()}
		return w
	}
	t.Run("beside a spent note", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.InputNullifiers[1] = 0x77
		b.Rehash(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("the chain binds the transaction hash", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.InputNullifiers[1] = 0x77
		b.Rehash(t)
		privateTxHash := b.Circuit.PrivateTxHash
		b.Circuit.InputNullifiers[1] = 0x78
		b.Rehash(t)
		b.Circuit.PrivateTxHash = privateTxHash
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.transactionBinding.bindTransaction")
	})
	t.Run("a note called an address leaves the input chain SPP hashed", func(t *testing.T) {
		w := world(t)
		w.Inputs[1] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 60, 52)}
		b := w.Build(t)
		spent := b.Circuit.PrivateTxHash
		b.Circuit.Inputs[1].Domain = transaction.AddressDomain
		b.Circuit.PrivateTxHash = spent
		refused(t, b.Circuit, "transfer.transactionBinding.bindTransaction")
	})
	t.Run("a note after an address", func(t *testing.T) {
		w := world(t)
		w.Inputs = []ringaudit.Input{addressSlot(), {Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)}}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an unknown domain", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.Inputs[1].Domain = 9
		refused(t, b.Circuit, "shared.UtxoWires.OpenInput")
	})
}

// The in-proof rail alone names a public sender.
func TestRailCells(t *testing.T) {
	t.Run("a signer rail sender", func(t *testing.T) {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Circuit.Sender = b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*TransferCircuit).assertRail")
	})
	t.Run("a delegate with in_proof", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Circuit.InProof = 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*TransferCircuit).assertRail")
	})
	t.Run("an in-proof input of another owner", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.InProof)
		w.Inputs = []ringaudit.Input{{Utxo: ringaudit.SpentUtxo(t, coOwner, ringtransfer.CoOwnerKey(t, coOwner), ringID(t), 100, 51)}}
		refused(t, w.Build(t).Circuit, "transfer.SignerSet.AssertOwners")
	})
}

func TestSaltedList(t *testing.T) {
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 0, 0, 1).OwnerKey)
	world := func(blocked ...*big.Int) ringtransfer.Confidential {
		w := ringtransfer.Signed(confidential2)
		w.SaltedBlock = append([]*big.Int{}, blocked...)
		return w
	}
	t.Run("an owner with no curator action passes by absence", func(t *testing.T) {
		requireSolved(t, world().Build(t).Circuit)
	})
	t.Run("a privately blocked owner fails the rule", func(t *testing.T) {
		refused(t, world(recipient).Build(t).Circuit, "policy.assertPaymentRules")
	})
	t.Run("an enrolled owner under another salt fails the tag", func(t *testing.T) {
		b := world().Build(t)
		b.Circuit.OwnerEntries[0].ListSalt = big.NewInt(0x1234)
		refused(t, b.Circuit, "policy.(*Policy).resolveSubjects")
	})
	t.Run("an unenrolled owner reads no salted list", func(t *testing.T) {
		w := world(recipient)
		w.Unenrolled = []*big.Int{recipient}
		w.Outputs = map[int]func(*ringaudit.Slot){0: func(slot *ringaudit.Slot) { slot.Utxo.NullifierPk = shared.ZeroNullifierPk }}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a delegate reads no salted list", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.SaltedBlock = []*big.Int{recipient}
		requireSolved(t, w.Build(t).Circuit)
	})
}

// A count below the live notes leaves one past it.
func Test40InputsOnTheWideKey(t *testing.T) {
	shape := transfer.Shape{Inputs: 40, Outputs: 2, Withdrawals: 4, Owners: 8, Wide: true}
	w := ringtransfer.Signed(shape)
	sender, key, ring := ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ringID(t)
	w.Inputs = make([]ringaudit.Input, 40)
	for i := range w.Inputs {
		amount := uint64(4)
		if i == 39 {
			amount = 8
		}
		w.Inputs[i] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, key, ring, amount, int64(51+i)), OwnerKey: ringtransfer.SenderKey()}
	}
	built := w.Build(t)
	requireSolved(t, built.Circuit)
	built.Circuit.InputCount = 39
	refused(t, built.Circuit, "transfer.OpenInputs")
}

// A count below the live notes leaves one past it.
func Test8DefaultNotesOnTheWideEntryKey(t *testing.T) {
	shape := transfer.Shape{Inputs: 8, Outputs: 8, Withdrawals: 32, Owners: 8, Entry: true, Wide: true}
	w := ringtransfer.Signed(shape)
	sender, key := ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t)
	w.Inputs = make([]ringaudit.Input, 8)
	for i := range w.Inputs {
		amount := uint64(4)
		if i == 7 {
			amount = 8
		}
		w.Inputs[i] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, key, big.NewInt(0), amount, int64(51+i)), OwnerKey: ringtransfer.SenderKey(), Mint: ringaudit.FixtureMint}
	}
	built := w.Build(t)
	requireSolved(t, built.Circuit)
	built.Circuit.InputCount = 7
	refused(t, built.Circuit, "transfer.OpenInputs")
}

// A statement cell moves the public input alone.
func TestStatementBindsEveryElement(t *testing.T) {
	if testing.Short() {
		t.Skip("solves the compiled key once per statement element")
	}
	circuit, err := transfer.NewTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	b := ringtransfer.Signed(confidential2).Build(t)
	bound := ringkey.Bind(t, circuit, b.Circuit)
	statement := b.Statement(t)
	for i := range statement {
		moved := append([]*big.Int{}, statement...)
		moved[i] = new(big.Int).Add(moved[i], big.NewInt(1))
		bound.RefuseStatement(t, b.Circuit, moved)
	}
}

// A key with no tracking rows for its legs always has the wide key to move to.
func TestNarrowKeysFitTheWideKey(t *testing.T) {
	var wide transfer.Shape
	for _, shape := range transfer.Shapes {
		if shape.Withdrawals > wide.Withdrawals {
			wide = shape
		}
	}
	for _, shape := range transfer.Shapes {
		if !shape.Wide && shape.Withdrawals == 4 && (shape.Inputs > wide.Inputs || shape.Outputs > wide.Outputs || shape.Owners > wide.Owners) {
			t.Errorf("%s does not fit the wide key %s", shape, wide)
		}
	}
}

// The digest binds the proved totals on the key, with one owner a peak and a total of the same debit.
func TestApprovalTotalsReachTheStatement(t *testing.T) {
	w := onRail(confidential2, ringtransfer.Signer)
	w.Policy = ringtransfer.Policy{OwnRegistry: true}
	layout := func(b ringtransfer.Built) []*big.Int {
		held, returned := new(big.Int), new(big.Int)
		for _, input := range b.Circuit.Inputs {
			if ringtest.AsBigInt(input.Domain).Int64() == transaction.UtxoDomain {
				held.Add(held, ringtest.AsBigInt(input.Amount))
			}
		}
		fields := []*big.Int{}
		for _, slot := range b.Circuit.Outputs {
			if ringtest.AsBigInt(slot.Output.Domain).Int64() == transaction.UtxoDomain && ringtest.AsBigInt(slot.Output.OwnerPkHash).Cmp(ringtest.AsBigInt(b.Circuit.Rows[0])) == 0 {
				returned.Add(returned, ringtest.AsBigInt(slot.Output.Amount))
			}
		}
		debit := new(big.Int).Sub(held, returned)
		for _, slot := range b.Circuit.Outputs {
			fields = append(fields, ringtest.AsBigInt(slot.Output.Asset), debit, debit)
		}
		for range transaction.NPublicSlots {
			fields = append(fields, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
		}
		return fields
	}
	disclose := func(b ringtransfer.Built, fields []*big.Int) {
		blinder := big.NewInt(0x51)
		b.Circuit.ApprovalBlinder = blinder
		b.Circuit.ApprovalTotals = spptest.MustHashChain4(t, append([]*big.Int{big.NewInt(shared.ApprovalTotalsDomain), blinder}, fields...))
		b.Rebind(t)
	}
	honest := w.Build(t)
	disclose(honest, layout(honest))
	requireSolved(t, honest.Circuit)
	forged := w.Build(t)
	fields := layout(forged)
	fields[1] = new(big.Int).Sub(fields[1], big.NewInt(1))
	disclose(forged, fields)
	refused(t, forged.Circuit, "policy.Screening.AssertApprovalTotals")
}

// comparator.go's width rests on the bound, a sum of 64 u64 amounts stays below 2^70.
func TestKeysHoldTheAmountBound(t *testing.T) {
	const bound = 64
	for _, shape := range transfer.Shapes {
		if shape.Inputs >= bound || shape.Outputs+shape.Withdrawals >= bound {
			t.Fatalf("%s passes the amount bound", shape)
		}
	}
}
