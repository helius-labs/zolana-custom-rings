// Composes the ring proof with SPP's blinding checks, the only checks on a published output blinding.

package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// sppBlindings runs steps 2 and 4 of SPP's Transaction.Constrain through SPP's own helpers over the published outputs.
type sppBlindings struct {
	PrivateTxHash     frontend.Variable
	OutputHashes      []frontend.Variable
	FirstNullifier    frontend.Variable
	BlindingSeed      frontend.Variable
	OutputTreeID      frontend.Variable
	Outputs           []transaction.UtxoCircuitFields
	InputHashes       []frontend.Variable
	AddressNullifiers []frontend.Variable
}

func (c *sppBlindings) Define(api frontend.API) error {
	seed := transaction.DeriveOutputBlindingSeed(api, c.FirstNullifier, c.BlindingSeed)
	hashes := make([]frontend.Variable, len(c.Outputs))
	for i, output := range c.Outputs {
		api.AssertIsEqual(output.Blinding, transaction.DeriveOutputBlinding(api, c.FirstNullifier, seed, i))
		hashes[i] = transaction.ConstrainOutput(api, output, c.OutputHashes[i], 0, 1, c.OutputTreeID)
	}
	blinding := transaction.DerivePrivateTxBlinding(api, c.FirstNullifier, c.BlindingSeed)
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, c.InputHashes, hashes, c.AddressNullifiers, blinding))
	return nil
}

// composed is one ring witness with the frame values both proofs read.
type composed struct {
	circuit *transfer.TransferCircuit
	audit   ringaudit.Audit
	rebind  func(testing.TB)
}

func confidentialComposed(t testing.TB, w ringtransfer.Confidential) composed {
	b := w.Build(t)
	return composed{circuit: b.Circuit, audit: b.Audit, rebind: b.Rebind}
}

func anonymousComposed(t testing.TB, w ringtransfer.Anonymous) composed {
	b := w.Build(t)
	return composed{circuit: b.Circuit, audit: b.Audit, rebind: b.Rebind}
}

// spp is the SPP witness over the ring's published outputs and spent inputs at seed.
func (c composed) spp(t testing.TB, seed *big.Int) *sppBlindings {
	t.Helper()
	published := c.audit.Outputs[:c.audit.OutputCount()]
	s := &sppBlindings{
		FirstNullifier: c.audit.FirstNullifier, BlindingSeed: seed, OutputTreeID: int(ringaudit.OutputTreeID),
		OutputHashes: make([]frontend.Variable, len(published)), Outputs: make([]transaction.UtxoCircuitFields, len(published)),
		InputHashes: spptest.ToVariables(ringaudit.SpentHashes(t, c.audit.InputUtxos())), AddressNullifiers: c.addressNullifiers(),
	}
	for i, slot := range published {
		u := slot.Utxo
		s.OutputHashes[i] = u.Hash(t)
		s.Outputs[i] = transaction.UtxoCircuitFields{
			Domain: u.Domain, Owner: u.Owner(t), Asset: u.Asset, Amount: new(big.Int).SetUint64(u.Amount), Blinding: u.Blinding,
			DataHash: u.DataHash, RingDataHash: u.RingDataHash, RingProgramID: u.RingProgramID,
		}
	}
	s.PrivateTxHash = spptest.MustPrivateTxHash(t, ringaudit.SpentHashes(t, c.audit.InputUtxos()), hashesOf(s.OutputHashes, s.Outputs), ringtest.ToBigInts(s.AddressNullifiers), privateTxBlinding(t, c.audit.FirstNullifier, seed))
	return s
}

func (c composed) addressNullifiers() []frontend.Variable {
	nullifiers := make([]frontend.Variable, len(c.audit.Inputs))
	for i, input := range c.audit.Inputs {
		nullifiers[i] = 0
		if input.Utxo.Domain == protocol.AddressDomain {
			nullifiers[i] = c.circuit.InputNullifiers[i]
		}
	}
	return nullifiers
}

// hashesOf is the list SPP's private_tx_hash chains, a dummy's hash zeroed.
func hashesOf(hashes []frontend.Variable, outputs []transaction.UtxoCircuitFields) []*big.Int {
	chained := make([]*big.Int, len(hashes))
	for i, output := range outputs {
		chained[i] = new(big.Int)
		if ringtest.AsBigInt(output.Domain).Int64() == protocol.UtxoDomain {
			chained[i] = ringtest.AsBigInt(hashes[i])
		}
	}
	return chained
}

func privateTxBlinding(t testing.TB, firstNullifier, seed *big.Int) *big.Int {
	t.Helper()
	blinding, err := protocol.PrivateTxBlinding(firstNullifier, seed)
	return spptest.MustHash(t, blinding, err)
}

func sppSolves(t *testing.T, s *sppBlindings) error {
	t.Helper()
	return test.IsSolved(s, s, ecc.BN254.ScalarField())
}

func compositionCases(t *testing.T) map[string]func(*testing.T) composed {
	withExit := transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4}
	payout := ringtransfer.Signed(payoutShape)
	payout.SaltedBlock = []*big.Int{}
	allDummies := ringtransfer.Signed(confidential2)
	allDummies.AllDummies = true
	compact := ringtransfer.Signed(withExit)
	compact.Omitted = 1
	entry := ringtransfer.Signed(confEntry2)
	entry.DefaultInput = true
	data := ringtransfer.Signed(confidential2)
	data.HasData = true
	return map[string]func(*testing.T) composed{
		"signer": func(t *testing.T) composed { return confidentialComposed(t, ringtransfer.Signed(confidential2)) },
		"in-proof": func(t *testing.T) composed {
			return confidentialComposed(t, onRail(confidential2, ringtransfer.InProof))
		},
		"delegate": func(t *testing.T) composed {
			return confidentialComposed(t, onRail(confidential2, ringtransfer.Delegate))
		},
		"delegate with an exit": func(t *testing.T) composed { return confidentialComposed(t, onRail(withExit, ringtransfer.Delegate)) },
		"hidden sender":         func(t *testing.T) composed { return anonymousComposed(t, ringtransfer.Hidden(anonymous2)) },
		"public owners": func(t *testing.T) composed {
			return anonymousComposed(t, onAnonymous(anonymous2, ringtransfer.PublicOwners))
		},
		"anonymous delegate": func(t *testing.T) composed {
			return anonymousComposed(t, onAnonymous(anonymous2, ringtransfer.AnonymousDelegate))
		},
		"entry":                  func(t *testing.T) composed { return confidentialComposed(t, entry) },
		"data-bearing output":    func(t *testing.T) composed { return confidentialComposed(t, data) },
		"payout":                 func(t *testing.T) composed { return confidentialComposed(t, payout) },
		"published dummies only": func(t *testing.T) composed { return confidentialComposed(t, allDummies) },
		"deposit": func(t *testing.T) composed {
			b := signerDeposit(t, func(*ringtransfer.World) {})
			return composed{circuit: b.Circuit, audit: b.Audit, rebind: b.Rebind}
		},
		"compact frame": func(t *testing.T) composed { return confidentialComposed(t, compact) },
	}
}

// Every rail solves beside an SPP witness under the sealed key's seed on one private_tx_hash.
func TestSppSeedComposesOnEveryRail(t *testing.T) {
	for name, build := range compositionCases(t) {
		t.Run(name, func(t *testing.T) {
			c := build(t)
			s := c.spp(t, c.audit.Seed)
			if ringtest.AsBigInt(s.PrivateTxHash).Cmp(ringtest.AsBigInt(c.circuit.PrivateTxHash)) != 0 {
				t.Fatal("the two proofs open different private_tx_hash values")
			}
			requireSolved(t, c.circuit)
			if err := sppSolves(t, s); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// SPP accepts any seed, the ring's derived blinding refuses every seed but the sealed key's.
func TestRingRefusesAnotherSeed(t *testing.T) {
	for name, build := range compositionCases(t) {
		t.Run(name, func(t *testing.T) {
			other := build(t).audit.Transfer.WithUnrelatedKey(t)
			c := build(t)
			for i := range c.audit.Outputs[:c.audit.OutputCount()] {
				c.audit.Outputs[i].Utxo.Blinding = other.Blinding(t, i)
				c.circuit.Outputs[i] = c.audit.Outputs[i].Wires()
			}
			s := c.spp(t, other.Seed)
			if err := sppSolves(t, s); err != nil {
				t.Fatal(err)
			}
			c.circuit.PrivateTxHash = s.PrivateTxHash
			c.rebind(t)
			refused(t, c.circuit, "bindTransaction")
		})
	}
}

// A transaction blinding off TXPB(n0, CRBS(tx_viewing_sk, salt)) opens no private_tx_hash the ring proves.
func TestRingRefusesAnotherTransactionBlinding(t *testing.T) {
	c := confidentialComposed(t, ringtransfer.Signed(confidential2))
	s := c.spp(t, c.audit.Seed)
	c.circuit.PrivateTxHash = spptest.MustPrivateTxHash(t, ringaudit.SpentHashes(t, c.audit.InputUtxos()), hashesOf(s.OutputHashes, s.Outputs), ringtest.ToBigInts(s.AddressNullifiers), big.NewInt(0x5b1d))
	c.rebind(t)
	refused(t, c.circuit, "bindTransaction")
}

// The ring proof solves with a changed output blinding, SPP's derivation refuses it.
func TestSppRefusesAChangedOutputBlinding(t *testing.T) {
	withExit := transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4}
	for name, slot := range map[string]int{"ring note": 0, "exit": 2, "dummy": 3} {
		t.Run(name, func(t *testing.T) {
			w := ringtransfer.Signed(withExit)
			if slot == 3 {
				w.Outputs = map[int]func(*ringaudit.Slot){3: func(s *ringaudit.Slot) { s.Utxo = ringaudit.Dummy(s.Utxo.TreeID, s.Utxo.Blinding) }}
			}
			honest := confidentialComposed(t, w)
			changed := ringaudit.Transfer.Blinding(honest.audit.Transfer, t, (slot+1)%len(honest.audit.Outputs))
			mutate := w.Outputs[slot]
			w.Outputs = map[int]func(*ringaudit.Slot){slot: func(s *ringaudit.Slot) {
				if mutate != nil {
					mutate(s)
				}
				s.Utxo.Blinding = changed
			}}
			c := confidentialComposed(t, w)
			requireSolved(t, c.circuit)
			ringtest.RequireRefused(t, sppSolves(t, c.spp(t, c.audit.Seed)), "sppBlindings")
		})
	}
}
