package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type AnonymousRail int

const (
	HiddenSender AnonymousRail = iota
	PublicOwners
	AnonymousDelegate
)

// Anonymous is one transfer of the anonymous family.
type Anonymous struct {
	World
	Shape transfer.Shape
	Rail  AnonymousRail
	// Parties are the co-signer cells, two co-signers by default.
	Parties []*big.Int
}

// BuiltAnonymous is an anonymous witness with the fixtures it was derived from.
type BuiltAnonymous struct {
	Assembled
	Circuit *transfer.TransferCircuit
	World   Anonymous
}

// Hidden is a policy ring transfer of shape on the anonymous rail.
func Hidden(shape transfer.Shape) Anonymous {
	return Anonymous{Shape: shape, Rail: HiddenSender, World: World{Policy: Policy{Screened: true, Cap: 1_000_000, CosignAbove: 500_000, WithdrawalThreshold: 100_000}}, Parties: []*big.Int{big.NewInt(11), big.NewInt(12)}}
}

func (w Anonymous) Build(t testing.TB) BuiltAnonymous {
	t.Helper()
	c, err := transfer.NewTransferCircuit(w.Shape)
	if err != nil {
		t.Fatal(err)
	}
	a := w.newAudit(t, w.Shape.Stream())
	var run []*big.Int
	switch w.Rail {
	case HiddenSender:
		run = w.CoOwners
	case PublicOwners:
		run = append([]*big.Int{Sender(t)}, w.CoOwners...)
	}
	c.InProof, c.Hidden, c.Delegate, c.Sender = 0, ringtest.Bit(w.Rail == HiddenSender), ringtest.Bit(w.Rail == AnonymousDelegate), 0
	for i := range c.PartyIdentities {
		c.PartyIdentities[i] = 0
		if i < len(w.Parties) {
			c.PartyIdentities[i] = w.Parties[i]
		}
	}
	b := BuiltAnonymous{Circuit: c, World: w, Assembled: w.fill(t, &c.Sections, a, w.Rail == AnonymousDelegate, run)}
	b.Rehash(t)
	return b
}

// Rehash recomputes private_tx_hash from the fixture slots and inputs, then the public input.
func (b BuiltAnonymous) Rehash(t testing.TB) {
	t.Helper()
	b.World.World.rehash(t, &b.Circuit.Sections, b.Audit)
	b.Rebind(t)
}

// Rebind recomputes the public input after a statement value changes.
func (b BuiltAnonymous) Rebind(t testing.TB) {
	t.Helper()
	b.Circuit.WithdrawalHash = withdrawalHash(t, &b.Circuit.Policy)
	b.Circuit.PublicInputHash = spptest.MustHashChain4(t, b.Statement(t))
}

func (b BuiltAnonymous) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return b.Values(t).Elements(t)
}

// Values is what the program holds for the statement.
func (b BuiltAnonymous) Values(t testing.TB) Statement {
	t.Helper()
	return railValues(t, b.Circuit, b.Assembled)
}
