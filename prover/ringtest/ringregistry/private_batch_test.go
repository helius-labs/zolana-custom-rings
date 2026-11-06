package ringregistry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func solvePrivate(c *registry.PrivateApplyRecordsCircuit) error {
	return test.IsSolved(c, c, ecc.BN254.ScalarField())
}

func TestPrivateWriteOpensTheOwnersTrackingRow(t *testing.T) {
	for _, mask := range []int64{ringregistry.PrivateBlockBit, ringregistry.PrivateAllowBit, ringregistry.PrivateFrozenBit} {
		if err := solvePrivate(ringregistry.PrivateBatch(t, 2, mask)); err != nil {
			t.Fatal(err)
		}
	}
	const owner = "registry.PrivateOwner.Assert"
	for _, tc := range []struct {
		name   string
		mutate func(*registry.PrivateApplyRecordsCircuit)
		frame  string
	}{
		{"another tracking root", func(c *registry.PrivateApplyRecordsCircuit) {
			c.TrackingRoot = ringregistry.NewTracking(t).Root()
		}, owner},
		{"another salt", func(c *registry.PrivateApplyRecordsCircuit) { c.Owners[0].ListSalt = 0x1234 }, owner},
		{"another owner's row", func(c *registry.PrivateApplyRecordsCircuit) {
			c.Owners[0].Record.Member = 103
		}, owner},
		{"an owner absent from the root", func(c *registry.PrivateApplyRecordsCircuit) {
			other := ringregistry.SaltedTracking(t, big.NewInt(13))
			other.Apply(t, ringregistry.TrackingEntry{
				Member: big.NewInt(103), NullifierPk: spptest.MustNullifierPk(t, big.NewInt(9)), CtHash: big.NewInt(19),
				ListTag: ringregistry.ListTag(t, big.NewInt(13)),
			})
			opening := other.Opening(big.NewInt(103))
			c.Owners[0].Record, c.Owners[0].Path = opening.Record.Wires(), opening.Path.Wires()
		}, owner},
		{"the sentinel", func(c *registry.PrivateApplyRecordsCircuit) {
			opening := ringregistry.NewTracking(t).Opening(big.NewInt(1))
			c.Owners[0].Record, c.Owners[0].Path = opening.Record.Wires(), opening.Path.Wires()
		}, owner},
		{"a bit past count", func(c *registry.PrivateApplyRecordsCircuit) {
			c.PrivateWrites = 3
			c.Owners[1] = c.Owners[0]
		}, "registry.(*PrivateApplyRecordsCircuit).Define"},
		{"an empty bitmap", func(c *registry.PrivateApplyRecordsCircuit) {
			c.PrivateWrites = 0
			c.Owners[0] = ringregistry.ZeroPrivateOwner()
		}, "registry.(*PrivateApplyRecordsCircuit).privateBits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ringregistry.PrivateBatch(t, 2, ringregistry.PrivateBlockBit)
			tc.mutate(c)
			ringregistry.BindPrivateBatch(t, c)
			ringtest.RequireRefused(t, solvePrivate(c), tc.frame)
		})
	}
}

func TestPrivateKeyRefusesAPublicMask(t *testing.T) {
	ringtest.RequireRefused(t, solvePrivate(ringregistry.PrivateBatch(t, 2, ringregistry.AllowBit)), "registry.(*PrivateApplyRecordsCircuit).Define")
}
