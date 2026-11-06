package ringregistry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type OwnerWrite struct {
	Tracking *Tracking
	Owner    registry.PrivateOwner
	Key      *big.Int
}

// SaltedTracking holds member 101 enrolled under salt.
func SaltedTracking(t testing.TB, salt *big.Int) *Tracking {
	t.Helper()
	tracking := NewTracking(t)
	tracking.Apply(t, TrackingEntry{
		Member: big.NewInt(101), NullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)), CtHash: big.NewInt(17),
		ListTag: ListTag(t, salt),
	})
	return tracking
}

func NewOwnerWrite(t testing.TB, salt *big.Int) OwnerWrite {
	t.Helper()
	tracking := SaltedTracking(t, salt)
	member := big.NewInt(101)
	opening := tracking.Opening(member)
	if !opening.Present {
		t.Fatal("ringregistry: the salted owner is not enrolled")
	}
	owner := registry.PrivateOwner{ListSalt: salt, Record: opening.Record.Wires(), Path: opening.Path.Wires()}
	return OwnerWrite{Tracking: tracking, Owner: owner, Key: ListKey(t, member, salt)}
}

// ZeroPrivateOwner is the all zero slot an unselected write carries.
func ZeroPrivateOwner() registry.PrivateOwner {
	zero := ZeroTrackingWrite()
	return registry.PrivateOwner{ListSalt: 0, Record: zero.Low.Wires(), Path: zero.Slot.Wires()}
}

// PrivateBatch writes mask on the salted owner key at slot 0 of a private key of capacity writes, the other slots stay inactive.
func PrivateBatch(t testing.TB, capacity int, mask int64) *registry.PrivateApplyRecordsCircuit {
	t.Helper()
	owner := NewOwnerWrite(t, big.NewInt(13))
	c, err := registry.NewPrivateApplyRecordsCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	members := New(t)
	c.OldRoot, c.OldNextIndex, c.ChainStart = members.Root(), members.NextIndex(), 17
	c.Count, c.PrivateWrites, c.TrackingRoot = 1, 1, owner.Tracking.Root()
	entry := Entry{Member: owner.Key, Mask: big.NewInt(mask), Value: big.NewInt(mask)}
	c.Writes[0], c.Owners[0] = members.Apply(t, entry).Wires(), owner.Owner
	for i := 1; i < capacity; i++ {
		c.Writes[i] = members.Apply(t, Entry{Member: big.NewInt(2), Mask: new(big.Int), Value: new(big.Int)}).Wires()
		c.Owners[i] = ZeroPrivateOwner()
	}
	c.NewRoot, c.NewNextIndex = members.Root(), members.NextIndex()
	c.ChainEnd = ringtest.MustPoseidonHash(t, ringtest.AsBigInt(c.ChainStart), entry.Hash(t))
	BindPrivateBatch(t, c)
	return c
}

// BindPrivateBatch hashes the statement from the circuit's current values, as the program rebuilds it.
func BindPrivateBatch(t testing.TB, c *registry.PrivateApplyRecordsCircuit) {
	t.Helper()
	fields := []frontend.Variable{
		shared.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
		Restrictive(c.Writes, int(ringtest.AsBigInt(c.Count).Int64())), c.PrivateWrites, c.TrackingRoot,
	}
	c.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(fields))
}
