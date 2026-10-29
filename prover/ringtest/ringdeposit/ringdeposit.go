// Package ringdeposit is the host twin of the ring deposit circuit for the Go tests.
package ringdeposit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// RingMode mirrors RingMode in program-libs/interface/src/accounts/state.rs, the flags DepositPublicInput binds follow it.
type RingMode int

const (
	ModeOff RingMode = iota
	ModeRegistry
	ModeAnonymous
)

type Deposit struct {
	Circuit *circuits.DepositCircuit
}

// Policy is a registry ring's table, the own registry lists every Listed asset on AllowBit.
type Policy struct {
	Rules  []ringpolicy.Rule
	Listed []int64
	// Asset is every slot's deposited asset.
	Asset int64
}

// Build deposits count owners under the CRDB blinding, escrowed on ModeRegistry and disclosing their keys on ModeAnonymous.
func Build(t testing.TB, count int, mode RingMode) *Deposit {
	t.Helper()
	return BuildBlinded(t, count, mode, ringprotocol.DepositBlinding)
}

// BuildBlinded is Build with blindingOf deriving the blinding every commitment and opening carries.
func BuildBlinded(t testing.TB, count int, mode RingMode, blindingOf func(testing.TB, *big.Int) *big.Int) *Deposit {
	t.Helper()
	return build(t, count, mode, blindingOf, Policy{Rules: nil, Listed: nil, Asset: ringpolicy.AssetA})
}

// Allowlisted requires every deposited asset on AllowBit, where the registry lists only AssetA.
func Allowlisted(asset int64) Policy {
	return Policy{Rules: []ringpolicy.Rule{ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)}, Listed: []int64{ringpolicy.AssetA}, Asset: asset}
}

// BuildScreened deposits count owners into a registry ring whose policy screens every deposited asset.
func BuildScreened(t testing.TB, count int, policy Policy) *Deposit {
	t.Helper()
	return build(t, count, ModeRegistry, ringprotocol.DepositBlinding, policy)
}

func build(t testing.TB, count int, mode RingMode, blindingOf func(testing.TB, *big.Int) *big.Int, policy Policy) *Deposit {
	t.Helper()
	anonymous, escrow, screened := mode == ModeAnonymous, mode == ModeRegistry, policy.Rules != nil
	keys, registry := ringaudit.DefaultKeys(t), ringregistry.New(t)
	c, err := circuits.NewDepositCircuit(circuits.MaxDeposits)
	if err != nil {
		t.Fatal(err)
	}
	c.ContextHash, c.Count, c.Anonymous, c.KeyEscrow, c.MemberRegistryRoot = big.NewInt(0xabcdef), count, ringtest.Bit(anonymous), ringtest.Bit(escrow), 0
	c.Table, c.PolicyHash = ringpolicy.Table{}.Wires(), 0
	if screened {
		c.Table = ringpolicy.Table{Lists: []uint64{ringregistry.AllowBit}, Rules: policy.Rules}.Wires()
		c.PolicyHash = ringpolicy.TableHash(t, c.Table)
		for _, asset := range policy.Listed {
			registry.Apply(t, ringregistry.Entry{Member: big.NewInt(asset), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(ringregistry.AllowBit), EscrowKey: big.NewInt(0)})
		}
	}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	plaintext := make([]byte, circuits.MaxDeposits*circuits.DepositOpeningBytes)
	commitments := make([]*big.Int, circuits.MaxDeposits)
	for i := range circuits.MaxDeposits {
		var key [32]byte
		ownerPkHash, nullifierPk, secret, ctHash := big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < count {
			ownerPkHash = big.NewInt(int64(11 + i))
			if anonymous {
				for j := range key {
					key[j] = byte(i + j + 1)
				}
				ownerPkHash = ringtest.MustSolanaPkField(t, key)
			}
			nullifierPk = spptest.MustNullifierPk(t, big.NewInt(int64(51+i)))
			secret = big.NewInt(int64(91 + i))
			if escrow {
				ctHash = big.NewInt(int64(0xc0 + i))
				registry.Apply(t, ringregistry.Entry{
					Member: ownerPkHash, Mask: big.NewInt(ringregistry.EscrowBit), Value: big.NewInt(ringregistry.EscrowBit),
					EscrowKey: ringregistry.EscrowKey(t, nullifierPk, ctHash),
				})
			}
		}
		c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.CtHashes[i] = ownerPkHash, nullifierPk, secret, ctHash
		c.Assets[i], c.Amounts[i] = 0, 0
		if i < count {
			c.Assets[i], c.Amounts[i] = policy.Asset, 100+i
		}
		ringtest.SetBytes(c.OwnerKeys[i][:], key[:])
		owner := spptest.MustOwnerHash(t, ownerPkHash, nullifierPk)
		blinding := blindingOf(t, secret)
		commitments[i] = ringtest.MustPoseidonHash(t, owner, blinding)
		opening := plaintext[i*circuits.DepositOpeningBytes : (i+1)*circuits.DepositOpeningBytes]
		owner.FillBytes(opening[:32])
		blinding.FillBytes(opening[32:64])
		copy(opening[64:], key[:])
	}
	for i := range circuits.MaxDeposits {
		c.Members[i] = ringregistry.UnreadRecordWires()
		if escrow {
			c.Members[i] = registry.Opening(ringtest.AsBigInt(c.OwnerPkHashes[i])).RecordWires()
		}
		c.AssetRecords[i] = registry.Opening(ringtest.AsBigInt(c.Assets[i])).Wires()
	}
	if escrow || screened {
		c.MemberRegistryRoot = registry.Root()
	}
	ciphertext := keys.EnvelopeCiphertext(t, plaintext, shared.DepositEncInfo)
	sealed := keys.Sealed(t, ciphertext)
	// Ordered as DepositPublicInput::elements.
	chain := []*big.Int{big.NewInt(shared.DepositStatementDomain), ringtest.AsBigInt(c.ContextHash), big.NewInt(int64(count)), ringtest.AsBigInt(c.Anonymous)}
	for i := range circuits.MaxDeposits {
		if i >= count {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		chain = append(chain, commitments[i], ringtest.HashBytes(t, ciphertext[i*circuits.DepositOpeningBytes:(i+1)*circuits.DepositOpeningBytes]))
	}
	chain = append(chain, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, ringtest.AsBigInt(c.KeyEscrow), ringtest.AsBigInt(c.MemberRegistryRoot), ringtest.AsBigInt(c.PolicyHash))
	for i := range circuits.MaxDeposits {
		chain = append(chain, ringtest.AsBigInt(c.Assets[i]), ringtest.AsBigInt(c.Amounts[i]))
	}
	c.PublicInputHash = spptest.MustHashChain(t, chain)
	return &Deposit{Circuit: c}
}

// BuildCapacity keeps the fixed statement while witnessing only the compiled prefix.
func BuildCapacity(t testing.TB, capacity, count int, mode RingMode) *Deposit {
	t.Helper()
	return Build(t, count, mode).Narrow(t, capacity)
}

// Narrow keeps the fixed statement while witnessing only the compiled prefix.
func (d *Deposit) Narrow(t testing.TB, capacity int) *Deposit {
	t.Helper()
	c := d.Circuit
	if ringtest.AsBigInt(c.Count).Cmp(big.NewInt(int64(capacity))) > 0 {
		t.Fatal("count exceeds deposit capacity")
	}
	c.Capacity = capacity
	c.OwnerPkHashes = c.OwnerPkHashes[:capacity]
	c.OwnerKeys = c.OwnerKeys[:capacity]
	c.NullifierPks = c.NullifierPks[:capacity]
	c.BlindingSecrets = c.BlindingSecrets[:capacity]
	c.CtHashes = c.CtHashes[:capacity]
	c.Members = c.Members[:capacity]
	c.Assets = c.Assets[:capacity]
	c.Amounts = c.Amounts[:capacity]
	c.AssetRecords = c.AssetRecords[:capacity]
	return d
}
