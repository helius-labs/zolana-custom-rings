// Package ringtransfer builds honest witnesses of the transfer keys from the audit and policy fixtures.
package ringtransfer

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// PublicSlot is one folded public slot, Gross the withdrawn total of its asset.
type PublicSlot struct {
	Asset *big.Int
	Net   int64
	Gross uint64
}

type Withdrawal struct {
	Owner, Asset *big.Int
	Amount       uint64
}

// Policy is the ring's table and the fixture asset's limits, Screened off without a policy hash.
type Policy struct {
	Screened bool
	// OwnRegistry reads the own root, the thresholds then bind with or without a policy hash.
	OwnRegistry bool
	// Cap, CosignAbove and WithdrawalThreshold bound the fixture asset.
	Cap, CosignAbove, WithdrawalThreshold uint64
	// Frozen freezes the fixture sender, the one rule a sender fails.
	Frozen bool
}

// World is what both families share, Build derives every hash from it.
type World struct {
	Policy       Policy
	ApprovalMask uint64
	Public       []PublicSlot
	Withdrawals  []Withdrawal
	// Exits are the slots leaving the ring, by default the second to last slot of a key past two outputs.
	Exits      []int
	AllDummies bool
	// CoOwners spend one more input each, public signers beside the rail's owner.
	CoOwners []*big.Int
	// PublicFunded spends no input.
	PublicFunded  bool
	FrozenCoOwner bool
	Omitted       int
	// Inputs replace the fixture's spend, owners off the rail's run need CoOwners.
	Inputs []ringaudit.Input
	// DefaultInput moves input 1 to the default ring, an entry key's evidence opens it.
	DefaultInput bool
	// HasData writes data hashes on the first ring output.
	HasData bool
	// Outputs replace slots by index before any hash reads them.
	Outputs map[int]func(*ringaudit.Slot)
	// Unenrolled owners hold no tracking row.
	Unenrolled []*big.Int
	// Enrolled maps an owner to the row key it holds in place of its note's key.
	Enrolled map[string]*big.Int
	// A nil slice leaves the policy reading no salted list.
	SaltedBlock []*big.Int
}

// Asset is the fixture asset of every ring output and spent note.
func Asset(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.AssetField(t, ringtest.Repeat(0x0a))
}

// SenderKey is the fixture sender's Ed25519 key.
func SenderKey() [32]byte {
	return ringtest.Repeat(0xa1)
}

// Sender is the identity of the fixture sender key.
func Sender(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, SenderKey())
}

// SenderNullifierPk is the key the fixture sender enrolled.
func SenderNullifierPk(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, big.NewInt(7))
}

// table admits every output owner on the allow list and refuses a frozen sender, a salted block list also refuses its owners.
func (w World) table() policy.Table {
	rules := []ringpolicy.Rule{ringpolicy.Require(policy.SubjectOutputOwner, ringregistry.AllowBit), ringpolicy.Forbid(policy.SubjectSender, ringregistry.FrozenBit)}
	lists := []uint64{ringregistry.AllowBit, ringregistry.BlockBit, ringregistry.FrozenBit}
	salted := uint64(0)
	if w.SaltedBlock != nil {
		rules = append(rules, ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.PrivateBlockBit))
		lists, salted = append(lists, ringregistry.PrivateBlockBit), ringregistry.PrivateBlockBit
	}
	return ringpolicy.Table{Lists: lists, Rules: rules, Salted: salted}.Wires()
}

// Assembled is what both families' Build share.
type Assembled struct {
	Audit        ringaudit.Audit
	Own, Curator *ringregistry.Registry
	Tracking     *ringregistry.Tracking
	Sender       *big.Int
	// Run is the signer set the program rebuilds.
	Run      []*big.Int
	delegate bool
}

// spend fills the fixture's inputs, half and half across the sender's two notes.
func (w World) spend(t testing.TB, a *ringaudit.Audit) {
	t.Helper()
	if w.Inputs != nil {
		copy(a.Inputs, w.Inputs)
		a.InputCount = max(len(w.Inputs), 1)
		return
	}
	a.InputCount = 2 + len(w.CoOwners)
	if a.Shape.SingleAssetPayout {
		a.InputCount = 1
	}
	if w.PublicFunded {
		return
	}
	owed := w.owedAsset(t, a)
	sender, nullifierPk := Sender(t), SenderNullifierPk(t)
	if a.Shape.SingleAssetPayout {
		a.InputCount = 1
		a.Inputs[0] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, nullifierPk, a.RingProgramID, owed, 51), OwnerKey: SenderKey(), Mint: ringaudit.FixtureMint}
		return
	}
	secondRing := a.RingProgramID
	if w.DefaultInput {
		secondRing = big.NewInt(0)
	}
	a.Inputs[0] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, nullifierPk, a.RingProgramID, owed-owed/2, 51), OwnerKey: SenderKey(), Mint: ringtest.Repeat(0x0a)}
	a.Inputs[1] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, nullifierPk, secondRing, owed/2, 52), OwnerKey: SenderKey(), Mint: ringtest.Repeat(0x0a)}
	for k, coOwner := range w.CoOwners {
		a.Inputs[2+k] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, coOwner, CoOwnerKey(t, coOwner), a.RingProgramID, 1, 53+int64(k))}
	}
}

// CoOwnerKey is the key a co-owner enrolled, one per owner.
func CoOwnerKey(t testing.TB, owner *big.Int) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, new(big.Int).Add(owner, big.NewInt(1)))
}

// owedAsset is what balance owes of the fixture asset, every output plus every net withdrawal.
func (w World) owedAsset(t testing.TB, a *ringaudit.Audit) uint64 {
	t.Helper()
	owed := int64(0)
	for _, utxo := range a.Utxos() {
		if utxo.IsUtxo() && utxo.Asset.Cmp(Asset(t)) == 0 {
			owed += int64(utxo.Amount)
		}
	}
	for _, public := range w.Public {
		if public.Asset.Cmp(Asset(t)) == 0 {
			owed -= public.Net
		}
	}
	return uint64(max(owed, 2))
}

// newAudit lays out every output and input before any hash reads them.
func (w World) newAudit(t testing.TB, shape audit.StreamShape) ringaudit.Audit {
	t.Helper()
	exits := w.Exits
	if exits == nil && shape.Outputs > 2 && !shape.SingleAssetPayout {
		exits = []int{shape.Outputs - 2}
	}
	a := ringaudit.NewAudit(t, shape, exits...)
	if w.AllDummies {
		a = a.AllDummies(t)
	}
	if w.Omitted > 0 {
		a = a.Omit(t, w.Omitted)
	}
	a.Outputs = slices.Clone(a.Outputs)
	if w.HasData {
		a.HasData = true
		for i := range a.Outputs {
			if a.Outputs[i].Utxo.IsUtxo() && a.Outputs[i].Utxo.RingProgramID.Sign() != 0 {
				a.Outputs[i].Utxo.DataHash, a.Outputs[i].Utxo.RingDataHash = big.NewInt(0x77), big.NewInt(0x78)
				break
			}
		}
	}
	for i, mutate := range w.Outputs {
		mutate(&a.Outputs[i])
	}
	w.spend(t, &a)
	return a
}

// rows are the distinct live input owners ascending, the delegate's skip a zero key.
func rows(a ringaudit.Audit, delegate bool, capacity int) []frontend.Variable {
	var owners []*big.Int
	for _, input := range a.Inputs {
		if !input.Utxo.IsUtxo() || (delegate && input.Utxo.NullifierPk.Cmp(shared.ZeroNullifierPk) == 0) {
			continue
		}
		if !slices.ContainsFunc(owners, func(o *big.Int) bool { return o.Cmp(input.Utxo.OwnerPkHash) == 0 }) {
			owners = append(owners, input.Utxo.OwnerPkHash)
		}
	}
	slices.SortFunc(owners, func(x, y *big.Int) int { return x.Cmp(y) })
	cells := make([]frontend.Variable, capacity)
	for j := range cells {
		cells[j] = 0
		if j < len(owners) {
			cells[j] = owners[j]
		}
	}
	return cells
}

// tracking enrolls every owner of a nonzero ring key.
func (w World) tracking(t testing.TB, a ringaudit.Audit) *ringregistry.Tracking {
	t.Helper()
	tree := ringregistry.NewTracking(t)
	enrolled := map[string]bool{}
	enroll := func(utxo ringaudit.Utxo) {
		owner := utxo.OwnerPkHash
		if !utxo.IsUtxo() || utxo.RingProgramID.Sign() == 0 || utxo.NullifierPk.Cmp(shared.ZeroNullifierPk) == 0 || enrolled[owner.String()] {
			return
		}
		enrolled[owner.String()] = true
		if slices.ContainsFunc(w.Unenrolled, func(o *big.Int) bool { return o.Cmp(owner) == 0 }) {
			return
		}
		key := utxo.NullifierPk
		if row, ok := w.Enrolled[owner.String()]; ok {
			key = row
		}
		ringpolicy.Enroll(t, tree, owner, key)
	}
	for _, input := range a.Inputs {
		enroll(input.Utxo)
	}
	for _, slot := range a.Outputs {
		enroll(slot.Utxo)
	}
	return tree
}

// registries lists every sender and UTXO output owner on the allow list and limits the fixture asset.
func (w World) registries(t testing.TB, a ringaudit.Audit, senders []frontend.Variable) (own, curator *ringregistry.Registry) {
	t.Helper()
	own, curator = ringregistry.New(t), ringregistry.New(t)
	zero := big.NewInt(0)
	seen := map[string]bool{}
	member := func(identity *big.Int, lists uint64) {
		if seen[identity.String()] {
			return
		}
		seen[identity.String()] = true
		bits := new(big.Int).SetUint64(lists)
		own.Apply(t, ringregistry.Entry{Member: identity, Mask: bits, Value: bits, MintPolicy: zero, WithdrawalThreshold: zero})
	}
	sender := Sender(t)
	for _, cell := range senders {
		identity := ringtest.AsBigInt(cell)
		if identity.Sign() == 0 {
			continue
		}
		lists := uint64(ringregistry.AllowBit)
		frozen := w.Policy.Frozen && identity.Cmp(sender) == 0
		frozen = frozen || (w.FrozenCoOwner && len(w.CoOwners) > 0 && identity.Cmp(w.CoOwners[0]) == 0)
		if frozen {
			lists |= ringregistry.FrozenBit
		}
		member(identity, lists)
	}
	for _, utxo := range a.Utxos() {
		if utxo.IsUtxo() {
			member(utxo.OwnerPkHash, ringregistry.AllowBit)
		}
	}
	for _, leg := range w.Withdrawals {
		member(leg.Owner, ringregistry.AllowBit)
	}
	p := w.Policy
	// Bit 192 writes the mint policy, cap at 2^64 and the co-sign bound below it.
	for _, owner := range w.SaltedBlock {
		bits := big.NewInt(ringregistry.PrivateBlockBit)
		own.Apply(t, ringregistry.Entry{Member: ringregistry.ListKey(t, owner, ringpolicy.ListSaltOf(t, owner)), Mask: bits, Value: bits, MintPolicy: zero, WithdrawalThreshold: zero})
	}
	mintPolicy := new(big.Int).Lsh(big.NewInt(1), 192)
	mintPolicy.Or(mintPolicy, new(big.Int).Lsh(new(big.Int).SetUint64(p.Cap), 64))
	mintPolicy.Or(mintPolicy, new(big.Int).SetUint64(p.CosignAbove))
	own.Apply(t, ringregistry.Entry{Member: Asset(t), Mask: zero, Value: zero, MintPolicy: mintPolicy, WithdrawalThreshold: new(big.Int).SetUint64(p.WithdrawalThreshold)})
	return own, curator
}

// fill sets every wire both families share and returns what the statement reads.
func (w World) fill(t testing.TB, c *transfer.Sections, a ringaudit.Audit, delegate bool, run []*big.Int) Assembled {
	t.Helper()
	wires := a.Wires(a.Layout())
	c.FirstNullifier, c.TxViewingSk, c.AuditorPk, c.Salt, c.Layout = wires.FirstNullifier, wires.TxViewingSk, wires.AuditorPk, wires.Salt, wires.Layout
	c.RingProgramID = a.RingProgramID
	c.OutputCount = a.OutputCount()
	for i, output := range a.Outputs {
		c.Outputs[i] = output.Wires()
	}
	c.InputCount = a.InputCount
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Utxo.Wires()
		c.InputNullifiers[i] = 0
		if i < a.InputCount {
			c.InputNullifiers[i] = new(big.Int).Add(a.FirstNullifier, big.NewInt(int64(i)))
		}
		if i < len(c.Entries) {
			c.Entries[i] = input.EntryWires()
		}
	}
	c.SignerCount = len(run)
	for k := range c.Signers {
		c.Signers[k] = 0
		if k < len(run) {
			c.Signers[k] = run[k]
		}
	}
	c.SignerDataCounts = ringaudit.SignerDataCounts(run, a.Utxos())
	c.Rows = rows(a, delegate, len(c.Rows))
	c.ApprovalMask, c.ApprovalTotals, c.ApprovalBlinder = w.ApprovalMask, 0, 0
	assembled := Assembled{Audit: a, Sender: Sender(t), Run: run, Tracking: w.tracking(t, a), delegate: delegate}
	assembled.Own, assembled.Curator = w.registries(t, a, c.Rows)
	w.reopen(t, c, assembled)
	return assembled
}

// reopen fills both pools over the circuit's rows.
func (w World) reopen(t testing.TB, c *transfer.Sections, a Assembled) {
	t.Helper()
	w.fillPolicy(t, &c.Policy, a, a.delegate, c.Rows, a.Audit.Utxos(), c.Inputs)
	outputOwners := make([]frontend.Variable, len(a.Audit.Outputs))
	payments := make([]frontend.Variable, 0, len(c.OwnerEntries))
	for o, slot := range a.Audit.Outputs {
		outputOwners[o] = 0
		if slot.Utxo.IsUtxo() && slot.Utxo.RingProgramID.Sign() != 0 {
			outputOwners[o] = slot.Utxo.OwnerPkHash
		}
		if !slot.Utxo.IsUtxo() {
			payments = append(payments, 0)
			continue
		}
		payments = append(payments, slot.Utxo.OwnerPkHash)
	}
	for _, leg := range c.Withdrawals {
		payments = append(payments, leg.Owner)
	}
	ringpolicy.FillTracking(t, &c.Tracking, a.Tracking, c.Rows, outputOwners, &c.Policy, payments)
}

func (w World) fillPolicy(t testing.TB, p *policy.Policy, a Assembled, delegate bool, senders []frontend.Variable, utxos []ringaudit.Utxo, inputs []shared.UtxoWires) {
	t.Helper()
	p.Table = w.table()
	p.PolicyHash, p.OwnRoot, p.CuratorRoot = 0, 0, 0
	if !delegate {
		if w.Policy.Screened {
			p.PolicyHash = ringpolicy.TableHash(t, p.Table)
		}
		if w.Policy.Screened || w.Policy.OwnRegistry {
			p.OwnRoot = a.Own.Root()
		}
	}
	p.RingProgramID = a.Audit.RingProgramID
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = 0, 0, 0
		if k < len(w.Public) {
			p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = w.Public[k].Asset, protocol.SignedToField(big.NewInt(w.Public[k].Net)), new(big.Int).SetUint64(w.Public[k].Gross)
		}
	}
	legs := w.Withdrawals
	if delegate {
		legs = nil
	}
	p.WithdrawalCount = len(legs)
	for i := range p.Withdrawals {
		p.Withdrawals[i] = policy.WithdrawalWires{Owner: 0, Asset: 0, Amount: 0}
		if i < len(legs) {
			p.Withdrawals[i] = policy.WithdrawalWires{Owner: legs[i].Owner, Asset: legs[i].Asset, Amount: new(big.Int).SetUint64(legs[i].Amount)}
		}
	}
	wires := make([]shared.UtxoWires, len(utxos))
	for o, utxo := range utxos {
		wires[o] = utxo.Wires()
	}
	ringpolicy.FillPools(t, p, wires, inputs, senders, a.Own, a.Curator, a.Tracking)
}

// withdrawalHash mirrors policy openWithdrawals over the live legs.
func withdrawalHash(t testing.TB, p *policy.Policy) *big.Int {
	t.Helper()
	fields := []*big.Int{big.NewInt(shared.WithdrawalsDomain), ringtest.AsBigInt(p.WithdrawalCount)}
	for _, leg := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		fields = append(fields, ringtest.AsBigInt(leg.Owner), ringtest.AsBigInt(leg.Asset), ringtest.AsBigInt(leg.Amount))
	}
	return spptest.MustHashChain4(t, fields)
}

// rehash recomputes private_tx_hash from the audit's slots.
func rehash(t testing.TB, c *transfer.Sections, a ringaudit.Audit) {
	t.Helper()
	inputs := spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, a.InputUtxos()))
	outputs := spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, a.Utxos()))
	nullifiers := ringtest.ToBigInts(c.InputNullifiers)
	c.InputNullifierChain = spptest.MustHashChain4(t, append([]*big.Int{ringtest.AsBigInt(c.InputCount)}, nullifiers...))
	addresses := make([]*big.Int, len(a.Inputs))
	for i, input := range a.Inputs {
		addresses[i] = new(big.Int)
		if input.Utxo.Domain == protocol.AddressDomain {
			addresses[i] = nullifiers[i]
		}
	}
	addressChain := spptest.MustNonZeroHashChain(t, addresses)
	c.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{inputs, outputs, addressChain, a.PrivateTxBlinding(t)})
}

// values is the statement both families share.
func values(t testing.TB, c *transfer.Sections, a Assembled) Statement {
	t.Helper()
	stream := a.Audit.Stream(t)
	s := Statement{
		Head: a.Audit.Head(t, stream), Outputs: a.Audit.StatementOutputs(t, stream), InputCount: a.Audit.InputCount,
		ApprovalMask: ringtest.AsBigInt(c.ApprovalMask), ApprovalTotals: ringtest.AsBigInt(c.ApprovalTotals), SignerDataCounts: ringtest.AsBigInt(c.SignerDataCounts), NoSpend: a.Audit.RealInputs() == 0,
		InputNullifierChain: ringtest.AsBigInt(c.InputNullifierChain),
		PrivateTxHash:       ringtest.AsBigInt(c.PrivateTxHash),
		SignerCount:         len(a.Run), SignerChain: ringaudit.SignerChain(t, a.Run, len(c.Signers)),
		PolicyHash: ringtest.AsBigInt(c.PolicyHash), OwnRoot: ringtest.AsBigInt(c.OwnRoot), CuratorRoot: ringtest.AsBigInt(c.CuratorRoot),
		TrackingRoot:   ringtest.AsBigInt(c.TrackingRoot),
		WithdrawalHash: ringtest.AsBigInt(c.WithdrawalHash),
	}
	for k := range c.PublicAssets {
		s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k] = ringtest.AsBigInt(c.PublicAssets[k]), ringtest.AsBigInt(c.PublicAmounts[k]), ringtest.AsBigInt(c.PublicGross[k])
	}
	return s
}
