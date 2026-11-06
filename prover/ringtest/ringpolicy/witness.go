package ringpolicy

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Witness is a built world, Circuit its assignment.
type Witness struct {
	Circuit *SectionCircuit
}

func (w World) Build(t testing.TB) Witness {
	t.Helper()
	return w.BuildRows(t, w.Table.rows())
}

// BuildRows builds the world under rows in place of Table's, the table a vector carries.
func (w World) BuildRows(t testing.TB, rows Rows) Witness {
	t.Helper()
	c, err := NewSectionCircuit(SectionShape{Outputs: w.Outputs, Withdrawals: w.WithdrawalCapacity, SaltedKeys: w.SaltedKeys, Records: w.Records})
	if err != nil {
		t.Fatal(err)
	}
	b := Witness{Circuit: c}
	p := &c.Policy
	own, curator := registry(t, w.Own), registry(t, w.Curator)
	WriteSalted(t, own, w.Salted)
	WriteSalted(t, curator, w.CuratorSalted)
	mintPolicies := map[string]*big.Int{}
	assets := map[string]*big.Int{}
	for i, a := range rows.InlineAssets {
		asset := ringtest.AsBigInt(a)
		key := asset.String()
		assets[key] = asset
		mintPolicies[key] = new(big.Int).Lsh(ringtest.AsBigInt(rows.InlineLimits[i]), 128)
	}
	for _, limit := range rows.Limits {
		asset := ringtest.AsBigInt(limit.Asset)
		key := asset.String()
		assets[key] = asset
		if mintPolicies[key] == nil {
			mintPolicies[key] = big.NewInt(0)
		}
		mintPolicies[key].Or(mintPolicies[key], new(big.Int).Lsh(ringtest.AsBigInt(limit.Cap), 64))
		mintPolicies[key].Or(mintPolicies[key], ringtest.AsBigInt(limit.CosignAbove))
	}
	keys := make([]string, 0, len(assets))
	for key := range assets {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		update := new(big.Int).Or(mintPolicies[key], new(big.Int).Lsh(big.NewInt(1), 192))
		// A mint policy write carries the threshold again, the record keeps the world's.
		threshold := big.NewInt(0)
		if assets[key].IsInt64() {
			threshold.SetUint64(w.Own[assets[key].Int64()].WithdrawalThreshold)
		}
		own.Apply(t, ringregistry.Entry{Member: assets[key], Mask: big.NewInt(0), Value: big.NewInt(0), MintPolicy: update, WithdrawalThreshold: threshold})
	}

	p.Table = rows.Wires()
	p.PolicyHash = 0
	if !w.Unscreened {
		p.PolicyHash = TableHash(t, p.Table)
	}
	p.RingProgramID, p.OwnRoot, p.CuratorRoot = ringID, own.Root(), 0
	if slices.ContainsFunc(rows.Sources, func(s policy.SourceWires) bool { return ringtest.AsBigInt(s.Registry).Sign() != 0 }) {
		p.CuratorRoot = curator.Root()
	}
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = 0, 0, 0
		if k < len(w.Public) {
			p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = w.Public[k].Asset, protocol.SignedToField(big.NewInt(w.Public[k].Amount)), w.Public[k].Gross
			if w.Public[k].Gross == 0 && w.Public[k].Amount < 0 {
				p.PublicGross[k] = -w.Public[k].Amount
			}
		}
	}
	c.PrivateTxBlinding = privateTxBlinding
	for j, row := range w.rows(len(c.Senders)) {
		c.Senders[j] = row
	}
	for o := range c.Outputs {
		s := pick(w.Slots, o)
		c.Outputs[o] = s.wires(0xb100 + int64(o))
	}
	p.WithdrawalCount = len(w.Withdrawals)
	for i := range p.Withdrawals {
		s := pick(w.Withdrawals, i)
		p.Withdrawals[i] = policy.WithdrawalWires{Owner: s.Owner, Asset: s.Asset, Amount: s.Amount}
	}
	inputs := w.Inputs
	if inputs == nil {
		inputs = w.balancedInputs()
	}
	if len(inputs) > len(c.Inputs) {
		t.Fatalf("%d inputs, the harness holds %d", len(inputs), len(c.Inputs))
	}
	for i := range c.Inputs {
		c.Inputs[i] = pick(inputs, i).wires(0xc100 + int64(i))
		if i < len(inputs) && inputs[i].bigAmount != nil {
			c.Inputs[i].Amount = inputs[i].bigAmount
		}
	}
	c.InputChain = inputChain
	c.ThresholdsActive, c.Delegate = ringtest.Bit(!w.NoOwnRegistry && !w.Delegate), ringtest.Bit(w.Delegate)
	c.ApprovalMask, c.ApprovalTotals, c.ApprovalBlinder = w.Approval, 0, 0
	tracking := ringregistry.NewTracking(t)
	for _, owner := range w.Enrolled {
		Enroll(t, tracking, big.NewInt(owner), big.NewInt(owner+1))
	}
	FillPools(t, p, c.Outputs, c.Inputs, c.Senders, own, curator, tracking)
	payments := make([]frontend.Variable, 0, len(p.OwnerEntries))
	for _, out := range c.Outputs {
		payments = append(payments, out.OwnerPkHash)
	}
	for _, leg := range p.Withdrawals {
		payments = append(payments, leg.Owner)
	}
	outputs := make([]frontend.Variable, len(c.Outputs))
	for o := range outputs {
		outputs[o] = 0
	}
	FillTracking(t, &c.Tracking, tracking, c.Senders, outputs, p, payments)
	b.Rehash(t)
	return b
}

func (b Witness) Policy() *policy.Policy {
	return &b.Circuit.Policy
}

func (b Witness) Outputs() []shared.UtxoWires {
	return b.Circuit.Outputs
}

func (b Witness) Assignment() frontend.Circuit {
	return b.Circuit
}

// Rehash recomputes private_tx_hash from the slot wires after one changes, then the public input.
func (b Witness) Rehash(t testing.TB) {
	t.Helper()
	wires := b.Outputs()
	outputs := make([]*big.Int, len(wires))
	for o, w := range wires {
		outputs[o] = utxoHash(t, w)
	}
	chain := ringtest.AsBigInt(b.Circuit.InputChain)
	b.Circuit.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{chain, spptest.MustNonZeroHashChain(t, outputs), big.NewInt(0), ringtest.AsBigInt(b.Circuit.PrivateTxBlinding)})
	b.Rebind(t)
}

// Rebind recomputes the public input after a statement value changes.
func (b Witness) Rebind(t testing.TB) {
	t.Helper()
	p := b.Policy()
	fields := []*big.Int{big.NewInt(shared.WithdrawalsDomain), ringtest.AsBigInt(p.WithdrawalCount)}
	for _, w := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		fields = append(fields, ringtest.AsBigInt(w.Owner), ringtest.AsBigInt(w.Asset), ringtest.AsBigInt(w.Amount))
	}
	p.WithdrawalHash = spptest.MustHashChain4(t, fields)
	b.Circuit.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(b.Circuit.Statement()))
}

func WriteSalted(t testing.TB, tree *ringregistry.Registry, records map[int64]uint64) {
	t.Helper()
	owners := make([]int64, 0, len(records))
	for owner := range records {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	zero := big.NewInt(0)
	for _, owner := range owners {
		identity := big.NewInt(owner)
		bits := new(big.Int).SetUint64(records[owner])
		tree.Apply(t, ringregistry.Entry{Member: ringregistry.ListKey(t, identity, ListSaltOf(t, identity)), Mask: bits, Value: bits, MintPolicy: zero, WithdrawalThreshold: zero})
	}
}

// rows is the sender and co-owners ascending with zero rows last, the order the circuit holds.
func (w World) rows(capacity int) []int64 {
	rows := append([]int64{w.Sender}, w.CoOwners...)
	slices.Sort(rows)
	rows = slices.Compact(rows)
	for len(rows) < capacity {
		rows = append(rows, 0)
	}
	return rows
}

// balancedInputs spends what balance owes per asset, every output plus every net withdrawal, none on a deposit-funded asset.
func (w World) balancedInputs() []Slot {
	owed, order := map[int64]*big.Int{}, []int64{}
	add := func(asset int64, amount *big.Int) {
		if owed[asset] == nil {
			owed[asset] = big.NewInt(0)
			order = append(order, asset)
		}
		owed[asset].Add(owed[asset], amount)
	}
	for _, slot := range w.Slots {
		if slot.Owner != 0 || slot.Unowned {
			add(slot.Asset, new(big.Int).SetUint64(slot.Amount))
		}
	}
	for _, public := range w.Public {
		add(public.Asset, big.NewInt(-public.Amount))
	}
	var inputs []Slot
	for _, asset := range order {
		if owed[asset].Sign() > 0 {
			inputs = append(inputs, Slot{Owner: w.Sender, Asset: asset, bigAmount: owed[asset]})
		}
	}
	return inputs
}

// registry writes every member's record in ascending member order.
func registry(t testing.TB, records map[int64]Record) *ringregistry.Registry {
	t.Helper()
	r := ringregistry.New(t)
	ids := make([]int64, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		record := records[id]
		lists := new(big.Int).SetUint64(record.Lists)
		entry := ringregistry.Entry{Member: big.NewInt(id), Mask: lists, Value: lists}
		if record.WithdrawalThreshold != 0 {
			// Bit 192 writes the mint policy, the threshold rides on that write.
			entry.MintPolicy, entry.WithdrawalThreshold = new(big.Int).Lsh(big.NewInt(1), 192), new(big.Int).SetUint64(record.WithdrawalThreshold)
		}
		r.Apply(t, entry)
	}
	return r
}

// wires opens the slot under treeID, a dummy keeps the asset and amount no sum counts.
func (s Slot) wires(blinding int64) shared.UtxoWires {
	if s.Owner == 0 && !s.Unowned {
		return shared.UtxoWires{
			Domain: transaction.DummyDomain, TreeID: treeID, OwnerPkHash: 0, NullifierPk: 0, Asset: s.Asset, Amount: s.Amount,
			Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
		}
	}
	ring := int64(ringID)
	if s.Exit {
		ring = 0
	}
	key := nullifierPk(s.Owner)
	if s.ZeroKey {
		key = shared.ZeroNullifierPk
	}
	return shared.UtxoWires{
		Domain: transaction.UtxoDomain, TreeID: treeID, OwnerPkHash: s.Owner, NullifierPk: key, Asset: s.Asset,
		Amount: s.Amount, Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: ring,
	}
}

// utxoHash is the hash private_tx_hash chains for a slot, zero unless the slot is a UTXO.
func utxoHash(t testing.TB, w shared.UtxoWires) *big.Int {
	t.Helper()
	if ringtest.AsBigInt(w.Domain).Int64() != transaction.UtxoDomain {
		return big.NewInt(0)
	}
	utxo := protocol.Utxo{
		Domain:        ringtest.AsBigInt(w.Domain),
		Owner:         spptest.MustOwnerHash(t, ringtest.AsBigInt(w.OwnerPkHash), ringtest.AsBigInt(w.NullifierPk)),
		Asset:         ringtest.AsBigInt(w.Asset),
		Amount:        ringtest.AsBigInt(w.Amount),
		Blinding:      ringtest.AsBigInt(w.Blinding),
		DataHash:      ringtest.AsBigInt(w.DataHash),
		RingDataHash:  ringtest.AsBigInt(w.RingDataHash),
		RingProgramID: ringtest.AsBigInt(w.RingProgramID),
	}
	return spptest.MustUtxoHash(t, utxo, ringtest.AsBigInt(w.TreeID))
}

func pick(slots []Slot, i int) Slot {
	return pad(slots, i, Slot{})
}

func pad[T any](rows []T, i int, zero T) T {
	if i < len(rows) {
		return rows[i]
	}
	return zero
}

func nullifierPk(member int64) *big.Int { return big.NewInt(member + 500_000) }
