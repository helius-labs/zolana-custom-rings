// Package ringpolicy builds honest witnesses of the policy keys from a World.
package ringpolicy

import (
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

const (
	Sender = 1001
	Alice  = 1002
	Bob    = 1003
	Carol  = 1004
	Dave   = 1005
	Erin   = 1006
	Frank  = 1007
	Grace  = 1008
	AssetA = 2001
	AssetB = 2002
	AssetC = 2003
)

const (
	ringID            = 0x52494e47
	treeID            = 3
	inputChain        = 0x1c
	privateTxBlinding = 0x7b
)

var curatorRegistry = big.NewInt(0xc0ffee)

// World is one transfer with the registries and table it reads, Build derives every hash from it.
type World struct {
	Outputs            int
	WithdrawalCapacity int
	Withdrawals        []Slot
	// Anonymous publishes no recipient, Unscreened writes no policy hash, NoOwnRegistry holds no thresholds, Delegate bypasses every policy.
	Unscreened, NoOwnRegistry, Delegate bool
	// Approval is the mask the proof must reach.
	Approval uint64
	Sender   int64
	CoOwners []int64
	// Nil derives one Sender input per asset the balance needs.
	Inputs       []Slot
	Table        Table
	Own, Curator map[int64]Record
	Slots        []Slot
	Public       []PublicSlot
	// Records sizes the record pools, a zero capacity takes the shape's maximum.
	Records policy.RecordPoolShape
	// SaltedKeys widens the pools as a key with no wider sibling does.
	SaltedKeys int
	// Enrolled owners hold a tracking row with their fixture salt.
	Enrolled []int64
	// List bits at each owner's salted key, enrolled or not.
	Salted, CuratorSalted map[int64]uint64
	// Unkeyed own records sit under the bare id, an owner record a writer left off its public key.
	Unkeyed map[int64]Record
}

// OutputCapacities are the output counts of the transfer keys.
var OutputCapacities = []int{2, 4, 8}

// Table is a policy table of ringregistry list bits, a list reads the curator registry when Curator holds its bit.
type Table struct {
	Lists   []uint64
	Curator map[uint64]bool
	// Mask of lists owners read at their salted keys.
	Salted uint64
	Rules  []Rule
	Inline []InlineLimit
	Limits []OutflowLimit
}

// Rule mirrors one Row of program-libs/policy/src/rule_table/mod.rs.
type Rule struct {
	Subject, Mode, Mask, Guard, Threshold, Alternative uint64
}

type InlineLimit struct {
	Asset int64
	Limit uint64
}

type OutflowLimit struct {
	Asset            int64
	Cap, CosignAbove uint64
}

// Record is one member's registry record.
type Record struct {
	Lists uint64
	// WithdrawalThreshold is an asset record's approval bound, zero leaves it unwritten.
	WithdrawalThreshold uint64
}

// Slot is one output or input, a zero owner leaves it a dummy unless Unowned holds.
type Slot struct {
	Owner, Asset  int64
	Amount        uint64
	Exit, Unowned bool
	// ZeroKey takes the owner's note under ZeroNullifierPk.
	ZeroKey bool
	// bigAmount carries a balanced input past u64, the harness reads no range.
	bigAmount *big.Int
}

// PublicSlot is one folded public slot, Gross zero takes the withdrawn amount.
type PublicSlot struct {
	Asset, Amount int64
	Gross         uint64
}

func Confidential() World {
	return World{
		Outputs: 2,
		Sender:  Sender,
		Table: Table{
			Lists:  []uint64{ringregistry.AllowBit, ringregistry.BlockBit, ringregistry.FrozenBit},
			Rules:  []Rule{Require(policy.SubjectOutputOwner, ringregistry.AllowBit), Forbid(policy.SubjectSender, ringregistry.FrozenBit)},
			Limits: []OutflowLimit{{Asset: AssetA, Cap: 1000, CosignAbove: 500}},
		},
		Own:     map[int64]Record{Sender: Record{Lists: ringregistry.AllowBit}, Alice: Record{Lists: ringregistry.AllowBit}, Bob: Record{Lists: ringregistry.AllowBit}},
		Curator: map[int64]Record{},
		Slots:   []Slot{{Owner: Alice, Asset: AssetA, Amount: 300}, {Owner: Sender, Asset: AssetA, Amount: 200}},
	}
}

func Anonymous() World {
	w := Confidential()

	return w
}

func Four() World {
	w := Confidential()
	w.Outputs = 4
	w.Table.Rules = append(w.Table.Rules, Require(policy.SubjectAsset, ringregistry.AllowBit))
	w.Own[AssetA], w.Own[AssetB] = Record{Lists: ringregistry.AllowBit}, Record{Lists: ringregistry.AllowBit}
	w.Slots = []Slot{{Owner: Alice, Asset: AssetA, Amount: 100}, {Owner: Bob, Asset: AssetB, Amount: 1000}, {Owner: Sender, Asset: AssetA, Amount: 50}}
	return w
}

func Wide8() World {
	w := Four()
	w.Outputs = 8
	for _, m := range []int64{Carol, Dave, Erin, Frank, Grace} {
		w.Own[m] = Record{Lists: ringregistry.AllowBit}
	}
	w.Own[AssetC] = Record{Lists: ringregistry.AllowBit}
	w.Slots = []Slot{
		{Owner: Alice, Asset: AssetA, Amount: 100}, {Owner: Bob, Asset: AssetA, Amount: 100},
		{Owner: Carol, Asset: AssetB, Amount: 100}, {Owner: Dave, Asset: AssetB, Amount: 100},
		{Owner: Erin, Asset: AssetC, Amount: 100}, {Owner: Sender, Asset: AssetA, Amount: 50},
		{Owner: Sender, Asset: AssetC, Amount: 50},
	}
	return w
}

// MemberWorlds is the honest world of every member key capacity.
var MemberWorlds = map[int]func() World{2: Confidential, 4: Four, 8: Wide8}

// Delegate is a move on the authority rail, no rule or cap binds it.
func Delegate(outputs int) World {
	w := Four()
	w.Outputs, w.Delegate = outputs, true
	return w
}

// Require admits a subject on any of lists, as Rule::require_any does.
func Require(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModePresent, Mask: lists}
}

// Forbid refuses only a subject on every one of lists, as Rule::forbid_only_on_all does.
func Forbid(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModeAbsent, Mask: lists}
}
