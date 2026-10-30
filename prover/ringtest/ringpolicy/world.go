// Package ringpolicy builds honest witnesses of the policy keys from a World.
package ringpolicy

import (
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
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
	// Outputs is the member key's capacity, zero selects the delegate key of Shape.
	Outputs                                int
	WithdrawalCapacity                     int
	OwnOnly                                bool
	Withdrawals                            []Slot
	Shape                                  transaction.Shape
	Anonymous, KeyEscrow, ApprovalRequired bool
	Sender                                 int64
	Table                                  Table
	Own, Curator                           map[int64]Record
	Slots, Inputs                          []Slot
	Public                                 []PublicSlot
	// Records sizes the record pools, a zero capacity takes the key's maximum.
	Records policy.RecordPoolShape
}

// Table is a policy table of ringregistry list bits, a list reads the curator registry when Curator holds its bit.
type Table struct {
	Lists   []uint64
	Curator map[uint64]bool
	Rules   []Rule
	Inline  []InlineLimit
	Limits  []OutflowLimit
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

// Record is one member's registry record, a registered member escrows Poseidon(nullifierPk, ctHash) of its outputs.
type Record struct {
	Lists      uint64
	Registered bool
}

// Slot is one output or input, a zero owner leaves it a dummy unless Unowned holds.
type Slot struct {
	Owner, Asset  int64
	Amount        uint64
	Exit, Unowned bool
}

type PublicSlot struct {
	Asset, Amount int64
}

func Confidential() World {
	return World{
		Outputs:   2,
		KeyEscrow: true,
		Sender:    Sender,
		Table: Table{
			Lists:  []uint64{ringregistry.AllowBit, ringregistry.BlockBit, ringregistry.FrozenBit},
			Rules:  []Rule{Require(policy.SubjectOutputOwner, ringregistry.AllowBit), Forbid(policy.SubjectSender, ringregistry.FrozenBit)},
			Limits: []OutflowLimit{{Asset: AssetA, Cap: 1000, CosignAbove: 500}},
		},
		Own:     map[int64]Record{Sender: Escrowed(ringregistry.AllowBit), Alice: Escrowed(ringregistry.AllowBit), Bob: Escrowed(ringregistry.AllowBit)},
		Curator: map[int64]Record{},
		Slots:   []Slot{{Owner: Alice, Asset: AssetA, Amount: 300}, {Owner: Sender, Asset: AssetA, Amount: 200}},
	}
}

func Anonymous() World {
	w := Confidential()
	w.Anonymous, w.KeyEscrow = true, false
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
		w.Own[m] = Escrowed(ringregistry.AllowBit)
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

func Wide16() World {
	w := Wide8()
	w.Outputs = 16
	w.Slots = append(w.Slots, Slot{Owner: Frank, Asset: AssetC, Amount: 100}, Slot{Owner: Grace, Asset: AssetB, Amount: 100}, Slot{Owner: Sender, Asset: AssetB, Amount: 50})
	return w
}

// MemberWorlds is the honest world of every member key capacity.
var MemberWorlds = map[int]func() World{2: Confidential, 4: Four, 8: Wide8, 16: Wide16}

func Delegate(shape transaction.Shape) World {
	w := Four()
	w.Outputs, w.Shape = 0, shape
	w.Inputs = []Slot{{Owner: Sender, Asset: AssetA, Amount: 150}, {Owner: Sender, Asset: AssetB, Amount: 100}}[:min(2, shape.NInputs)]
	return w
}

func Escrowed(lists uint64) Record {
	return Record{Lists: lists, Registered: true}
}

// Require admits a subject on any of lists, as Rule::require_any does.
func Require(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModePresent, Mask: lists}
}

// Forbid refuses only a subject on every one of lists, as Rule::forbid_all does.
func Forbid(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModeAbsent, Mask: lists}
}
