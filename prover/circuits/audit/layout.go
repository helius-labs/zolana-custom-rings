// Chooses the fields an auditor disclosure contains. The proof must disclose
// exactly the fields the program expects for the transfer, so no field the
// auditor needs can be left out.
//
// Read after audit/audit.go, shared/disclosure.go, ringgadget/count.go. Read
// before audit/delivered.go, audit/anonymous.go.

package audit

import (
	"math/bits"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Flags of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const (
	// LayoutExits is set exactly when a published UTXO exits, SeedOut then opens the disclosure.
	LayoutExits = 1 << iota
	// LayoutEscrow is the config's key escrow, the policy proof escrows every output nullifier key the disclosure leaves out.
	LayoutEscrow
	// LayoutReserved is free in every key, the program sends it clear.
	LayoutReserved
	// LayoutFullOpenings is the anonymous entry layout, every spent UTXO opens in the disclosure.
	LayoutFullOpenings
)

const layoutBits = 4

type auditLayout struct {
	flags       [layoutBits]frontend.Variable
	free, fixed int
}

// selected is 1 exactly when the statement's varied flags equal those of set.
type layoutChoice struct {
	set      int
	selected frontend.Variable
}

// disclosureLayout publishes fields in order, the prefix of an end's length under that end's selector.
type disclosureLayout struct {
	selected frontend.Variable
	fields   []frontend.Variable
	ends     []layoutEnd
}

type layoutEnd struct {
	length   int
	selected frontend.Variable
}

// decodeLayout pins every flag outside free to its bit of fixed.
func decodeLayout(api frontend.API, layout frontend.Variable, free, fixed int) auditLayout {
	if free&fixed != 0 {
		panic("audit: a layout flag is both free and fixed")
	}
	// The decomposition bounds the layout to its flags.
	l := auditLayout{flags: [layoutBits]frontend.Variable(api.ToBinary(layout, layoutBits)), free: free, fixed: fixed}
	for i, flag := range l.flags {
		if free&(1<<i) == 0 {
			// A pinned flag names the one layout the key proves.
			api.AssertIsEqual(flag, fixed>>i&1)
		}
	}
	return l
}

func (l auditLayout) flag(f int) frontend.Variable {
	return l.flags[bits.TrailingZeros(uint(f))]
}

// assertExits pins the exits flag to the slots, a disclosure without SeedOut holds no exit.
func (l auditLayout) assertExits(api frontend.API, slots []outputSlot) {
	exits := frontend.Variable(0)
	for _, slot := range slots {
		exits = api.Add(exits, slot.exit)
	}
	api.AssertIsEqual(l.flag(LayoutExits), ringgadget.IsNonZero(api, exits))
}

func (c layoutChoice) has(f int) bool {
	return c.set&f != 0
}

// choices is every assignment of the free flags in vary over the pinned ones, the statement selects exactly one.
func (l auditLayout) choices(api frontend.API, vary int) []layoutChoice {
	if vary&^l.free != 0 {
		panic("audit: a varied layout flag is pinned")
	}
	choices := []layoutChoice{{set: l.fixed, selected: 1}}
	for i, flag := range l.flags {
		if vary&(1<<i) == 0 {
			continue
		}
		next := make([]layoutChoice, 0, 2*len(choices))
		for _, c := range choices {
			next = append(next,
				layoutChoice{set: c.set, selected: api.Mul(c.selected, api.Sub(1, flag))},
				layoutChoice{set: c.set | 1<<i, selected: api.Mul(c.selected, flag)},
			)
		}
		choices = next
	}
	return choices
}

func (e auditEnvelope) seedOut(c layoutChoice) []frontend.Variable {
	if c.has(LayoutExits) {
		return []frontend.Variable{e.outputSeed}
	}
	return nil
}

// fixed publishes every field.
func (c layoutChoice) fixed(fields []frontend.Variable) disclosureLayout {
	return disclosureLayout{selected: c.selected, fields: fields, ends: []layoutEnd{{length: len(fields), selected: c.selected}}}
}

// countedTail opens its first published(n) fields under a count of n.
type countedTail struct {
	fields    []frontend.Variable
	published func(n int) int
}

// uniformTail publishes whole records of one width.
func uniformTail(records [][]frontend.Variable) countedTail {
	width := len(records[0])
	tail := countedTail{published: func(n int) int { return n * width }}
	for _, record := range records {
		if len(record) != width {
			panic("audit: disclosure records differ in width")
		}
		tail.fields = append(tail.fields, record...)
	}
	return tail
}

// counted publishes head and then the tail fields the count opens.
func (c layoutChoice) counted(api frontend.API, head []frontend.Variable, tail countedTail, count ringgadget.Count) disclosureLayout {
	l := disclosureLayout{selected: c.selected, fields: slices.Concat(head, tail.fields)}
	for k, oneHot := range count.OneHot {
		l.ends = append(l.ends, layoutEnd{length: len(head) + tail.published(count.Candidate(k)), selected: api.Mul(c.selected, oneHot)})
	}
	return l
}

// disclose is HashChain4 over the fields of the layout the statement selects, field j enciphered with CROD pad j.
func (e auditEnvelope) disclose(api frontend.API, choices []layoutChoice, layoutOf func(layoutChoice) disclosureLayout) frontend.Variable {
	layouts := make([]disclosureLayout, len(choices))
	width := 0
	for i, choice := range choices {
		layouts[i] = layoutOf(choice)
		width = max(width, len(layouts[i].fields))
	}
	ciphertext := shared.DisclosurePad(api, shared.DisclosurePadDomain, e.packedTxViewingSk, e.salt, width)
	ends := shared.Zeros(width)
	for _, l := range layouts {
		for j, field := range l.fields {
			ciphertext[j] = api.Add(ciphertext[j], api.Mul(l.selected, field))
		}
		for _, end := range l.ends {
			ends[end.length-1] = api.Add(ends[end.length-1], end.selected)
		}
	}
	// Exactly one end is selected, its length the field count the program reads.
	return ringgadget.HashPrefix4(api, ciphertext, ends)
}
