package audit_test

import (
	"fmt"
	"math"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// entryShape is the cheapest entry key, its fixture spends a ring note and a default-ring note.
var entryShape = audit.AnonymousEntryShapes[0]

// Every commitment and entry key solves its honest fixture under a policy and as an audit-only transfer.
func TestAnonymousAuditSolvesEveryShape(t *testing.T) {
	for _, shape := range slices.Concat(audit.AnonymousAuditShapes[:], audit.AnonymousEntryShapes[:]) {
		t.Run(anonymousKeyName(shape), func(t *testing.T) {
			c, ok := compiledAudits[anonymousKeyName(shape)]
			if !ok {
				circuit, err := audit.NewAnonymousAuditCircuit(shape)
				if err != nil {
					t.Fatal(err)
				}
				c = &compiledAudit{cs: ringkey.Compile(t, circuit)}
			}
			a := ringaudit.NewAnonymousAudit(t, shape)
			c.requireSolved(t, a.Circuit(t))
			a.SenderCommitment = big.NewInt(0)
			c.requireSolved(t, a.Circuit(t))
		})
	}
}

// The entry key opens a ring note and a default-ring note, with and without an exit.
func TestAnonymousEntrySolvesBothLayouts(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	a := ringaudit.NewAnonymousAudit(t, entryShape)
	c.requireSolved(t, a.Circuit(t))
	a.Outputs[1] = a.NewAnonymousExit(t, 1)
	a.Layout.Exits = true
	c.requireSolved(t, a.Circuit(t))
}

// Every published input count solves on a commitment key and on the entry key, the reserved flag either way.
func TestAnonymousAuditSolvesEveryInputCount(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		c := compileAnonymous(t, shape)
		for count := 1; count <= shape.InputClass; count++ {
			t.Run(fmt.Sprintf("%s/%d", anonymousKeyName(shape), count), func(t *testing.T) {
				a := ringaudit.NewAnonymousAudit(t, shape).AtInputCount(count)
				a.Layout.Reserved = count%2 == 0
				c.requireSolved(t, a.Circuit(t))
			})
		}
	}
}

// Each case changes one value of an honest transfer of two payments, an exit and change in slots 0 to 3.
func TestAnonymousAuditRefusals(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	stranger := ringtest.Repeat(0xc3)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"ring output with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.RingDataHash = big.NewInt(5) }},
		{"exit with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[2].Utxo.RingDataHash = big.NewInt(5) }},
		{"ring output with a data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.DataHash = big.NewInt(5) }},
		{"owner key not the slot owner", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].OwnerKey[0] ^= 1 }},
		{"UTXO input at the input count", func(a *ringaudit.AnonymousAudit) { a.InputCount = 1 }},
		{"input of another owner", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].OwnerPkHash = ringtest.MustSolanaPkField(t, stranger) }},
		{"input 0 a dummy", func(a *ringaudit.AnonymousAudit) { a.Inputs[0] = ringaudit.Dummy(3, big.NewInt(0x9000)) }},
		{"committed input of the default ring", func(a *ringaudit.AnonymousAudit) { a.Inputs[1] = a.SenderUtxo(t, big.NewInt(0), 60, 52) }},
		{"SeedOut omitted with an exit published", func(a *ringaudit.AnonymousAudit) { a.Layout.Exits = false }},
		{"full openings on a commitment key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = true }},
		{"escrow flag on an anonymous key", func(a *ringaudit.AnonymousAudit) { a.Layout.Escrow = true }},
		{"ring output blinding of another slot", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.Blinding = a.Blinding(t, 0) }},
		{"exit blinding off the CRBS seed", func(a *ringaudit.AnonymousAudit) { a.Outputs[2].Utxo.Blinding = big.NewInt(0x5ec) }},
		{"sender commitment of another sender", func(a *ringaudit.AnonymousAudit) {
			a.SenderCommitment = ringprotocol.SenderCommitment(t, ringtest.MustSolanaPkField(t, stranger), a.PrivateTxBlinding)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			tc.mutate(&a)
			c.refuse(t, a.Circuit(t))
		})
	}
}

// A live amount of 2^64 - 1 solves and 2^64 fails its decomposition, on a ring output and an exit alike.
func TestAnonymousAmountsStayBelowTwoTo64(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	for name, slot := range map[string]int{"ring output": 1, "exit": 2} {
		t.Run(name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			a.Outputs[slot].Utxo.Amount = math.MaxUint64
			c.requireSolved(t, a.Circuit(t))
			assignment := a.Circuit(t)
			assignment.Outputs[slot].Output.Amount = new(big.Int).Lsh(big.NewInt(1), 64)
			c.refuse(t, assignment)
		})
	}
}

// Dummies inside the count prove only behind every spent UTXO.
func TestAnonymousCommitmentInputsKeepDummiesLast(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	c := compileAnonymous(t, shape)
	trailing := ringaudit.NewAnonymousAudit(t, shape).AtInputCount(3)
	c.requireSolved(t, trailing.Circuit(t))
	gap := trailing
	gap.Inputs = slices.Clone(trailing.Inputs)
	gap.Inputs[1], gap.Inputs[2] = gap.Inputs[2], gap.Inputs[1]
	c.refuse(t, gap.Circuit(t))
}

// A spent hash below 2^254 - q has a second 126-bit split, the prefix of hash + q, the canonical bound refuses it.
func TestAnonymousSpentPrefixRefusesTheAliasSplit(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	c := compileAnonymous(t, shape)
	q := ecc.BN254.ScalarField()
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), q)
	for blinding := int64(52); blinding < 116; blinding++ {
		a := ringaudit.NewAnonymousAudit(t, shape)
		a.Inputs[1] = a.SenderUtxo(t, a.RingProgramID, 60, blinding)
		hash := a.Inputs[1].Hash(t)
		if hash.Cmp(limit) >= 0 {
			continue
		}
		c.requireSolved(t, a.Circuit(t))
		c.refuse(t, a.Circuit(t), splitOf(t, hash, new(big.Int).Add(hash, q)))
		return
	}
	t.Fatal("no fixture hash below 2^254 - q")
}

// An even published count closes the last prefix pair with a zero half, a statement opening another half fails the binding.
func TestAnonymousPrefixPairClosesWithAZeroHalf(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	c := compileAnonymous(t, shape)
	a := ringaudit.NewAnonymousAudit(t, shape)
	records := a.InputRecords(t)
	last := len(records) - 1
	records[last] = new(big.Int).Add(records[last], big.NewInt(1))
	statement := ringaudit.AnonymousStatement(t, a.AuditHead(t, a.Layout), a.StatementOutputs(t), a.DisclosureOf(t, a.SlotBytes(t), records), a.Tail(t))
	c.refuseStatementOf(t, a.Circuit(t), statement)
}

// The widest class solves at both ends of its counts and across a pair boundary.
func TestAnonymousWideClassSolves(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 16, Outputs: 2}
	c := compileAnonymous(t, shape)
	for _, count := range []int{1, 2, 3, 15, 16} {
		t.Run(fmt.Sprintf("%s/%d", anonymousKeyName(shape), count), func(t *testing.T) {
			c.requireSolved(t, ringaudit.NewAnonymousAudit(t, shape).AtInputCount(count).Circuit(t))
		})
	}
}

// splitOf replaces the honest split of value with the split of alias.
func splitOf(t *testing.T, value, alias *big.Int) solver.Option {
	t.Helper()
	honest := ringtest.RegisteredHint(t, "/ringgadget.splitFieldHint")
	return solver.OverrideHint(solver.GetHintID(honest), func(field *big.Int, inputs, outputs []*big.Int) error {
		if inputs[0].Cmp(value) == 0 {
			return honest(field, []*big.Int{alias, inputs[1]}, outputs)
		}
		return honest(field, inputs, outputs)
	})
}

// Each case changes one value of an honest entry transfer whose input 0 is a ring note and input 1 a default-ring note.
func TestAnonymousEntryRefusals(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"input with a data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].DataHash = big.NewInt(5) }},
		{"ring note with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[0].RingDataHash = big.NewInt(5) }},
		{"input under another nullifier key than input 0", func(a *ringaudit.AnonymousAudit) {
			a.Inputs[1].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(8))
		}},
		{"input hashes on an entry key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = false }},
		{"sender key of another owner", func(a *ringaudit.AnonymousAudit) {
			a.SenderKey = ringtest.Repeat(0xc3)
			a.Outputs[1] = a.NewPayment(t, a.Change(t, 1))
			a.SenderCommitment = ringprotocol.SenderCommitment(t, a.SenderPkHash(t), a.PrivateTxBlinding)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, entryShape)
			tc.mutate(&a)
			c.refuse(t, a.Circuit(t))
		})
	}
}

// A commitment key discloses input 0's hash and the prefix of every other spent hash, a disclosure naming another note fails the statement.
func TestAnonymousDisclosesInputHashAndPrefixes(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	honest := ringaudit.NewAnonymousAudit(t, shape)
	other := honest
	other.Inputs = slices.Clone(honest.Inputs)
	other.Inputs[1].Blinding = big.NewInt(53)
	refuseOtherDisclosure(t, c, honest, other)
}

// An entry key opens every spent UTXO under input 0's nullifier key, a disclosure of another opening fails the statement.
func TestAnonymousEntryDisclosesEachOpening(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for name, edit := range map[string]func([]ringaudit.Utxo){
		"asset":         func(u []ringaudit.Utxo) { u[1].Asset = ringtest.AssetField(t, ringtest.Repeat(0x0b)) },
		"amount":        func(u []ringaudit.Utxo) { u[1].Amount++ },
		"blinding":      func(u []ringaudit.Utxo) { u[1].Blinding = big.NewInt(53) },
		"nullifier key": func(u []ringaudit.Utxo) { u[0].NullifierPk = big.NewInt(0x1234) },
	} {
		t.Run(name, func(t *testing.T) {
			honest := ringaudit.NewAnonymousAudit(t, entryShape)
			other := honest
			other.Inputs = slices.Clone(honest.Inputs)
			edit(other.Inputs)
			refuseOtherDisclosure(t, c, honest, other)
		})
	}
}

// A ring output's owner key and every UTXO's asset, amount and nullifier key reach the auditor, a disclosure of another opening fails the statement.
func TestAnonymousSlotsDiscloseTheirOpening(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	edits := map[string]func(*ringaudit.AnonymousOutput){
		"asset":         func(o *ringaudit.AnonymousOutput) { o.Utxo.Asset = ringtest.AssetField(t, ringtest.Repeat(0x0b)) },
		"amount":        func(o *ringaudit.AnonymousOutput) { o.Utxo.Amount++ },
		"nullifier key": func(o *ringaudit.AnonymousOutput) { o.Utxo.NullifierPk = big.NewInt(0x1234) },
		"owner key":     func(o *ringaudit.AnonymousOutput) { o.OwnerKey[0] ^= 1 },
	}
	for slotName, slot := range map[string]int{"ring output": 1, "exit": 2} {
		for name, edit := range edits {
			if slotName == "exit" && name == "owner key" {
				continue
			}
			t.Run(slotName+"/"+name, func(t *testing.T) {
				honest := ringaudit.NewAnonymousAudit(t, shape)
				other := honest
				other.Outputs = slices.Clone(honest.Outputs)
				edit(&other.Outputs[slot])
				refuseOtherDisclosure(t, c, honest, other)
			})
		}
	}
}

// An exit discloses no owner key and a dummy slot only zeros, a disclosure of any other slot bytes fails the statement.
func TestAnonymousMaskedSlotBytesStayZero(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 8}
	c := compileAnonymous(t, shape)
	const exit, dummy = 3, 6
	for _, tc := range []struct {
		name   string
		tamper func(a ringaudit.AnonymousAudit, slots [][]byte)
	}{
		{"exit owner key", func(a ringaudit.AnonymousAudit, slots [][]byte) { copy(slots[exit], ringaudit.ExitOwnerKey[:]) }},
		{"dummy owner key", func(a ringaudit.AnonymousAudit, slots [][]byte) { copy(slots[dummy], a.Outputs[dummy].OwnerKey[:]) }},
		{"dummy asset", func(a ringaudit.AnonymousAudit, slots [][]byte) { slots[dummy][63] = 1 }},
		{"dummy amount", func(a ringaudit.AnonymousAudit, slots [][]byte) { slots[dummy][71] = 1 }},
		{"ring output without its owner key", func(a ringaudit.AnonymousAudit, slots [][]byte) { clear(slots[0][:32]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			slots := a.SlotBytes(t)
			tc.tamper(a, slots)
			statement := ringaudit.AnonymousStatement(t, a.AuditHead(t, a.Layout), a.StatementOutputs(t), a.DisclosureOf(t, slots, a.InputRecords(t)), a.Tail(t))
			c.refuseStatementOf(t, a.Circuit(t), statement)
		})
	}
}

// refuseOtherDisclosure requires honest's statement carrying other's disclosure to fail the public input binding.
func refuseOtherDisclosure(t *testing.T, c *compiledAudit, honest, other ringaudit.AnonymousAudit) {
	t.Helper()
	statement := ringaudit.AnonymousStatement(t, honest.AuditHead(t, honest.Layout), honest.StatementOutputs(t), other.Disclosure(t), honest.Tail(t))
	c.refuseStatementOf(t, honest.Circuit(t), statement)
}

// Rebinding a forbidden party into a valid statement cannot bypass the circuit.
func TestAnonymousParties(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		c := compileAnonymous(t, shape)
		for i := range 3 {
			a := ringaudit.NewAnonymousAudit(t, shape)
			a.PartyIdentities[i] = a.SenderPkHash(t)
			c.refuse(t, a.Circuit(t))
			a.PartyIdentities[i] = big.NewInt(0)
			c.requireSolved(t, a.Circuit(t))
			assignment := a.Circuit(t)
			assignment.PartyIdentities[i] = 99 // differs from the verifier's bound identity
			c.refuseStatementOf(t, assignment, a.Statement(t))
		}
	}
}
