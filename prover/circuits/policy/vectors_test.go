// Pins the table hash and rule decoding to their Rust twins over shared vectors.

package policy_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

type tableRows struct {
	Sources []struct {
		ListID   int64        `json:"list_id"`
		Registry ringtest.Hex `json:"registry"`
	} `json:"sources"`
	Salted       uint64         `json:"salted"`
	Rules        []ringtest.Hex `json:"rules"`
	InlineAssets []ringtest.Hex `json:"inline_assets"`
	InlineLimits []uint64       `json:"inline_limits"`
	Limits       []struct {
		Asset       ringtest.Hex `json:"asset"`
		Cap         uint64       `json:"cap"`
		CosignAbove uint64       `json:"cosign_above"`
	} `json:"limits"`
}

// tableVector is one case program-libs/policy/tests/policy_table_vector.rs writes.
type tableVector struct {
	Name string `json:"name"`
	tableRows
	RuleParts  []ruleParts    `json:"rule_parts"`
	Fields     []ringtest.Hex `json:"fields"`
	PolicyHash ringtest.Hex   `json:"policy_hash"`
}

// ruleVector is one case program-libs/policy/tests/policy_rules_vector.rs writes.
type ruleVector struct {
	Name string `json:"name"`
	tableRows
	OwnRecords     []recordVector `json:"own_records"`
	CuratorRecords []recordVector `json:"curator_records"`
	Sender         ringtest.Hex   `json:"sender"`
	RingInputs     []struct {
		Owner  ringtest.Hex `json:"owner"`
		Asset  ringtest.Hex `json:"asset"`
		Amount uint64       `json:"amount"`
	} `json:"ring_inputs"`
	Outputs []struct {
		Ring   bool         `json:"ring"`
		Owner  ringtest.Hex `json:"owner"`
		Asset  ringtest.Hex `json:"asset"`
		Amount uint64       `json:"amount"`
	} `json:"outputs"`
	Outcome struct {
		Kind    string `json:"kind"`
		Rule    int    `json:"rule"`
		Subject string `json:"subject"`
	} `json:"outcome"`
}

type recordVector struct {
	Member ringtest.Hex `json:"member"`
	Lists  uint64       `json:"lists"`
}

// Enumerated parts carry their Rust names.
type ruleParts struct {
	Subject     string `json:"subject"`
	Mode        string `json:"mode"`
	Mask        uint16 `json:"mask"`
	Guard       string `json:"guard"`
	Threshold   uint64 `json:"threshold"`
	Alternative uint16 `json:"alternative"`
}

var (
	subjects = map[string]uint64{"output_owner": policy.SubjectOutputOwner, "sender": policy.SubjectSender, "asset": policy.SubjectAsset}
	modes    = map[string]uint64{"present": policy.ModePresent, "absent": policy.ModeAbsent}
	guards   = map[string]uint64{"always": policy.GuardAlways, "above_amount": policy.GuardAboveAmount, "above_amount_by_asset": policy.GuardAboveAmountByAsset}
)

type tableCircuit struct {
	Table      policy.Table
	PolicyHash frontend.Variable
}

func (c *tableCircuit) Define(api frontend.API) error {
	policy.DecodeTable(c.Table, api, rangecheck.New(api), c.PolicyHash)
	return nil
}

func TestPolicyTableMatchesRustVectors(t *testing.T) {
	var vectors struct {
		Cases []tableVector `json:"cases"`
	}
	ringtest.ReadVector(t, "policy/ring-policy-table.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no cases")
	}
	split := ringtest.RegisteredHint(t, "rulePartsHint")
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			if len(v.RuleParts) != len(v.Rules) {
				t.Fatalf("%d rule parts for %d rules", len(v.RuleParts), len(v.Rules))
			}
			for i, parts := range v.RuleParts {
				want := parts.values(t)
				got := make([]*big.Int, len(want))
				for k := range got {
					got[k] = new(big.Int)
				}
				if err := split(ecc.BN254.ScalarField(), []*big.Int{v.Rules[i].Int}, got); err != nil {
					t.Fatal(err)
				}
				for k := range want {
					if !got[k].IsUint64() || got[k].Uint64() != want[k] {
						t.Fatalf("rule %d part %d is %v, its vector part reads %d", i, k, got[k], want[k])
					}
				}
			}
			table := v.rows().Wires()
			fields := ringtest.ToBigInts(table.Fields())
			if len(fields) != len(v.Fields) {
				t.Fatalf("%d fields, the vector has %d", len(fields), len(v.Fields))
			}
			for i, want := range v.Fields {
				if fields[i].Cmp(want.Int) != 0 {
					t.Fatalf("field %d is %x, the vector has %x", i, fields[i], want.Int)
				}
			}
			hash := v.PolicyHash.Int
			if host := ringpolicy.TableHash(t, table); host.Cmp(hash) != 0 {
				t.Fatalf("host hash %x, the vector has %x", host, hash)
			}
			if err := test.IsSolved(&tableCircuit{}, &tableCircuit{Table: table, PolicyHash: hash}, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			other := new(big.Int).Add(hash, big.NewInt(1))
			if test.IsSolved(&tableCircuit{}, &tableCircuit{Table: table, PolicyHash: other}, ecc.BN254.ScalarField()) == nil {
				t.Fatal("a table opened under another policy_hash")
			}
		})
	}
}

// A refused transfer passes the rules before the one its vector names and fails from that rule on.
func TestPolicyRulesMatchRustVectors(t *testing.T) {
	var vectors struct {
		Cases []ruleVector `json:"cases"`
	}
	ringtest.ReadVector(t, "policy/ring-policy-rules.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no policy rule vectors")
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Outcome.Kind {
			case "pass":
				if err := v.solve(t, len(v.Rules)); err != nil {
					t.Fatalf("an admitted transfer is refused, %v", err)
				}
			case "lists":
				if err := v.solve(t, v.Outcome.Rule); err != nil {
					t.Fatalf("the rules before rule %d refuse, %v", v.Outcome.Rule, err)
				}
				for _, rules := range []int{v.Outcome.Rule + 1, len(v.Rules)} {
					section := "policy.assertPaymentRules"
					if v.Outcome.Subject == "sender" {
						section = "policy.assertSenderRules"
					}
					ringtest.RequireRefused(t, v.solve(t, rules), section)
				}
			default:
				t.Fatalf("outcome %q", v.Outcome.Kind)
			}
		})
	}
}

// values follows the circuit's split order.
func (r ruleParts) values(t *testing.T) []uint64 {
	t.Helper()
	named := func(names map[string]uint64, name string) uint64 {
		value, ok := names[name]
		if !ok {
			t.Fatalf("no Go constant for %q", name)
		}
		return value
	}
	return []uint64{named(subjects, r.Subject), named(modes, r.Mode), uint64(r.Mask), named(guards, r.Guard), r.Threshold, uint64(r.Alternative)}
}

func (v tableRows) rows() ringpolicy.Rows {
	rows := ringpolicy.Rows{Salted: v.Salted}
	for _, source := range v.Sources {
		rows.Sources = append(rows.Sources, policy.SourceWires{ListID: source.ListID, Registry: source.Registry.Int})
	}
	for _, rule := range v.Rules {
		rows.Rules = append(rows.Rules, rule.Int)
	}
	for i, asset := range v.InlineAssets {
		rows.InlineAssets, rows.InlineLimits = append(rows.InlineAssets, asset.Int), append(rows.InlineLimits, v.InlineLimits[i])
	}
	for _, limit := range v.Limits {
		rows.Limits = append(rows.Limits, ringpolicy.MintLimit{Asset: limit.Asset.Int, Cap: limit.Cap, CosignAbove: limit.CosignAbove})
	}
	return rows
}

// solve runs the smallest member key holding the outputs under the table's first rules.
func (v ruleVector) solve(t *testing.T, rules int) error {
	t.Helper()
	capacity := slices.IndexFunc(ringpolicy.OutputCapacities, func(outputs int) bool { return outputs >= len(v.Outputs) })
	if capacity < 0 {
		t.Fatalf("%d outputs exceed every transfer key", len(v.Outputs))
	}
	w := ringpolicy.World{
		Outputs: ringpolicy.OutputCapacities[capacity],
		Sender:  memberID(t, v.Sender),
		Own:     records(t, v.OwnRecords),
		Curator: records(t, v.CuratorRecords),
	}
	for _, out := range v.Outputs {
		owner := memberID(t, out.Owner)
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: owner, Asset: memberID(t, out.Asset), Amount: out.Amount, Unowned: owner == 0, Exit: !out.Ring})
	}
	for _, input := range v.RingInputs {
		w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: memberID(t, input.Owner), Asset: memberID(t, input.Asset), Amount: input.Amount})
	}
	rows := v.rows()
	rows.Rules = rows.Rules[:rules]
	b := w.BuildRows(t, rows)
	return test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
}

func records(t *testing.T, vectors []recordVector) map[int64]ringpolicy.Record {
	t.Helper()
	out := make(map[int64]ringpolicy.Record, len(vectors))
	for _, r := range vectors {
		out[memberID(t, r.Member)] = ringpolicy.Record{Lists: r.Lists}
	}
	return out
}

func memberID(t *testing.T, member ringtest.Hex) int64 {
	t.Helper()
	if !member.IsInt64() {
		t.Fatalf("member %x exceeds int64", member.Int)
	}
	return member.Int64()
}
