package audit_test

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

const fieldCountVector = "audit/ring-disclosure-counts.json"

const fieldCountDescription = "Published field counts of the audit disclosures, each record a host disclosure the audit circuit solves. " +
	"delivered takes the capacity and the exits and key_escrow flags, " +
	"anonymous the audit key, its input class, the published input count, the output count and the exits flag. " +
	"Produced by prover/circuits/audit/disclosure_test.go with WRITE_AUDIT_VECTORS=1."

type fieldCounts struct {
	Description string                `json:"description"`
	Delivered   []deliveredFieldCount `json:"delivered"`
	Anonymous   []anonymousFieldCount `json:"anonymous"`
}

type deliveredFieldCount struct {
	Outputs   int  `json:"outputs"`
	Exits     bool `json:"exits"`
	KeyEscrow bool `json:"key_escrow"`
	Fields    int  `json:"fields"`
}

type anonymousFieldCount struct {
	Key     string `json:"key"`
	Class   int    `json:"class"`
	Inputs  int    `json:"inputs"`
	Outputs int    `json:"outputs"`
	Exits   bool   `json:"exits"`
	Fields  int    `json:"fields"`
}

func TestDisclosureFieldCountsAreTheSharedVector(t *testing.T) {
	want := fieldCounts{Description: fieldCountDescription}
	for _, capacity := range audit.DeliveredAuditCapacities {
		delivered := compileDelivered(t, capacity)
		for _, layout := range []ringaudit.Layout{{Exits: true}, {}, {Exits: true, Escrow: true}, {Escrow: true}} {
			d := ringaudit.DeliveredAuditOf(t, capacity)
			if layout.Exits {
				d = ringaudit.NewDeliveredAudit(t, capacity)
			}
			d.Layout = layout
			delivered.requireSolved(t, d.Circuit(t))
			want.Delivered = append(want.Delivered, deliveredFieldCount{Outputs: capacity, Exits: layout.Exits, KeyEscrow: layout.Escrow, Fields: len(d.Disclosure(t))})
		}
	}
	type anonymousCounts struct {
		shape  audit.AnonymousAuditShape
		counts []int
	}
	anonymous := []anonymousCounts{
		{audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}, []int{1, 2, 3, 4}},
		{audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}, []int{2}},
		{audit.AnonymousAuditShape{InputClass: 4, Outputs: 8}, []int{2}},
		{audit.AnonymousAuditShape{InputClass: 16, Outputs: 2}, []int{15, 16}},
	}
	for _, shape := range audit.AnonymousEntryShapes {
		anonymous = append(anonymous, anonymousCounts{shape, []int{2}})
	}
	for _, tc := range anonymous {
		c := compileAnonymous(t, tc.shape)
		key := "commitment"
		if tc.shape.FullOpenings {
			key = "entry"
		}
		for _, count := range tc.counts {
			a := ringaudit.NewAnonymousAudit(t, tc.shape).AtInputCount(count)
			c.requireSolved(t, a.Circuit(t))
			want.Anonymous = append(want.Anonymous, anonymousFieldCount{Key: key, Class: tc.shape.InputClass, Inputs: count, Outputs: tc.shape.Outputs, Exits: a.Layout.Exits, Fields: len(a.Disclosure(t))})
		}
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := ringVectorPath(t, fieldCountVector)
	if os.Getenv("WRITE_AUDIT_VECTORS") != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(raw, encoded) {
		t.Fatalf("the host disclosures disagree with test-vectors/%s, rewrite it with WRITE_AUDIT_VECTORS=1", fieldCountVector)
	}
}

// Every prefix of a canonical hash lies below 2^InputPrefixBits and a pair of them below q.
func TestInputPrefixesPackBelowTheModulus(t *testing.T) {
	q := ecc.BN254.ScalarField()
	if top := new(big.Int).Rsh(q, 8*(32-audit.InputPrefixLen)); top.BitLen() > audit.InputPrefixBits {
		t.Fatalf("the prefix of q takes %d bits", top.BitLen())
	}
	if 2*audit.InputPrefixBits >= q.BitLen() {
		t.Fatalf("a pair of %d-bit prefixes reaches q", audit.InputPrefixBits)
	}
}

func ringVectorPath(t *testing.T, name string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate disclosure_test.go")
	}
	return filepath.Join(filepath.Dir(source), "../../../test-vectors", name)
}
