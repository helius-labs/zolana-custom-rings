package audit_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type statementVectors struct {
	Audit []auditStatementVector `json:"audit"`
}

type auditStatementVector struct {
	PartyIdentities  []string                `json:"party_identities"`
	Kind             string                  `json:"kind"`
	FirstNullifier   string                  `json:"first_nullifier"`
	RingProgramID    string                  `json:"ring_id"`
	TxViewingU       string                  `json:"tx_viewing_u"`
	AuditorPubkey    string                  `json:"auditor_pubkey"`
	EphU             string                  `json:"eph_u"`
	Sealed           string                  `json:"sealed"`
	Salt             string                  `json:"salt"`
	Layout           int64                   `json:"layout"`
	Outputs          []statementOutputVector `json:"outputs"`
	Disclosure       []string                `json:"disclosure"`
	PrivateTxHash    string                  `json:"private_tx_hash"`
	Sender           string                  `json:"sender"`
	SenderCommitment string                  `json:"sender_commitment"`
	Elements         []string                `json:"elements"`
	PublicInputHash  string                  `json:"public_input_hash"`
}

type statementOutputVector struct {
	Kind string `json:"kind"`
	Hash string `json:"hash"`
	U    string `json:"u"`
	Body string `json:"body"`
}

// The host builders every honest witness solves against rebuild the program's audit statements of the Rust vector.
func TestAuditStatementsMatchRustVectors(t *testing.T) {
	var vectors statementVectors
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	kinds := map[string]bool{}
	for _, v := range vectors.Audit {
		t.Run(v.Kind, func(t *testing.T) {
			head := ringaudit.AuditHead{
				FirstNullifier: ringtest.VectorField(t, v.FirstNullifier),
				RingProgramID:  ringtest.VectorField(t, v.RingProgramID),
				TxViewingU:     [32]byte(ringtest.VectorBytes(t, v.TxViewingU, 32)),
				AuditorPubkey:  [33]byte(ringtest.VectorBytes(t, v.AuditorPubkey, 33)),
				EphU:           [32]byte(ringtest.VectorBytes(t, v.EphU, 32)),
				Sealed:         ringtest.VectorBytes(t, v.Sealed, 32),
				Salt:           [16]byte(ringtest.VectorBytes(t, v.Salt, 16)),
				Layout:         v.Layout,
			}
			outputs := make([]ringaudit.StatementOutput, len(v.Outputs))
			for i, o := range v.Outputs {
				outputs[i] = ringaudit.StatementOutput{Hash: ringtest.VectorField(t, o.Hash), Exit: o.Kind == "exit"}
				if o.U != "" {
					outputs[i].U = [32]byte(ringtest.VectorBytes(t, o.U, 32))
				}
				if o.Body != "" {
					outputs[i].Body = ringtest.VectorBytes(t, o.Body, shared.BodyLen)
				}
			}
			disclosure := make([]*big.Int, len(v.Disclosure))
			for i, field := range v.Disclosure {
				disclosure[i] = ringtest.VectorField(t, field)
			}
			var elements []*big.Int
			switch v.Kind {
			case "delivered":
				elements = ringaudit.DeliveredStatement(t, head, outputs, disclosure)
			case "delivered_sender":
				elements = ringaudit.DeliveredSenderStatement(t, head, outputs, disclosure, ringtest.VectorField(t, v.PrivateTxHash), ringtest.VectorField(t, v.Sender))
			case "anonymous":
				elements = ringaudit.AnonymousStatement(t, head, outputs, disclosure, ringaudit.AnonymousTail{
					PrivateTxHash:    ringtest.VectorField(t, v.PrivateTxHash),
					SenderCommitment: ringtest.VectorField(t, v.SenderCommitment),
					PartyIdentities:  [3]*big.Int{ringtest.VectorField(t, v.PartyIdentities[0]), ringtest.VectorField(t, v.PartyIdentities[1]), ringtest.VectorField(t, v.PartyIdentities[2])},
				})
			default:
				t.Fatalf("unknown audit kind %q", v.Kind)
			}
			kinds[v.Kind] = true
			requireElements(t, elements, v.Elements, v.PublicInputHash)
		})
	}
	if len(kinds) != 3 {
		t.Fatalf("the vector covers %v, want delivered, delivered_sender and anonymous", kinds)
	}
}

func requireElements(t *testing.T, elements []*big.Int, want []string, publicInputHash string) {
	t.Helper()
	if len(elements) != len(want) {
		t.Fatalf("%d elements, the vector holds %d", len(elements), len(want))
	}
	for i, element := range elements {
		if element.Cmp(ringtest.VectorField(t, want[i])) != 0 {
			t.Errorf("element %d is %x, the vector holds %s", i, element, want[i])
		}
	}
	if hash := spptest.MustHashChain4(t, elements); hash.Cmp(ringtest.VectorField(t, publicInputHash)) != 0 {
		t.Errorf("public input %x, the vector holds %s", hash, publicInputHash)
	}
}

// program-libs/interface pins its anonymous tables to the same file.
func TestAnonymousShapesAreTheSharedVector(t *testing.T) {
	var vector struct {
		Classes []struct {
			Outputs int   `json:"outputs"`
			Classes []int `json:"classes"`
		} `json:"anonymous_audit_classes"`
		Entry struct {
			Class   int   `json:"class"`
			Outputs []int `json:"outputs"`
		} `json:"anonymous_entry"`
	}
	ringtest.ReadVector(t, "proof/ring_keyed_shapes.json", &vector)
	var commitment, entry []audit.AnonymousAuditShape
	for _, row := range vector.Classes {
		for _, class := range row.Classes {
			commitment = append(commitment, audit.AnonymousAuditShape{InputClass: class, Outputs: row.Outputs})
		}
	}
	for _, outputs := range vector.Entry.Outputs {
		entry = append(entry, audit.AnonymousAuditShape{InputClass: vector.Entry.Class, Outputs: outputs, FullOpenings: true})
	}
	if !slices.Equal(commitment, audit.AnonymousAuditShapes[:]) || !slices.Equal(entry, audit.AnonymousEntryShapes[:]) {
		t.Fatalf("anonymous shapes %v and %v, vector %v and %v", audit.AnonymousAuditShapes, audit.AnonymousEntryShapes, commitment, entry)
	}
}

// Every commitment case of the Rust auditor vector ends in the tail the Go host publishes.
func TestCommitmentTailIsTheRustDisclosure(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name   string `json:"name"`
			Key    string `json:"key"`
			Inputs []struct {
				Commitment string `json:"commitment"`
			} `json:"inputs"`
			Plaintext []string `json:"plaintext"`
		} `json:"cases"`
	}
	ringtest.ReadVector(t, "audit/audit-disclosure-anonymous.json", &vectors)
	covered := 0
	for _, c := range vectors.Cases {
		if c.Key != "commitment" {
			continue
		}
		hashes := make([]*big.Int, len(c.Inputs))
		for i, input := range c.Inputs {
			hashes[i] = ringtest.VectorField(t, input.Commitment)
		}
		tail := ringaudit.CommitmentRecords(hashes)
		written := c.Plaintext[len(c.Plaintext)-len(tail):]
		for i, field := range tail {
			if field.Cmp(ringtest.VectorField(t, written[i])) != 0 {
				t.Errorf("%s tail field %d is %x, the vector holds %s", c.Name, i, field, written[i])
			}
		}
		covered++
	}
	if covered == 0 {
		t.Fatal("the vector holds no commitment case")
	}
}
