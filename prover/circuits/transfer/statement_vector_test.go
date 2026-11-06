// Pins the statement, the signer chain and the pool capacities to their Rust twins over shared vectors.

package transfer_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type statementOutputVector struct {
	Hash   string `json:"hash"`
	Record string `json:"record"`
	Tail   string `json:"tail,omitempty"`
}

type withdrawalVector struct {
	Owner  string `json:"owner"`
	Asset  string `json:"asset"`
	Amount uint64 `json:"amount"`
}

// transferStatementVector holds every preimage go_vectors.rs reads, one per chain and digest position.
type transferStatementVector struct {
	Name                string                  `json:"name"`
	Family              string                  `json:"family"`
	InProof             bool                    `json:"in_proof"`
	PublicOwners        bool                    `json:"public_owners"`
	Delegate            bool                    `json:"delegate"`
	ApprovalMask        uint64                  `json:"approval_mask"`
	ApprovalTotals      string                  `json:"approval_totals"`
	SignerDataCounts    uint64                  `json:"signer_data_counts"`
	NoSpend             bool                    `json:"no_spend"`
	FirstNullifier      string                  `json:"first_nullifier"`
	RingID              string                  `json:"ring_id"`
	TxViewingU          string                  `json:"tx_viewing_u"`
	AuditorPubkey       string                  `json:"auditor_pubkey"`
	Envelope            string                  `json:"envelope"`
	Salt                string                  `json:"salt"`
	Layout              int64                   `json:"layout"`
	OutputCapacity      int                     `json:"output_capacity"`
	Outputs             []statementOutputVector `json:"outputs"`
	InputCount          int                     `json:"input_count"`
	InputNullifierChain string                  `json:"input_nullifier_chain"`
	PrivateTxHash       string                  `json:"private_tx_hash"`
	Sender              *string                 `json:"sender"`
	PartyIdentities     []string                `json:"party_identities"`
	SignerSlots         int                     `json:"signer_slots"`
	Signers             []string                `json:"signers"`
	SignerCount         int                     `json:"signer_count"`
	SignerChain         string                  `json:"signer_chain"`
	PolicyHash          string                  `json:"policy_hash"`
	OwnRoot             string                  `json:"own_root"`
	CuratorRoot         string                  `json:"curator_root"`
	TrackingRoot        string                  `json:"tracking_root"`
	PublicAssets        []string                `json:"public_assets"`
	PublicAmounts       []string                `json:"public_amounts"`
	PublicGross         []string                `json:"public_gross"`
	Withdrawals         []withdrawalVector      `json:"withdrawals"`
	WithdrawalHash      string                  `json:"withdrawal_hash"`
	Elements            []string                `json:"elements"`
	PublicInputHash     string                  `json:"public_input_hash"`
}

func hexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = ringtest.FieldHex(value)
	}
	return out
}

func vectorOf(t *testing.T, name, family string, s ringtransfer.Statement, run []*big.Int, slots int, p *policy.Policy, elements []*big.Int) transferStatementVector {
	t.Helper()
	v := transferStatementVector{
		Name: name, Family: family, ApprovalMask: s.ApprovalMask.Uint64(), ApprovalTotals: ringtest.FieldHex(s.ApprovalTotals), SignerDataCounts: s.SignerDataCounts.Uint64(), NoSpend: s.NoSpend,
		FirstNullifier: ringtest.FieldHex(s.Head.FirstNullifier), RingID: ringtest.FieldHex(s.Head.RingProgramID),
		TxViewingU: hex.EncodeToString(s.Head.TxViewingU[:]), AuditorPubkey: hex.EncodeToString(s.Head.AuditorPubkey[:]),
		Envelope: hex.EncodeToString(s.Head.Envelope), Salt: hex.EncodeToString(s.Head.Salt[:]), Layout: s.Head.Layout,
		OutputCapacity: len(s.Outputs), InputCount: s.InputCount, PrivateTxHash: ringtest.FieldHex(s.PrivateTxHash),
		SignerSlots: slots, Signers: append([]string{}, hexes(run)...), SignerCount: s.SignerCount, SignerChain: ringtest.FieldHex(s.SignerChain),
		PolicyHash: ringtest.FieldHex(s.PolicyHash), OwnRoot: ringtest.FieldHex(s.OwnRoot), CuratorRoot: ringtest.FieldHex(s.CuratorRoot),
		TrackingRoot: ringtest.FieldHex(s.TrackingRoot), InputNullifierChain: ringtest.FieldHex(s.InputNullifierChain),
		PublicAssets: hexes(s.PublicAssets[:]), PublicAmounts: hexes(s.PublicNets[:]), PublicGross: hexes(s.PublicGross[:]),
		WithdrawalHash: ringtest.FieldHex(s.WithdrawalHash), Elements: hexes(elements), PublicInputHash: ringtest.FieldHex(spptest.MustHashChain4(t, elements)),
		Withdrawals: []withdrawalVector{},
	}
	for _, leg := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		v.Withdrawals = append(v.Withdrawals, withdrawalVector{Owner: ringtest.FieldHex(ringtest.AsBigInt(leg.Owner)), Asset: ringtest.FieldHex(ringtest.AsBigInt(leg.Asset)), Amount: ringtest.AsBigInt(leg.Amount).Uint64()})
	}
	for _, output := range s.Outputs {
		if output.Omitted {
			continue
		}
		o := statementOutputVector{Hash: ringtest.FieldHex(output.Hash), Record: hex.EncodeToString(output.Record)}
		if output.Tail != nil {
			o.Tail = hex.EncodeToString(output.Tail)
		}
		v.Outputs = append(v.Outputs, o)
	}
	return v
}

// fixedStatementElements is TRANSFER_FIXED_ELEMENTS less the sender, the sender and party cells, the public slots and the close add to it.
const fixedStatementElements = 10 + 3 + 4 + 4 + 3 + 2 + 4 + 1

func confidentialCase(t *testing.T, name string, w ringtransfer.Confidential) transferStatementVector {
	t.Helper()
	b := w.Build(t)
	values, elements := b.Values(t), b.Statement(t)
	if want := fixedStatementElements + 1 + shared.AnonymousParties + 9 + 1; len(elements) != want {
		t.Fatalf("%s holds %d elements, the statement fixes %d", name, len(elements), want)
	}
	v := vectorOf(t, name, "confidential", values, b.Run, w.Shape.Inputs, &b.Circuit.Policy, elements)
	v.InProof, v.Delegate = values.RailBits[0], values.RailBits[2]
	sender := ringtest.FieldHex(values.Cells[0])
	v.Sender = &sender
	requireSolved(t, b.Circuit)
	return v
}

func anonymousCase(t *testing.T, name string, w ringtransfer.Anonymous) transferStatementVector {
	t.Helper()
	b := w.Build(t)
	values, elements := b.Values(t), b.Statement(t)
	if want := fixedStatementElements + 1 + shared.AnonymousParties + 9 + 1; len(elements) != want {
		t.Fatalf("%s holds %d elements, the statement fixes %d", name, len(elements), want)
	}
	v := vectorOf(t, name, "anonymous", values, b.Run, w.Shape.Inputs, &b.Circuit.Policy, elements)
	v.PublicOwners, v.Delegate = w.Rail == ringtransfer.PublicOwners, values.RailBits[2]
	v.PartyIdentities = hexes(values.Cells[1:])
	requireSolved(t, b.Circuit)
	return v
}

// The pinned honest witnesses solve their keys, a Rust or TypeScript builder reaching these elements from the preimages reaches a statement the key proves.
func TestTransferStatementVector(t *testing.T) {
	asset := ringtransfer.Asset(t)
	legs := []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: asset, Amount: 10}}
	public := []ringtransfer.PublicSlot{{Asset: asset, Net: -10, Gross: 10}}
	compact := ringtransfer.Signed(transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4})
	compact.Exits, compact.Omitted = []int{}, 1
	coOwned := ringtransfer.Signed(confidential2)
	coOwned.CoOwners = []*big.Int{coOwner}
	inProofCoOwned := onRail(confidential2, ringtransfer.InProof)
	inProofCoOwned.CoOwners = []*big.Int{coOwner}
	withData := ringtransfer.Signed(dataKey2)
	withData.HasData = true
	entered := ringtransfer.Signed(confEntry2)
	entered.DefaultInput = true
	noSpend := onAnonymous(anonymous2, ringtransfer.PublicOwners)
	noSpend.PublicFunded = true
	withCoOwner := ringtransfer.Hidden(anonymous2)
	withCoOwner.CoOwners = []*big.Int{coOwner}
	omitted := ringtransfer.Hidden(transfer.Shape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4})
	omitted.Omitted = 1
	withdrawing := ringtransfer.Hidden(anonymous2)
	withdrawing.Withdrawals, withdrawing.Public = legs, public
	anonData := ringtransfer.Hidden(anonData2)
	anonData.HasData = true
	ringtest.PinVector(t, "audit/transfer_statement.json", map[string]any{
		"description": "Honest statements of the Go transfer fixtures, each solves its key, with every preimage of a chain or digest position. Every rail: head(10), in_proof, hidden, delegate, approval_mask, approval_totals, signer_data_counts, no_spend, output_count, output_chain, record_chain, tail_chain, input_count, input_nullifier_chain, private_tx_hash, sender, parties, signer_count, signer_chain, policy_hash, own_root, curator_root, tracking_root, (asset, net, gross) * 3, withdrawal_hash, length. outputs lists the published slots, chains zero fill to output_capacity, tail_chain is zero while no slot carries a tail. signer_chain is HashChain4(signers, zeros up to signer_slots), zero on an empty run. withdrawal_hash is HashChain4(CRPW, count, owner, asset, amount per leg). envelope_digest is Poseidon(u32 len, HashChain4(pack_left31(bytes))). public_input_hash = HashChain4(elements). Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases": []transferStatementVector{
			confidentialCase(t, "signer", ringtransfer.Signed(confidential2)),
			confidentialCase(t, "signer_two_owners", coOwned),
			confidentialCase(t, "in_proof", onRail(confidential2, ringtransfer.InProof)),
			confidentialCase(t, "in_proof_co_owner", inProofCoOwned),
			confidentialCase(t, "authority", onRail(confidential2, ringtransfer.Delegate)),
			confidentialCase(t, "signer_compact", compact),
			confidentialCase(t, "signer_data", withData),
			confidentialCase(t, "signer_entry", entered),
			anonymousCase(t, "hidden", ringtransfer.Hidden(anonymous2)),
			anonymousCase(t, "hidden_co_owner", withCoOwner),
			anonymousCase(t, "hidden_compact", omitted),
			anonymousCase(t, "hidden_withdrawal", withdrawing),
			anonymousCase(t, "hidden_data", anonData),
			anonymousCase(t, "hidden_entry", ringtransfer.Hidden(entry2)),
			anonymousCase(t, "public_owners", onAnonymous(anonymous2, ringtransfer.PublicOwners)),
			anonymousCase(t, "public_owners_no_spend", noSpend),
			anonymousCase(t, "anonymous_delegate", onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)),
		},
	})
}

type signerSetCase struct {
	Name    string   `json:"name"`
	Slots   int      `json:"slots"`
	Signers []string `json:"signers"`
	Chain   string   `json:"signer_chain"`
}

// Every language rebuilds one chain per run, an empty run reads zero at any slot count.
func TestSignerSetVector(t *testing.T) {
	run := func(name string, slots int, signers ...*big.Int) signerSetCase {
		return signerSetCase{Name: name, Slots: slots, Signers: append([]string{}, hexes(signers)...), Chain: ringtest.FieldHex(ringaudit.SignerChain(t, signers, slots))}
	}
	ringtest.PinVector(t, "audit/signer_set.json", map[string]any{
		"description": "signer_chain over the SPP owner signer run. A count of zero binds chain zero and every signer slot zero on every rail, else HashChain4(identity_0 .. identity_{count-1}, 0 .. 0 up to slots). Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases": []signerSetCase{
			run("empty on a confidential key", 24),
			run("empty on an entry key", 8),
			run("one owner", 24, coOwner),
			run("two owners in run order", 24, coOwner, otherOwner),
			run("the same owners reordered", 24, otherOwner, coOwner),
			run("one owner on a smaller class", 5, coOwner),
		},
	})
}

type poolCapacity struct {
	Key      string `json:"key"`
	Own      int    `json:"own"`
	Curator  int    `json:"curator"`
	Tracking int    `json:"tracking"`
}

// The pools a key compiles are the formula Rust's RingCircuit::record_pools keeps.
func TestPoolCapacityVector(t *testing.T) {
	var keys []poolCapacity
	for _, shape := range transfer.Shapes {
		c, err := transfer.NewTransferCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, poolCapacity{shape.String(), c.RecordPools().Own, c.RecordPools().Curator, c.TrackingPoolSize()})
	}
	ringtest.PinVector(t, "policy/pool_capacity.json", map[string]any{
		"description": "The pools each transfer key compiles. distinct = S + 2 * N + w, own = distinct + max(min(w, 3), 3), curator = distinct + min(w, 3), tracking = S + N + W with W the withdrawal owner rows a key holds. Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"keys":        keys,
	})
}
