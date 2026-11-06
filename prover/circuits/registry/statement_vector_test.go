package registry

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type keyStatementCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	RingID          frontend.Variable
	Member          frontend.Variable
	NullifierPk     frontend.Variable
	ListTag         frontend.Variable
	AuditorPubkey   [33]frontend.Variable
	EphU            [32]frontend.Variable
	Ciphertext      [64]frontend.Variable
}

func (c *keyStatementCircuit) Define(api frontend.API) error {
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, append([]frontend.Variable{4}, c.EphU[:]...)),
		Ciphertext: c.Ciphertext[:],
	}
	statement := (&RegisterKeyCircuit{RingID: c.RingID, Member: c.Member}).statement(api, c.NullifierPk, c.ListTag, sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// The Rust ciphertext is no sealed envelope.
func TestRegisterKeyStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		RegisterKey struct {
			RingID          string `json:"ring_id"`
			Member          string `json:"member"`
			NullifierPk     string `json:"nullifier_pk"`
			ListTag         string `json:"list_tag"`
			AuditorPubkey   string `json:"auditor_pubkey"`
			EphU            string `json:"eph_u"`
			Ciphertext      string `json:"ciphertext"`
			PublicInputHash string `json:"public_input_hash"`
		} `json:"register_key"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.RegisterKey
	witness := &keyStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		RingID:          ringtest.VectorField(t, v.RingID),
		Member:          ringtest.VectorField(t, v.Member),
		NullifierPk:     ringtest.VectorField(t, v.NullifierPk),
		ListTag:         ringtest.VectorField(t, v.ListTag),
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphU[:], ringtest.VectorWires(t, v.EphU, 32))
	copy(witness.Ciphertext[:], ringtest.VectorWires(t, v.Ciphertext, 64))
	ringtest.RequirePublicInputBound(t, &keyStatementCircuit{}, witness)
}

type applyStatementFields struct {
	PublicInputHash                                                    frontend.Variable `gnark:",public"`
	OldRoot, NewRoot, OldNextIndex, NewNextIndex, ChainStart, ChainEnd frontend.Variable
	Count                                                              frontend.Variable
}

func (f applyStatementFields) records() ApplyRecordsCircuit {
	return ApplyRecordsCircuit{
		OldRoot: f.OldRoot, NewRoot: f.NewRoot, OldNextIndex: f.OldNextIndex, NewNextIndex: f.NewNextIndex,
		ChainStart: f.ChainStart, ChainEnd: f.ChainEnd, Count: f.Count,
	}
}

type publicRecordsStatementCircuit struct {
	applyStatementFields
	Restrictive frontend.Variable
}

func (c *publicRecordsStatementCircuit) Define(api frontend.API) error {
	records := c.records()
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, records.statement(c.Restrictive)))
	return nil
}

type privateRecordsStatementCircuit struct {
	applyStatementFields
	Restrictive, PrivateWrites, TrackingRoot frontend.Variable
}

func (c *privateRecordsStatementCircuit) Define(api frontend.API) error {
	statement := (&PrivateApplyRecordsCircuit{ApplyRecordsCircuit: c.records(), PrivateWrites: c.PrivateWrites, TrackingRoot: c.TrackingRoot}).statement(c.Restrictive)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

type enrollmentsStatementCircuit struct {
	applyStatementFields
}

func (c *enrollmentsStatementCircuit) Define(api frontend.API) error {
	statement := (&ApplyEnrollmentsCircuit{OldRoot: c.OldRoot, NewRoot: c.NewRoot, OldNextIndex: c.OldNextIndex, NewNextIndex: c.NewNextIndex, ChainStart: c.ChainStart, ChainEnd: c.ChainEnd, Count: c.Count}).statement()
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

type applyStatementVector struct {
	OldRoot         string  `json:"old_root"`
	NewRoot         string  `json:"new_root"`
	OldNextIndex    uint32  `json:"old_next_index"`
	NewNextIndex    uint32  `json:"new_next_index"`
	ChainStart      string  `json:"chain_start"`
	ChainEnd        string  `json:"chain_end"`
	Count           uint64  `json:"count"`
	Restrictive     bool    `json:"restrictive"`
	PrivateWrites   uint16  `json:"private_writes"`
	TrackingRoot    *string `json:"tracking_root"`
	PublicInputHash string  `json:"public_input_hash"`
}

func (v applyStatementVector) fields(t *testing.T) applyStatementFields {
	t.Helper()
	return applyStatementFields{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		OldRoot:         ringtest.VectorField(t, v.OldRoot), NewRoot: ringtest.VectorField(t, v.NewRoot),
		OldNextIndex: v.OldNextIndex, NewNextIndex: v.NewNextIndex,
		ChainStart: ringtest.VectorField(t, v.ChainStart), ChainEnd: ringtest.VectorField(t, v.ChainEnd), Count: v.Count,
	}
}

func TestApplyStatementsMatchRustVector(t *testing.T) {
	var vectors struct {
		ApplyRecords       applyStatementVector `json:"apply_records"`
		ApplyRecordsPublic applyStatementVector `json:"apply_records_public"`
		ApplyEnrollments   applyStatementVector `json:"apply_enrollments"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	private := vectors.ApplyRecords
	if private.TrackingRoot == nil {
		t.Fatal("the private apply vector names no tracking root")
	}
	ringtest.RequirePublicInputBound(t, &privateRecordsStatementCircuit{}, &privateRecordsStatementCircuit{
		applyStatementFields: private.fields(t), Restrictive: ringtest.Bit(private.Restrictive),
		PrivateWrites: uint64(private.PrivateWrites), TrackingRoot: ringtest.VectorField(t, *private.TrackingRoot),
	})
	public := vectors.ApplyRecordsPublic
	ringtest.RequirePublicInputBound(t, &publicRecordsStatementCircuit{}, &publicRecordsStatementCircuit{applyStatementFields: public.fields(t), Restrictive: ringtest.Bit(public.Restrictive)})
	ringtest.RequirePublicInputBound(t, &enrollmentsStatementCircuit{}, &enrollmentsStatementCircuit{applyStatementFields: vectors.ApplyEnrollments.fields(t)})
}
