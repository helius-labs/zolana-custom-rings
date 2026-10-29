// Package shared holds the ring derivations, the auditor envelope and the SPP openings two or more ring circuits share.
package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ring domains, distinct ASCII tags mirrored by program-libs/interface/src/proof/domain.rs and sdk-libs/ts/src/crypto/derivation/ring-domain.ts.
const (
	// AuditStatementDomain = "CRAU"
	AuditStatementDomain = 0x43524155
	// DeliveredSlotSecretDomain = "CRDS"
	DeliveredSlotSecretDomain = 0x43524453
	// BlindingSeedDomain = "CRBS"
	BlindingSeedDomain = 0x43524253
	// SenderCommitmentDomain = "CRSC"
	SenderCommitmentDomain = 0x43525343
	// DisclosurePadDomain = "CROD"
	DisclosurePadDomain = 0x43524f44
	// PolicyStatementDomain = "CRPO"
	PolicyStatementDomain = 0x4352504f
	// PolicyTableDomain = "CRTB"
	PolicyTableDomain = 0x43525442
	// QueueWriteDomain = "CRQW"
	QueueWriteDomain = 0x43525157
	// ApplyRecordsDomain = "CRAP"
	ApplyRecordsDomain = 0x43524150
	// RegisterKeyDomain = "CRRG"
	RegisterKeyDomain = 0x43525247
	// DepositStatementDomain = "CRDP"
	DepositStatementDomain = 0x43524450
	// MergeStatementDomain = "CRMG"
	MergeStatementDomain = 0x43524d47
	// DepositBlindingDomain = "CRDB"
	DepositBlindingDomain = 0x43524442
	// WithdrawalsDomain = "CRPW"
	WithdrawalsDomain = 0x43525057
	// WithdrawalExemptionDomain = "CRWX"
	WithdrawalExemptionDomain = 0x43525758
)

// PolicyStatementVersion binds the policy statement layout, mirrored by PolicyStatement::elements in program-libs/interface/src/proof/statement.rs.
const PolicyStatementVersion = 4

// Envelope and merge pad domains, mirrored by sdk-libs/client/src/crypto/encryption/mod.rs, its merge_disclosure module and sdk-libs/ts/src/crypto/audit/audit.ts.
const (
	// DomSepCRShared = "CR_S"
	DomSepCRShared = 0x43525f53
	// MergeDisclosureDomain = "CR_MD", a merge pad under the same key never repeats an output pad.
	MergeDisclosureDomain = 0x4352_5f4d44
)

// Key schedule labels, distinct per ciphertext kind.
const (
	// AuditEncInfo is the audit stream schedule tag, mirrored by AUDIT_STREAM_INFO in program-libs/interface/src/codec/anonymous_output.rs.
	AuditEncInfo = "CRING/adt1"
	// NfKeyEncInfo separates the key ciphertext from the audit one, mirrored by NF_KEY_ENC_INFO in sdk-libs/client/src/crypto/encryption/mod.rs.
	NfKeyEncInfo   = "CRING/nfk1"
	DepositEncInfo = "CRING/dep1"
	MergeEncInfo   = "CRING/mrg1"
)

// BodyLen is be32(blinding) ‖ u64be(amount).
const BodyLen = 40

// DeliveredSlot is a delivered slot secret preimage, Agreement = pack_be(X25519(tx_viewing_sk, u)) and each key pack_be(0x04 ‖ u).
type DeliveredSlot struct {
	Agreement      [2]frontend.Variable
	TxPk           [2]frontend.Variable
	Recipient      [2]frontend.Variable
	Salt           frontend.Variable
	OutputIndex    frontend.Variable
	FirstNullifier frontend.Variable
}

// Secret is Poseidon(CRDS, dh0, dh1, txpk0, txpk1, r0, r1, salt, i, n0), the recipient rebuilds it from X25519(u_sk, tx_u).
func (s DeliveredSlot) Secret(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		DeliveredSlotSecretDomain, s.Agreement[0], s.Agreement[1], s.TxPk[0], s.TxPk[1],
		s.Recipient[0], s.Recipient[1], s.Salt, s.OutputIndex, s.FirstNullifier,
	})
}

// BlindingSeed is SPP's blinding_seed Poseidon(CRBS, sk0, sk1, salt), every output blinding rebuilds from tx_viewing_sk.
func BlindingSeed(api frontend.API, txViewingSk [2]frontend.Variable, salt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{BlindingSeedDomain, txViewingSk[0], txViewingSk[1], salt})
}

// SenderCommitment binds the anonymous audit and the member policy to one sender, private_tx_hash fixes the blinding both read.
func SenderCommitment(api frontend.API, senderPkHash, privateTxBlinding frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SenderCommitmentDomain, senderPkHash, privateTxBlinding})
}

// DepositBlinding is Poseidon(CRDB, blindingSecret), domain separated from every SPP output blinding.
func DepositBlinding(api frontend.API, blindingSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{DepositBlindingDomain, blindingSecret})
}
