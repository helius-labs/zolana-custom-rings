// Holds the hashes ring proofs, the programs and the SDKs compute alike. A value that differs here
// reaches the chain as a statement no verifier accepts or a note no reader rebuilds.
//
// Each hash starts with its own tag, a value made for one purpose cannot pass as another. Ring tags
// open with CR and no SPP tag does, a ring hash never answers an SPP derivation.
//
// Read first. Read before shared/disclosure.go, shared/envelope.go, audit/audit.go.

// Package shared holds the ring derivations, the auditor envelope and the SPP openings two or more ring circuits share.
package shared

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ring domains, distinct ASCII tags mirrored by program-libs/interface/src/proof/domain.rs and sdk-libs/ts/src/crypto/derivation/ring-domain.ts.
const (
	// BlindingSeedDomain = "CRBS"
	BlindingSeedDomain = 0x43524253
	// PolicyTableDomain = "CRTB"
	PolicyTableDomain = 0x43525442
	// RecordWriteDomain = "CRQW"
	RecordWriteDomain = 0x43525157
	// ApplyRecordsDomain = "CRAP"
	ApplyRecordsDomain = 0x43524150
	// RegisterKeyDomain = "CRRG"
	RegisterKeyDomain = 0x43525247
	// MergeStatementDomain = "CRMG"
	MergeStatementDomain = 0x43524d47
	// ApprovalTotalsDomain = "CRAO"
	ApprovalTotalsDomain = 0x4352414f
	// WithdrawalsDomain = "CRPW"
	WithdrawalsDomain = 0x43525057
	// TransferStatementDomain = "CRTX"
	TransferStatementDomain = 0x43525458
	// TrackingLeafDomain = "CRTK"
	TrackingLeafDomain = 0x4352544b
	// TrackingEntryDomain = "CRTQ"
	TrackingEntryDomain = 0x43525451
	// ApplyEnrollmentsDomain = "CRTA"
	ApplyEnrollmentsDomain = 0x43525441
	// ListTagDomain = "CRPT"
	ListTagDomain = 0x43525054
	// ListKeyDomain = "CRPL"
	ListKeyDomain = 0x4352504c
)

// The root of every auditor stream, mirrored by AUDIT_SHARED_SECRET in program-libs/interface/src/proof/domain.rs and DOM_SEP_CR_SHARED in sdk-libs/ts/src/crypto/audit/audit.ts.
const (
	// DomSepCRShared = "CR_S"
	DomSepCRShared = 0x43525f53
)

// Key schedule labels, distinct per ciphertext kind.
const (
	// AuditEncInfo mirrors AUDIT_STREAM_LABEL in program-libs/interface/src/proof/domain.rs.
	AuditEncInfo = "CRING/adt"
	// NfKeyEncInfo mirrors REGISTER_KEY_LABEL.
	NfKeyEncInfo = "CRING/nfk"
	// MergeEncInfo mirrors MERGE_RECORD_LABEL.
	MergeEncInfo = "CRING/mrg"
)

// ZeroNullifierPk permits nullifier derivation from the opening without a secret.
var ZeroNullifierPk, _ = new(big.Int).SetString("2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c", 16)

// SolAssetField is the native SOL asset, mirrored by SOL_ASSET_FIELD in zolana/program-libs/interface/src/lib.rs.
var SolAssetField, _ = new(big.Int).SetString("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", 16)

// BlindingSeed is SPP's blinding_seed Poseidon(CRBS, sk0, sk1, salt), every output blinding rebuilds from tx_viewing_sk.
func BlindingSeed(api frontend.API, txViewingSk [2]frontend.Variable, salt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{BlindingSeedDomain, txViewingSk[0], txViewingSk[1], salt})
}

// ListTag is Poseidon(CRPT, listSalt), the tracking leaf's commitment to the owner's one salt.
func ListTag(api frontend.API, listSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ListTagDomain, listSalt})
}

// ListKey is the member key of an owner's salted record, pseudorandom without the salt.
func ListKey(api frontend.API, owner, listSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ListKeyDomain, owner, listSalt})
}

// AnonymousParties is mirrored by ANONYMOUS_PARTIES.
const AnonymousParties = 7

// AssertAnonymousParties separates the hidden owner from the public identities
// reconstructed by the verifier. Zero denotes an absent optional party. An equal party
// would name the owner the rail hides, SPP asserts the same against its signers.
func AssertAnonymousParties(api frontend.API, owner frontend.Variable, parties []frontend.Variable) {
	for _, party := range parties {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: party, V: api.IsZero(api.Sub(owner, party))})
	}
}
