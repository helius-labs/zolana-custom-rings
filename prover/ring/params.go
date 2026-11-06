package ring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Request fields carry the circuit field names, their tags the wire names.

type RequestHead struct {
	CircuitType     common.CircuitType `json:"circuitType"`
	PublicInputHash Field              `json:"publicInputHash"`
}

func (h RequestHead) head() RequestHead { return h }

type headed interface {
	head() RequestHead
}

type Opening struct {
	Domain        Field `json:"domain"`
	TreeID        Field `json:"treeId"`
	OwnerPkHash   Field `json:"ownerPkHash"`
	NullifierPk   Field `json:"nullifierPk"`
	Asset         Field `json:"asset"`
	Amount        Field `json:"amount"`
	Blinding      Field `json:"blinding"`
	DataHash      Field `json:"dataHash"`
	RingDataHash  Field `json:"ringDataHash"`
	RingProgramID Field `json:"ringProgramId"`
}

// AuditParams are the envelope wires of a transfer, the ring id sits beside the policy values.
type AuditParams struct {
	FirstNullifier Field `json:"firstNullifier"`
	TxViewingSk    Bytes `json:"txViewingSk"`
	AuditorPk      Bytes `json:"auditorPk"`
	Salt           Bytes `json:"salt"`
	Layout         uint8 `json:"layout"`
}

// OutputOpening is one output slot, the preimages its record names and the key it is sealed to.
type OutputOpening struct {
	Output       Opening `json:"output"`
	OwnerKey     Bytes   `json:"ownerKey"`
	MintChunks   []Field `json:"mintChunks"`
	RecipientKey Bytes   `json:"recipientKey"`
}

// EntryOpening names a default-ring input's preimages, zero off one.
type EntryOpening struct {
	OwnerKey   Bytes   `json:"ownerKey"`
	MintChunks []Field `json:"mintChunks"`
}

// TrackingRecordParams is one opened tracking leaf.
type TrackingRecordParams struct {
	Member      Field `json:"member"`
	Next        Field `json:"next"`
	NullifierPk Field `json:"nullifierPk"`
	CtHash      Field `json:"ctHash"`
	ListTag     Field `json:"listTag"`
}

// TrackingParams opens every owner row and live ring output under the frame's tracking root.
type TrackingParams struct {
	TrackingRoot     Field                  `json:"trackingRoot"`
	TrackingRecords  []TrackingRecordParams `json:"trackingRecords"`
	TrackingProof    SharedRegistryProof    `json:"trackingProof"`
	TrackingSubjects []PooledSubject        `json:"trackingSubjects"`
	RowEntries       []uint32               `json:"rowEntries"`
	OutputEntries    []uint32               `json:"outputEntries"`
}

type TransferParams struct {
	RequestHead
	AuditParams
	InProof         bool    `json:"inProof"`
	Hidden          bool    `json:"hidden"`
	Delegate        bool    `json:"delegate"`
	Sender          Field   `json:"sender"`
	PartyIdentities []Field `json:"partyIdentities"`
	ApprovalMask    uint8   `json:"approvalMask"`
	// Both absent read zero, a frame that discloses nothing.
	ApprovalTotals  *Field          `json:"approvalTotals,omitempty"`
	ApprovalBlinder *Field          `json:"approvalBlinder,omitempty"`
	OutputCount     uint8           `json:"outputCount"`
	Outputs         []OutputOpening `json:"outputs"`
	InputCount      uint8           `json:"inputCount"`
	// Inputs hold the spent notes in SPP's note order, then dummies.
	Inputs        []Opening      `json:"inputs"`
	AddressChain  Field          `json:"addressChain"`
	Entries       []EntryOpening `json:"entries,omitempty"`
	SignerCount   uint8          `json:"signerCount"`
	Signers       []Field        `json:"signers"`
	Rows          []Field        `json:"rows"`
	PrivateTxHash Field          `json:"privateTxHash"`
	TrackingParams
	PolicyParams
}

type Source struct {
	ListID uint8 `json:"listId"`
	// Registry is zero for a list the ring's own registry serves, else the curator registry address.
	Registry Field `json:"registry"`
}

type PolicyTable struct {
	Sources []Source `json:"sources"`
	// Bit i puts list i+1 at owners' salted keys.
	Salted    uint16  `json:"salted"`
	PolicyLen uint8   `json:"policyLen"`
	Rules     []Field `json:"rules"`
}

type Withdrawal struct {
	Owner  Field `json:"owner"`
	Asset  Field `json:"asset"`
	Amount Field `json:"amount"`
}

type PolicyInputsParams struct {
	WithdrawalCount uint8        `json:"withdrawalCount"`
	WithdrawalHash  Field        `json:"withdrawalHash"`
	Withdrawals     []Withdrawal `json:"withdrawals"`
	PolicyHash      Field        `json:"policyHash"`
	RingProgramID   Field        `json:"ringId"`
	OwnRoot         Field        `json:"ownRoot"`
	CuratorRoot     Field        `json:"curatorRoot"`
	PublicAssets    []Field      `json:"publicAssets"`
	PublicAmounts   []Field      `json:"publicAmounts"`
	PublicGross     []Field      `json:"publicGross"`
	PolicyTable
}

type PooledRecord struct {
	Member              Field   `json:"member"`
	Next                Field   `json:"next"`
	Lists               uint64  `json:"lists"`
	MintPolicy          Field   `json:"mintPolicy"`
	WithdrawalThreshold Field   `json:"withdrawalThreshold"`
	AssetLimits         []Field `json:"assetLimits"`
}

type PooledSubject struct {
	Member      Field  `json:"member"`
	RecordIndex uint32 `json:"recordIndex"`
}

type PooledEntry struct {
	Own     uint32   `json:"own"`
	Curator []uint32 `json:"curator"`
}

// PooledOwnerEntry takes a zero salt with no tracking row.
type PooledOwnerEntry struct {
	PooledEntry
	Tracking      uint32   `json:"tracking"`
	ListSalt      Field    `json:"listSalt"`
	OwnSalted     uint32   `json:"ownSalted"`
	CuratorSalted []uint32 `json:"curatorSalted"`
}

type SharedRegistryPath struct {
	Index    uint64    `json:"index"`
	Siblings [][]Field `json:"siblings"`
}

type SharedRegistryProof struct {
	Canopy []Field              `json:"canopy"`
	Paths  []SharedRegistryPath `json:"paths"`
}

type PolicyParams struct {
	PolicyInputsParams
	OwnRecords      []PooledRecord      `json:"ownRecords"`
	CuratorRecords  []PooledRecord      `json:"curatorRecords"`
	OwnProof        SharedRegistryProof `json:"ownProof"`
	CuratorProof    SharedRegistryProof `json:"curatorProof"`
	OwnSubjects     []PooledSubject     `json:"ownSubjects"`
	CuratorSubjects []PooledSubject     `json:"curatorSubjects"`
	SenderEntries   []PooledOwnerEntry  `json:"senderEntries"`
	// OwnerEntries[o] and AssetEntries[o] index payment o's owner and asset subjects.
	OwnerEntries       []PooledOwnerEntry `json:"ownerEntries"`
	AssetEntries       []PooledEntry      `json:"assetEntries"`
	PublicAssetEntries []uint32           `json:"publicAssetEntries"`
}

type RecordWrite struct {
	Member              Field   `json:"member"`
	Mask                uint64  `json:"mask"`
	Value               uint64  `json:"value"`
	MintPolicy          Field   `json:"mintPolicy"`
	WithdrawalThreshold Field   `json:"withdrawalThreshold"`
	AssetLimits         []Field `json:"assetLimits"`
}

type RecordWriteProofInput struct {
	Entry                  RecordWrite `json:"entry"`
	Exists                 bool        `json:"exists"`
	OldNext                Field       `json:"oldNext"`
	OldLists               uint64      `json:"oldLists"`
	OldMintPolicy          Field       `json:"oldMintPolicy"`
	OldWithdrawalThreshold Field       `json:"oldWithdrawalThreshold"`
	OldAssetLimits         []Field     `json:"oldAssetLimits"`
	// Index and Path open the member's leaf or the leaf an insert takes.
	Index                  uint64  `json:"index"`
	Path                   []Field `json:"path"`
	LowMember              Field   `json:"lowMember"`
	LowNext                Field   `json:"lowNext"`
	LowLists               uint64  `json:"lowLists"`
	LowMintPolicy          Field   `json:"lowMintPolicy"`
	LowWithdrawalThreshold Field   `json:"lowWithdrawalThreshold"`
	LowAssetLimits         []Field `json:"lowAssetLimits"`
	// LowIndex and LowPath open the low record.
	LowIndex uint64  `json:"lowIndex"`
	LowPath  []Field `json:"lowPath"`
}

type ApplyRecordsParams struct {
	RequestHead
	OldRoot      Field  `json:"oldRoot"`
	NewRoot      Field  `json:"newRoot"`
	OldNextIndex uint32 `json:"oldNextIndex"`
	NewNextIndex uint32 `json:"newNextIndex"`
	ChainStart   Field  `json:"chainStart"`
	ChainEnd     Field  `json:"chainEnd"`
	Count        uint8  `json:"count"`
	// A nil write past Count assigns zeros.
	Writes []*RecordWriteProofInput `json:"writes"`
}

// TrackingWrite is the witness of one applied entry.
type TrackingWrite struct {
	Member      Field                `json:"member"`
	NullifierPk Field                `json:"nullifierPk"`
	CtHash      Field                `json:"ctHash"`
	ListTag     Field                `json:"listTag"`
	Index       uint64               `json:"index"`
	Path        []Field              `json:"path"`
	LowRecord   TrackingRecordParams `json:"lowRecord"`
	LowIndex    uint64               `json:"lowIndex"`
	LowPath     []Field              `json:"lowPath"`
}

// PrivateApplyRecordsParams refuses a public request, every private field is required.
type PrivateApplyRecordsParams struct {
	ApplyRecordsParams
	PrivateWrites uint64 `json:"privateWrites"`
	TrackingRoot  Field  `json:"trackingRoot"`
	// A nil owner outside the bitmap assigns zeros.
	Owners []*PrivateOwnerParams `json:"owners"`
}

type PrivateOwnerParams struct {
	ListSalt Field                `json:"listSalt"`
	Record   TrackingRecordParams `json:"record"`
	Index    uint64               `json:"index"`
	Path     []Field              `json:"path"`
}

type ApplyEnrollmentsParams struct {
	RequestHead
	OldRoot      Field  `json:"oldRoot"`
	NewRoot      Field  `json:"newRoot"`
	OldNextIndex uint64 `json:"oldNextIndex"`
	NewNextIndex uint64 `json:"newNextIndex"`
	ChainStart   Field  `json:"chainStart"`
	ChainEnd     Field  `json:"chainEnd"`
	Count        uint8  `json:"count"`
	// A nil write past Count assigns zeros.
	Writes []*TrackingWrite `json:"writes"`
}

type RegisterKeyParams struct {
	RequestHead
	RingID          Field `json:"ringId"`
	Member          Field `json:"member"`
	NullifierSecret Bytes `json:"nullifierSecret"`
	ListSalt        Bytes `json:"listSalt"`
	EphSk           Bytes `json:"ephSk"`
	AuditorPk       Bytes `json:"auditorPk"`
}

// TrackingLeaf mirrors registry.TrackingRecord field for field.
type TrackingLeaf struct {
	Member      Field `json:"member"`
	Next        Field `json:"next"`
	NullifierPk Field `json:"nullifierPk"`
	CtHash      Field `json:"ctHash"`
	ListTag     Field `json:"listTag"`
}

// TrackingOpening mirrors registry.TrackingOpening field for field.
type TrackingOpening struct {
	Present bool               `json:"present"`
	Record  TrackingLeaf       `json:"record"`
	Path    SharedRegistryPath `json:"path"`
}

// MergeParams seals a ring's SPP merge output to its auditor, Tracking is nil under a zero key.
type MergeParams struct {
	RequestHead
	OutputUtxoHash     Field            `json:"outputUtxoHash"`
	FirstNullifier     Field            `json:"firstNullifier"`
	RingProgramID      Field            `json:"ringProgramId"`
	AuditorPk          Bytes            `json:"auditorPk"`
	Payer              Field            `json:"payer"`
	TrackingRoot       Field            `json:"trackingRoot"`
	EphSk              Bytes            `json:"ephSk"`
	RecipientKey       Bytes            `json:"recipientKey"`
	OwnerKey           Bytes            `json:"ownerKey"`
	OwnerPkHash        Field            `json:"ownerPkHash"`
	MintChunks         []Field          `json:"mintChunks"`
	Asset              Field            `json:"asset"`
	Amount             Field            `json:"amount"`
	NullifierPk        Field            `json:"nullifierPk"`
	Seed               Field            `json:"seed"`
	OutputTreeID       Field            `json:"outputTreeId"`
	OutputRingDataHash Field            `json:"outputRingDataHash"`
	Tracking           *TrackingOpening `json:"tracking"`
}

// Unmarshal refuses an unknown or repeated key, a missing key without omitempty and trailing data.
func Unmarshal(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := strictly(decoder, reflect.TypeOf(v).Elem(), 0); err != nil {
		return fmt.Errorf("custom-ring: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("custom-ring: trailing data after the request")
	}
	return json.Unmarshal(data, v)
}

const maxDepth = 32

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// strictly reads one value of t, refusing a key without an exact field, a repeated key and a null t cannot hold.
func strictly(decoder *json.Decoder, t reflect.Type, depth int) error {
	if depth > maxDepth {
		return errors.New("nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	nullable := t.Kind() == reflect.Pointer
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	custom := reflect.PointerTo(t).Implements(unmarshaler)
	if token == nil {
		if nullable || custom {
			return nil
		}
		return errors.New("null value")
	}
	if !custom {
		switch t.Kind() {
		case reflect.Struct:
			return strictObject(decoder, t, token, depth)
		case reflect.Slice, reflect.Array:
			return strictArray(decoder, t, token, depth)
		}
	}
	if _, composite := token.(json.Delim); composite {
		return errors.New("expected a scalar")
	}
	return nil
}

func strictObject(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('{') {
		return errors.New("expected an object")
	}
	fields := jsonFields(t, nil)
	byName := make(map[string]jsonField, len(fields))
	for _, field := range fields {
		byName[field.name] = field
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, _ := key.(string)
		field, known := byName[name]
		if !known {
			return fmt.Errorf("unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("repeated field %q", name)
		}
		seen[name] = true
		if err := strictly(decoder, field.typ, depth+1); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for _, field := range fields {
		if !field.optional && !seen[field.name] {
			return fmt.Errorf("missing field %q", field.name)
		}
	}
	return nil
}

func strictArray(decoder *json.Decoder, t reflect.Type, token json.Token, depth int) error {
	if token != json.Delim('[') {
		return errors.New("expected an array")
	}
	for i := 0; decoder.More(); i++ {
		if err := strictly(decoder, t.Elem(), depth+1); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	_, err := decoder.Token()
	return err
}

type jsonField struct {
	name     string
	typ      reflect.Type
	optional bool
}

// jsonFields promotes untagged embedded structs as encoding/json does.
func jsonFields(t reflect.Type, fields []jsonField) []jsonField {
	for i := range t.NumField() {
		field := t.Field(i)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			fields = jsonFields(field.Type, fields)
			continue
		}
		if name == "-" || !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, jsonField{name: name, typ: field.Type, optional: slices.Contains(strings.Split(options, ","), "omitempty")})
	}
	return fields
}
