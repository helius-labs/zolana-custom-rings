// Package ringaudit recomputes the audit statements of package audit on the host.
package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

// Keys are the envelope keys of one audited transfer.
type Keys struct {
	txViewingSk [32]byte
	ephSk       [32]byte
	txPk        [33]byte
	ephPk       [33]byte
	auditorPk   [32]byte
	dh          [32]byte
	txDh        [32]byte
}

func AuditorSk() [32]byte { return ringtest.Scalar(0x33) }

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txViewingSk := ringprotocol.Clamped(ringtest.Scalar(0x11))
	ephSk := ringtest.Scalar(0x22)
	txPriv := ringprotocol.XPrivateKey(t, txViewingSk)
	ephPriv := ringprotocol.XPrivateKey(t, ephSk)
	auditorPriv := ringprotocol.XPrivateKey(t, AuditorSk())

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	txDh, err := txPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txDh:        [32]byte(txDh),
		txViewingSk: txViewingSk,
		ephSk:       ephSk,
		txPk:        ringprotocol.Tagged(txPriv.PublicKey().Bytes()),
		ephPk:       ringprotocol.Tagged(ephPriv.PublicKey().Bytes()),
		auditorPk:   [32]byte(auditorPriv.PublicKey().Bytes()),
		dh:          [32]byte(dh),
	}
}

// WithRawTxScalar witnesses secret unclamped under the key its clamping publishes.
func (k Keys) WithRawTxScalar(t testing.TB, secret [32]byte) Keys {
	t.Helper()
	k.txPk = ringprotocol.Tagged(ringprotocol.XPrivateKey(t, ringprotocol.Clamped(secret)).PublicKey().Bytes())
	k.txViewingSk = secret
	return k
}

func (k Keys) TxViewingSk() [32]byte {
	return k.txViewingSk
}

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [32]byte {
	return k.auditorPk
}

func (k Keys) EphPk() [33]byte {
	return k.ephPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

func (k Keys) SealStream(t testing.TB, plaintext []byte, label string) Sealed {
	t.Helper()
	return k.Sealed(t, k.StreamCiphertext(t, plaintext, label))
}

func (k Keys) StreamCiphertext(t testing.TB, plaintext []byte, label string) []byte {
	t.Helper()
	key, nonce := ringprotocol.AuditStreamKeys(t, k.envelopeSecret(t), label)
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

// TransferCiphertext seals under the transfer's own key, Poseidon(secret, salt) keeps a resend apart.
func (k Keys) TransferCiphertext(t testing.TB, plaintext []byte, salt [16]byte) []byte {
	t.Helper()
	dhLo, dhHi := ringprotocol.Pack32(k.txDh)
	txLo, txHi := ringprotocol.Pack33(k.txPk)
	auditorLo, auditorHi := ringprotocol.Pack33(ringprotocol.Tagged(k.auditorPk[:]))
	secret := ringtest.MustPoseidonHash(t, ringprotocol.Tag(shared.DomSepCRShared), dhLo, dhHi, txLo, txHi, auditorLo, auditorHi)
	salted := ringtest.MustPoseidonHash(t, secret, new(big.Int).SetBytes(salt[:]))
	key, nonce := ringprotocol.AuditStreamKeys(t, salted, shared.AuditEncInfo)
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

func (k Keys) AuditHead(t testing.TB, firstNullifier, ringID *big.Int, salt [16]byte, envelope, keys []byte) AuditHead {
	t.Helper()
	return AuditHead{
		FirstNullifier: firstNullifier,
		RingProgramID:  ringID,
		TxViewingU:     [32]byte(k.txPk[1:]),
		AuditorPubkey:  ringprotocol.Tagged(k.auditorPk[:]),
		Envelope:       envelope,
		Keys:           keys,
		Salt:           salt,
	}
}

// envelopeSecret is Poseidon(CR_S, pack_be(dh), pack_be(eph), pack_be(auditor)) of the envelope.
func (k Keys) envelopeSecret(t testing.TB) *big.Int {
	t.Helper()
	dhLo, dhHi := ringprotocol.Pack32(k.dh)
	ephLo, ephHi := ringprotocol.Pack33(k.ephPk)
	auditorLo, auditorHi := ringprotocol.Pack33(ringprotocol.Tagged(k.auditorPk[:]))
	return ringtest.MustPoseidonHash(t, ringprotocol.Tag(shared.DomSepCRShared), dhLo, dhHi, ephLo, ephHi, auditorLo, auditorHi)
}

func (k Keys) Sealed(t testing.TB, ciphertext []byte) Sealed {
	t.Helper()
	ephLo, ephHi := ringprotocol.Pack33(k.ephPk)
	auditorLo, auditorHi := ringprotocol.Pack33(ringprotocol.Tagged(k.auditorPk[:]))
	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: ringtest.HashBytes(t, ciphertext),
	}
}

// Stream is the auditor stream and the sealed record of every slot.
type Stream struct {
	Ranges     audit.StreamRanges
	Salt       [16]byte
	Ciphertext []byte
	Records    [][]byte
}

func (s Stream) Envelope(count int) []byte {
	return s.Ciphertext[:s.Ranges.EnvelopeLen(count)]
}

// Keys is the transmitted recipient key region of m slots.
func (s Stream) Keys(m int) []byte {
	offset := s.Ranges.KeyOffset(0)
	return s.Ciphertext[offset : offset+m*audit.KeyLen]
}

func (s Stream) Record(i int) []byte {
	return s.Records[i]
}

// SealRecord seals slot i's record to u, as shared.SlotSeal does.
func (k Keys) SealRecord(t testing.TB, u [32]byte, salt [16]byte, i int, firstNullifier *big.Int, plaintext []byte) []byte {
	t.Helper()
	return ringprotocol.SealRecord(t, k.txViewingSk, u, salt, i, firstNullifier, shared.OutputRecordInfo, plaintext)
}
