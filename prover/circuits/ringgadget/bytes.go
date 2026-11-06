// Helpers that turn numbers into bytes for disclosures and hashes. SPP binds an
// amount as a field value, a ring also shows it to the auditor as bytes. A number too
// large for its byte length fails the proof, so each amount has exactly one byte
// form and the auditor reads the value SPP bound.
//
// Read first. Read before shared/disclosure.go, shared/envelope.go, audit/record.go.

// Package ringgadget holds the generic gadgets the ring circuits add to zolana's gadget package.
package ringgadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. UintBytesBE's bytes recompose to value, a value at or above 2^(8n) has no bytes.
// 2. BoundedBytes adds no constraint, every byte it passes must be bound where it is produced.

const byteBits = 8

// BoundedBytes skips the byte check, for bytes the caller constrains to 8 bits where they are produced.
type BoundedBytes struct{}

func (BoundedBytes) Check(frontend.Variable, int) {}

// UintBytesBE fails the decomposition for a value at or above 2^(8n).
// Up to n = 31 the bits' sum stays below q, the bytes are the integer itself with no alias value + q. A wider field value goes through FieldToBytesBEWith.
func UintBytesBE(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, byteBits*n))
}
