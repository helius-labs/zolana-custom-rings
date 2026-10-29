// Package ringgadget holds the generic gadgets the ring circuits add to zolana's gadget package.
package ringgadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const byteBits = 8

// BoundedBytes skips the byte check, for bytes the caller constrains to 8 bits where they are produced.
type BoundedBytes struct{}

func (BoundedBytes) Check(frontend.Variable, int) {}

// UintBytesBE fails the decomposition for a value at or above 2^(8n).
func UintBytesBE(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, byteBits*n))
}

func ConstBytes(s string) []frontend.Variable {
	out := make([]frontend.Variable, len(s))
	for i := range s {
		out[i] = s[i]
	}
	return out
}
