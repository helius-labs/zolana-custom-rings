// Packs bytes into field elements. Where a statement hashes one the program rebuilds it, a chunk or
// pad off the mirror fails the statement. A byte above 8 bits would alias a packed element, so each
// caller holds that bound where its bytes are produced.
//
// Read after ringgadget/bytes.go, shared/derivation.go. Read before shared/envelope.go, audit/audit.go.

package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// PackDisclosure zero pads bytes at the end to whole 31-byte chunks and packs each chunk, the caller bounds every byte.
func PackDisclosure(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	chunks := (len(bytes) + gadget.HashBytesChunkSize - 1) / gadget.HashBytesChunkSize
	return PackBounded(api, append(append([]frontend.Variable{}, bytes...), Zeros(chunks*gadget.HashBytesChunkSize-len(bytes))...))
}

// PackBounded is gadget.PackBytesBE over bytes the caller bounds where they are produced.
func PackBounded(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	return gadget.PackBytesBEWith(api, ringgadget.BoundedBytes{}, bytes)
}

func Zeros(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = 0
	}
	return out
}
