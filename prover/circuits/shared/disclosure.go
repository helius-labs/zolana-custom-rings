// Packs and masks the fields a disclosure shows the auditor. A salt used twice
// under one key repeats the mask, so every disclosure needs a fresh salt.
//
// Read after ringgadget/bytes.go, shared/derivation.go. Read before
// shared/envelope.go, audit/layout.go, merge.go.

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

// DisclosurePad needs a fresh salt per key, a reused salt repeats the pad.
func DisclosurePad(api frontend.API, domain uint64, key [2]frontend.Variable, salt frontend.Variable, n int) []frontend.Variable {
	seed := gadget.PoseidonHash(api, []frontend.Variable{domain, key[0], key[1], salt})
	pad := make([]frontend.Variable, n)
	for i := range pad {
		pad[i] = gadget.PoseidonHash(api, []frontend.Variable{seed, i})
	}
	return pad
}
