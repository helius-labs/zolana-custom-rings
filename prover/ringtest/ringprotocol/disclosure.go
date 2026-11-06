package ringprotocol

import (
	"math/big"
)

// PackDisclosure mirrors shared.PackDisclosure, the short last chunk keeps its bytes first.
func PackDisclosure(bytes []byte) []*big.Int {
	const chunk = 31
	padded := append(append([]byte{}, bytes...), make([]byte, (chunk-len(bytes)%chunk)%chunk)...)
	fields := make([]*big.Int, len(padded)/chunk)
	for i := range fields {
		fields[i] = new(big.Int).SetBytes(padded[i*chunk : (i+1)*chunk])
	}
	return fields
}
