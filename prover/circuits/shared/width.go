// Checks that a circuit is built only at a size the ring ships keys for. A
// circuit of any other size would have no verifier on chain.
//
// Read first. Read before registry/apply_records.go.

package shared

import (
	"fmt"
	"slices"
)

func ValidateWidth(circuit string, width int, shipped []int) error {
	if !slices.Contains(shipped, width) {
		return fmt.Errorf("%s: unsupported width %d, want one of %v", circuit, width, shipped)
	}
	return nil
}

func ValidateLength(circuit, name string, got, want int) error {
	if got != want {
		return fmt.Errorf("%s: %s count %d, want %d", circuit, name, got, want)
	}
	return nil
}
