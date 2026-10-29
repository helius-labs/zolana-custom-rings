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
