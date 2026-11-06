// Sizes a transfer key. Each axis bounds what a key can prove and never what it checks, a transfer
// past an axis needs a larger key and passes no predicate on a smaller one.
//
// Read after transfer/transfer.go. Read before prover/ring/keys.go.
//
// Properties:
// 1. Every shape a key compiles from is a row of TRANSFER_SHAPES, the program selects its verifying key by that row.
// 2. Pool limits include input assets independently of output assets.

package transfer

import (
	"fmt"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
)

// Shape sizes a key, Inputs also bounds the signers it can bind.
type Shape struct {
	Inputs, Outputs, Withdrawals, Owners int
	Entry                                bool
	// Wide fits a salted and a public record per owner.
	Wide bool
	// Standard format excludes input and public slot assets.
	Tracking, Records int
}

// Shapes mirrors TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var Shapes = [...]Shape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4, Tracking: 6, Records: 12},
	{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4, Tracking: 8, Records: 16},
	{Inputs: 16, Outputs: 8, Withdrawals: 4, Owners: 4, Tracking: 12, Records: 24},
	{Inputs: 24, Outputs: 8, Withdrawals: 32, Owners: 13, Wide: true, Tracking: 42, Records: 88},
	{Inputs: 40, Outputs: 2, Withdrawals: 4, Owners: 8, Wide: true, Tracking: 11, Records: 24},
	{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true, Tracking: 14, Records: 32},
	{Inputs: 2, Outputs: 8, Withdrawals: 4, Owners: 2, Entry: true, Wide: true, Tracking: 14, Records: 36},
	{Inputs: 5, Outputs: 8, Withdrawals: 4, Owners: 4, Entry: true, Wide: true, Tracking: 15, Records: 38},
	{Inputs: 8, Outputs: 8, Withdrawals: 32, Owners: 8, Entry: true, Wide: true, Tracking: 38, Records: 80},
}

// Keyed returns the catalog row with the widths of shape.
func Keyed(shape Shape) (Shape, error) {
	for _, row := range Shapes {
		if row.widths() == shape.widths() {
			return row, nil
		}
	}
	return Shape{}, fmt.Errorf("unsupported transfer shape %+v, want one of %v", shape, Shapes)
}

func (s Shape) widths() Shape {
	s.Tracking, s.Records = 0, 0
	return s
}

func (s Shape) String() string {
	family := "transfer"
	switch {
	case s.Entry:
		family = "transfer_entry"
	case s.Wide:
		family = "transfer_wide"
	}
	return fmt.Sprintf("custom_ring_%s_%d_in%d_w%d_s%d", family, s.Outputs, s.Inputs, s.Withdrawals, s.Owners)
}

func (s Shape) Stream() audit.StreamShape {
	return audit.StreamShape{InputClass: s.Inputs, Outputs: s.Outputs, Entry: s.Entry}
}

func (s Shape) entries() int {
	if s.Entry {
		return s.Inputs
	}
	return 0
}

func (s Shape) trackedWithdrawals() int {
	return s.Tracking - s.Owners - s.Outputs
}

// saltedKeys widens the pools past their public records to Records.
func (s Shape) saltedKeys() int {
	return s.Records - s.Owners - 2*s.Outputs - s.Withdrawals
}
