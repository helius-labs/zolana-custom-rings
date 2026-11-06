package ring

import (
	"fmt"
	"strings"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Family is mirrored by RingCircuit in program-libs/interface/src/proof/key_catalog.rs.
type Family int

const (
	Transfer Family = iota
	ApplyRecords
	ApplyEnrollments
	RegisterKey
	Merge
)

type Key struct {
	Circuit common.CircuitType
	Family  Family
	// Inputs counts the input slots or writes the key sizes.
	Inputs      int
	Outputs     int
	Withdrawals int
	Owners      int
	Entry       bool
	Wide        bool
	Private     bool
}

// Keys takes each shape from the package that sizes it.
var Keys = keys()

func (k Key) KeyFile() string {
	return strings.ReplaceAll(string(k.Circuit), "-", "_") + ".key"
}

func keys() []Key {
	var keys []Key
	add := func(key Key) {
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, shape := range transfer.Shapes {
		add(Key{Family: Transfer, Inputs: shape.Inputs, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Owners: shape.Owners, Entry: shape.Entry, Wide: shape.Wide})
	}
	for _, private := range []bool{false, true} {
		for _, writes := range registry.ApplyWidths {
			add(Key{Family: ApplyRecords, Inputs: writes, Private: private})
		}
	}
	for _, writes := range registry.ApplyWidths {
		add(Key{Family: ApplyEnrollments, Inputs: writes})
	}
	add(Key{Family: RegisterKey})
	add(Key{Family: Merge})
	return keys
}

func (k Key) transferShape() transfer.Shape {
	return transfer.Shape{Inputs: k.Inputs, Outputs: k.Outputs, Withdrawals: k.Withdrawals, Owners: k.Owners, Entry: k.Entry, Wide: k.Wide}
}

func (k Key) circuitType() common.CircuitType {
	named := func(format string, args ...any) common.CircuitType {
		return common.CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case Transfer:
		family := "transfer"
		switch {
		case k.Entry:
			family = "transfer-entry"
		case k.Wide:
			family = "transfer-wide"
		}
		return named("%s-%d-in%d-w%d-s%d", family, k.Outputs, k.Inputs, k.Withdrawals, k.Owners)
	case ApplyRecords:
		if k.Private {
			return named("apply-records-private-%d", k.Inputs)
		}
		return named("apply-records-%d", k.Inputs)
	case ApplyEnrollments:
		return named("apply-enrollments-%d", k.Inputs)
	case RegisterKey:
		return named("register-key")
	case Merge:
		return named("merge")
	}
	panic(fmt.Sprintf("ring: unknown ring family %d", k.Family))
}
