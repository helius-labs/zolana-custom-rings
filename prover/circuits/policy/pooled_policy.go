package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type RecordPoolShape struct {
	Own, Curator                 int
	OwnSubjects, CuratorSubjects int
}

type PoolEntry struct {
	Own     frontend.Variable
	Curator []frontend.Variable
}

func newPoolEntry(ownOnly bool) PoolEntry {
	entry := PoolEntry{}
	if !ownOnly {
		entry.Curator = make([]frontend.Variable, 1)
	}
	return entry
}

func (s RecordPoolShape) validate(limits RecordPoolShape) error {
	if err := validatePoolCapacity(s.Own, s.OwnSubjects, limits.Own); err != nil {
		return err
	}
	if limits.Curator == 0 {
		if s.Curator != 0 || s.CuratorSubjects != 0 {
			return fmt.Errorf("policy own pool has curator capacity")
		}
		return nil
	}
	return validatePoolCapacity(s.Curator, s.CuratorSubjects, limits.Curator)
}

func validatePoolCapacity(records, subjects, maximum int) error {
	for _, capacity := range []int{records, subjects} {
		if capacity < 1 || capacity > maximum {
			return fmt.Errorf("policy pool capacity is invalid")
		}
	}
	return nil
}

func (e PoolEntry) validate(ownOnly bool) error {
	expected := 1
	if ownOnly {
		expected = 0
	}
	if len(e.Curator) != expected {
		return fmt.Errorf("policy curator reference shape is invalid")
	}
	return nil
}

func (p *PolicyInputs) recordCapacity(publicAssets int) RecordPoolShape {
	outputs, withdrawals := len(p.Outputs), len(p.Withdrawals)
	// Withdrawals settle through SPP public slots, so their assets are among at most NPublicSlots.
	withdrawalAssets := min(withdrawals, transaction.NPublicSlots)
	distinct := 1 + outputs + withdrawals + outputs
	limits := RecordPoolShape{Own: distinct + max(withdrawalAssets, publicAssets)}
	if !p.OwnOnly {
		limits.Curator = distinct + withdrawalAssets
	}
	return limits
}

func (s RecordPoolShape) withDefaults(limits RecordPoolShape) RecordPoolShape {
	if s.Own == 0 {
		s.Own = limits.Own
	}
	if s.Curator == 0 {
		s.Curator = limits.Curator
	}
	if s.OwnSubjects == 0 {
		s.OwnSubjects = s.Own
	}
	if s.CuratorSubjects == 0 {
		s.CuratorSubjects = s.Curator
	}
	return s
}
