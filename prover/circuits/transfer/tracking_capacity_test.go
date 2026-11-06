package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

// Eight signing rows, two outputs and thirty two unenrolled withdrawal owners under a salted list fill the wide key's tracking pool.
func TestTheWidestInlineSpendOpensEveryTrackingRow(t *testing.T) {
	w := ringtransfer.Signed(wideOwners2)
	w.SaltedBlock, w.Exits, w.Omitted = []*big.Int{}, []int{}, wideOwners2.Outputs-2
	for k := range 7 {
		w.CoOwners = append(w.CoOwners, big.NewInt(0x1000+int64(k)))
	}
	asset := ringtransfer.Asset(t)
	for leg := range 32 {
		w.Withdrawals = append(w.Withdrawals, ringtransfer.Withdrawal{Owner: big.NewInt(0x2000 + int64(leg)), Asset: asset, Amount: 1})
	}
	w.Public = []ringtransfer.PublicSlot{{Asset: asset, Net: -32, Gross: 32}}
	built := w.Build(t)
	keyed, err := transfer.Keyed(wideOwners2)
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, subject := range built.Circuit.TrackingSubjects {
		if ringtest.AsBigInt(subject.Member).Sign() != 0 {
			live++
		}
	}
	if live != keyed.Tracking || len(built.Circuit.TrackingSubjects) != keyed.Tracking {
		t.Fatalf("%d live rows in a pool of %d, want %d in %d", live, len(built.Circuit.TrackingSubjects), keyed.Tracking, keyed.Tracking)
	}
	requireSolved(t, built.Circuit)
	// A dropped subject leaves its read unanswered.
	built.Circuit.TrackingSubjects[len(built.Circuit.TrackingSubjects)-1].Member = 0
	refused(t, built.Circuit)
}
