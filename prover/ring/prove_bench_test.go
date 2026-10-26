package ring

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// BenchmarkRingProve measures the CPU request-to-proof path with loaded keys.
func BenchmarkRingProve(b *testing.B) {
	payload, err := os.ReadFile("proving-benchmarks.json")
	if err != nil {
		b.Fatal(err)
	}
	var circuits []common.CircuitType
	if err := json.Unmarshal(payload, &circuits); err != nil {
		b.Fatal(err)
	}
	for _, circuit := range circuits {
		b.Run(string(circuit), func(b *testing.B) {
			b.StopTimer()
			system := loadRingSystem(b, circuit)
			payload := mustMarshal(b, benchmarkRequest(b, keyOf(b, circuit)))
			request := extensionOf(b, circuit).Request()
			if err := json.Unmarshal(payload, request); err != nil {
				b.Fatal(err)
			}
			assignment, err := request.Assignment()
			if err != nil {
				b.Fatal(err)
			}
			prover := common.ExtensionProof{System: system, Request: request}
			proof, err := prover.Prove()
			if err != nil {
				b.Fatal(err)
			}
			if err := verifyProof(system, proof, assignment); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for range b.N {
				proof, err = prover.Prove()
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := verifyProof(system, proof, assignment); err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(system.ConstraintSystem.GetNbConstraints()), "constraints")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/1e6, "ms/op")
		})
	}
}

func benchmarkRequest(b testing.TB, key Key) any {
	b.Helper()
	if key.Family != AnonymousAudit || key.Inputs != 32 {
		return hostRequest(b, key)
	}
	audit := ringaudit.NewAnonymousAudit(b, key.anonymousShape())
	for i := audit.InputCount; i < len(audit.Inputs); i++ {
		audit.Inputs[i] = audit.SenderUtxo(b, audit.RingProgramID, 100, 1000+int64(i))
	}
	audit.InputCount = len(audit.Inputs)
	return requestOf[AnonymousAuditParams](b, key.Circuit, audit.Circuit(b))
}
