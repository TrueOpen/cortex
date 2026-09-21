package daemon

import (
	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/tasktrace"
)

// traceConfirmedPackage is the field set of a confirmed output, shared by the
// Verifier handraise and the verify execution so the same milestone reads the
// same way whichever path reached it.
//
// The three artifact refs are printed even though the task-data path leaves them
// empty: which of the two confirmation paths ran is exactly what an operator
// cannot otherwise tell from the outside, and `output_ref=""` beside
// `provenance=task_data` says it.
func traceConfirmedPackage(kind string, pkg builderclient.OutputPackage) []tasktrace.Field {
	provenance := "store"
	if pkg.Provenance == builderclient.OutputPackageFromTaskData {
		provenance = "task_data"
	}
	return []tasktrace.Field{
		tasktrace.Str("kind", kind), tasktrace.Str("task", pkg.TaskID),
		tasktrace.Hash("output_hash", pkg.OutputHash), tasktrace.Hash("package_hash", pkg.PackageHash),
		tasktrace.Hash("receipt_hash", pkg.ReceiptHash),
		tasktrace.Str("output_ref", pkg.OutputRef), tasktrace.Str("trace_ref", pkg.TraceRef),
		tasktrace.Str("checkpoint_ref", pkg.CheckpointRef),
		tasktrace.Int("output_bytes", len(pkg.Output)),
		tasktrace.Int("receipt_payload_bytes", len(pkg.ReceiptPayload)),
		tasktrace.Int("worker_signature_bytes", len(pkg.WorkerSignature)),
		tasktrace.Str("provenance", provenance),
	}
}
