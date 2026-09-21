package layout

import "context"

// InferExecutor runs inference for one task. It is part of the executor seam
// frozen in #219: #221 (daemon admission and lifecycle) and #226 (worker
// recovery) both build on it.
//
// The executor receives the authoritative task record and the current infer
// record, performs the work, and returns the updated infer record. The caller
// persists the result through MergeInfer.
type InferExecutor interface {
	RunInfer(ctx context.Context, task TaskRecord, infer InferRecord) (InferRecord, error)
}

// VerifyExecutor runs verification for one task. It is part of the executor seam
// frozen in #219 alongside InferExecutor.
//
// The executor receives the authoritative task record and the current verify
// record, performs the work, and returns the updated verify record. The caller
// persists the result through MergeVerify.
type VerifyExecutor interface {
	RunVerify(ctx context.Context, task TaskRecord, verify VerifyRecord) (VerifyRecord, error)
}

// ExecutorSeam groups the two role executors. A TaskRunner holds a reference to
// the seam and dispatches recovered or newly admitted work through it.
type ExecutorSeam interface {
	InferExecutor
	VerifyExecutor
}
