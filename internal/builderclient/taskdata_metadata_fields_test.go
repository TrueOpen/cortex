package builderclient

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"google.golang.org/protobuf/proto"
)

func TestMetadataRequiresExactObjectRefAndReadiness(t *testing.T) {
	base := taskDataTestMetadata(taskDataTestObjectKey(), 4, TaskDataReady)
	for name, mutate := range map[string]func(*nexusv1.TaskDataObjectMetadataV1){
		"missing ref":            func(m *nexusv1.TaskDataObjectMetadataV1) { m.ObjectRef = nil },
		"unknown kind":           func(m *nexusv1.TaskDataObjectMetadataV1) { m.ObjectRef.ObjectKind = 99 },
		"zero readiness":         func(m *nexusv1.TaskDataObjectMetadataV1) { m.Readiness = 0 },
		"unknown readiness":      func(m *nexusv1.TaskDataObjectMetadataV1) { m.Readiness = 99 },
		"chunk lengths mismatch": func(m *nexusv1.TaskDataObjectMetadataV1) { m.ChunkLengths = []uint32{3}; m.OutputLeafCount = 1 },
		"leaf count mismatch":    func(m *nexusv1.TaskDataObjectMetadataV1) { m.ChunkLengths = []uint32{4}; m.OutputLeafCount = 2 },
		"staged boundaries": func(m *nexusv1.TaskDataObjectMetadataV1) {
			m.Readiness = nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_STORED
			m.ChunkLengths = []uint32{4}
			m.OutputLeafCount = 1
		},
		"present empty producer": func(m *nexusv1.TaskDataObjectMetadataV1) { empty := ""; m.ObjectRef.ProducerOperator = &empty },
	} {
		t.Run(name, func(t *testing.T) {
			wire := proto.Clone(base).(*nexusv1.TaskDataObjectMetadataV1)
			mutate(wire)
			if _, err := taskDataMetadataFromProto(wire); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	for _, readiness := range []TaskDataReadiness{TaskDataStored, TaskDataReady} {
		wire := taskDataTestMetadata(taskDataTestObjectKey(), 4, readiness)
		if _, err := taskDataMetadataFromProto(wire); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkerManifestMetadataSeparatesLocatorAndIntegrityHash(t *testing.T) {
	f, pair, req, uploads := fakeFinalizeFixture(t, nil)
	for _, upload := range uploads[1:] {
		if _, err := f.UploadTaskResultObject(context.Background(), "", upload); err != nil {
			t.Fatal(err)
		}
	}
	key := uploads[3].Key
	body, err := TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	auth := taskDataTestRequestAuth(t, pair, "GetTaskDataMetadata", key, body)
	metadata, err := f.GetTaskDataMetadata(context.Background(), "", GetTaskDataMetadataRequest{Key: key, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	want := evidencebundle.Hash(uploads[3].Data).String()
	if metadata.EvidenceBundle.EvidenceManifestHash != want || want == key.ContentHash || metadata.EvidenceBundle.ArtifactTotalSizeBytes != req.Receipt.RequiredEvidenceCommitments[1].EncodedSizeBytes {
		t.Fatalf("metadata=%+v key=%+v", metadata, key)
	}
	server := newTaskDataTestServer(t, &taskDataTestHandler{metadata: func(_ context.Context, r *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error) {
		if !proto.Equal(r.Msg.ObjectRef, taskDataKeyToProto(key)) {
			t.Error("typed manifest reference changed")
		}
		b := metadata.EvidenceBundle
		return connect.NewResponse(&nexusv1.GetTaskDataMetadataResponse{Metadata: &nexusv1.TaskDataObjectMetadataV1{ObjectRef: taskDataKeyToProto(key), SizeBytes: metadata.SizeBytes, Readiness: nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_STORED}, EvidenceBundle: &nexusv1.EvidenceBundleSummaryV1{EvidenceManifestHash: b.EvidenceManifestHash, EvidenceSchemaHash: b.EvidenceSchemaHash, ArtifactCount: b.ArtifactCount, ArtifactTotalSizeBytes: b.ArtifactTotalSizeBytes, ManifestSizeBytes: b.ManifestSizeBytes}}), nil
	}})
	got, err := newTestTaskDataClient(server.Client(), "").GetTaskDataMetadata(context.Background(), server.URL, GetTaskDataMetadataRequest{Key: key, Auth: auth})
	if err != nil || got.EvidenceBundle == nil || got.EvidenceBundle.EvidenceManifestHash != want {
		t.Fatalf("metadata=%+v err=%v", got, err)
	}
}
