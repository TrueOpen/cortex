package devex

import (
	"crypto/sha256"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"go/parser"
	"go/token"
	"google.golang.org/protobuf/testing/protocmp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	_ "github.com/TrueOpen/cortex/proto/bus/v1"
	_ "github.com/TrueOpen/cortex/proto/hub/v1"
	_ "github.com/TrueOpen/cortex/proto/nexus/v1"
	_ "github.com/TrueOpen/cortex/proto/shared/v1"
	_ "github.com/TrueOpen/cortex/proto/task/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestChainBindingsMatchReleasedDescriptor(t *testing.T) {
	data, err := os.ReadFile("../../proto/testdata/wire-v0.3.0.binpb")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "d0c240eb9b1ca57ad645721dd0b23db1c4510901bdad18759ddbaf58b51460b9" {
		t.Fatalf("pinned wire v0.3.0 descriptor changed: %s", got)
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, expected := range set.File {
		name := expected.GetName()
		if !strings.HasPrefix(name, "hub/v1/") && !strings.HasPrefix(name, "task/v1/") && !strings.HasPrefix(name, "shared/v1/") && !strings.HasPrefix(name, "bus/v1/") && name != "nexus/v1/ingress.proto" {
			continue
		}
		actual, err := protoregistry.GlobalFiles.FindFileByPath(name)
		if err != nil {
			t.Errorf("missing released binding %s: %v", name, err)
			continue
		}
		want := proto.Clone(expected).(*descriptorpb.FileDescriptorProto)
		want.SourceCodeInfo = nil
		// Buf adds file-level compiler metadata (field 8042), omitted by protoc.
		want.ProtoReflect().SetUnknown(nil)
		got := protodesc.ToFileDescriptorProto(actual)
		got.SourceCodeInfo = nil
		if !proto.Equal(want, got) {
			t.Fatalf("binding descriptor differs from pinned wire v0.3.0: %s\n%s", name, cmp.Diff(want, got, protocmp.Transform()))
		}
		checked++
	}
	if checked < 40 {
		t.Fatalf("unexpectedly small descriptor coverage: %d", checked)
	}
}

func TestVendoredChainBindingsKeepImportsLocalised(t *testing.T) {
	err := filepath.WalkDir("../../proto", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".pb.go") || strings.Contains(filepath.ToSlash(path), "/cortex/") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if !strings.Contains(name, ".") || strings.HasPrefix(name, "google.golang.org/protobuf/") || strings.HasPrefix(name, "github.com/TrueOpen/cortex/proto/") {
				continue
			}
			t.Errorf("unlocalised binding import %q in %s", name, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
