// Command wiregen reproduces the canonical bindings from a pinned wire release descriptor.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

const descriptorSHA256 = "0eae8af1536e489f38f668dfa87c848d1e889b460513607e13df54d9fde54887"

func main() {
	descriptor := flag.String("descriptor", "proto/testdata/wire-v0.2.0.binpb", "pinned wire release descriptor")
	out := flag.String("out", "bin/.chain-bindings", "empty scratch output directory")
	flag.Parse()
	data, err := os.ReadFile(*descriptor)
	check(err)
	if fmt.Sprintf("%x", sha256.Sum256(data)) != descriptorSHA256 {
		check(fmt.Errorf("wire descriptor checksum mismatch"))
	}
	entries, err := os.ReadDir(*out)
	if err != nil && !os.IsNotExist(err) {
		check(err)
	}
	if len(entries) > 0 {
		check(fmt.Errorf("output directory must be empty; generation never deletes or overwrites a tree"))
	}
	var set descriptorpb.FileDescriptorSet
	check(proto.Unmarshal(data, &set))
	files := map[string]*descriptorpb.FileDescriptorProto{}
	for _, file := range set.File {
		files[file.GetName()] = file
	}
	selected := map[string]bool{}
	var add func(string)
	add = func(name string) {
		if selected[name] || strings.HasPrefix(name, "google/protobuf/") {
			return
		}
		file := files[name]
		if file == nil {
			check(fmt.Errorf("missing descriptor dependency %s", name))
		}
		selected[name] = true
		for _, dep := range file.Dependency {
			add(dep)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "hub/v1/") || strings.HasPrefix(name, "task/v1/") || strings.HasPrefix(name, "shared/v1/") || strings.HasPrefix(name, "bus/v1/") || name == "nexus/v1/ingress.proto" {
			add(name)
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	check(os.MkdirAll(*out, 0755))
	for _, plugin := range []string{"go", "connect-go"} {
		args := []string{"--descriptor_set_in=" + *descriptor, "--" + plugin + "_out=" + *out, "--" + plugin + "_opt=paths=source_relative"}
		for _, name := range names {
			args = append(args, "--"+plugin+"_opt=M"+name+"=github.com/SingaXYZ/cortex/proto/"+filepath.ToSlash(filepath.Dir(name)))
		}
		if plugin == "go" {
			args = append(args, names...)
		} else {
			args = append(args, "nexus/v1/ingress.proto")
		}
		cmd := exec.Command("protoc", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		check(cmd.Run())
	}
}

func check(err error) {
	if err != nil {
		slog.Error("wire generation failed", "error", err)
		os.Exit(1)
	}
}
