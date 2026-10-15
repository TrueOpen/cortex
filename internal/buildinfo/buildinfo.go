// Package buildinfo reports which release a binary was built from.
//
// A release build sets Version with
//
//	-ldflags "-X github.com/TrueOpen/cortex/internal/buildinfo.Version=v0.1.0"
//
// which make build, the Dockerfile and the release archives do. A binary
// built some other way falls back to the module version Go records for
// `go install ...@v0.1.0`, and is otherwise "dev": an operator reading the
// startup log should never have to guess what is running.
package buildinfo

import "runtime/debug"

// Version is set at link time. Read it through Current.
var Version = "dev"

// Current returns the release this binary was built from, or "dev".
func Current() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
