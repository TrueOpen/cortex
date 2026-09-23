// Command keyaddr prints the bech32 address a keystore v3 file signs as.
//
// Config requires signer.operator_address before cortexd will start, and a
// mismatch fails closed, so operators need the address of a freshly created
// keystore before the daemon ever runs. This tool only decrypts and derives;
// it never creates key material and never prints a private key.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
)

func main() {
	observability.SetDefaultLogger(os.Stderr)
	dir := flag.String("dir", "", "directory holding keystore v3 files")
	hrp := flag.String("hrp", "trueopen", "bech32 human-readable prefix")
	passwordEnv := flag.String("password-env", "", "environment variable holding the keystore password")
	passwordFile := flag.String("password-file", "", "file holding the keystore password")
	passwordStdin := flag.Bool("password-stdin", false, "read the keystore password from stdin")
	flag.Parse()

	if *dir == "" || flag.NArg() == 0 {
		printUsage()
		os.Exit(2)
	}

	refs := make([]signer.KeyRef, 0, flag.NArg())
	for _, name := range flag.Args() {
		refs = append(refs, signer.KeyRef{Ref: name})
	}

	opened, err := signer.Open("file://"+*dir, signer.OpenOptions{
		PasswordEnv:   *passwordEnv,
		PasswordFile:  *passwordFile,
		PasswordStdin: *passwordStdin,
		Stdin:         os.Stdin,
		HRP:           *hrp,
		KeyRefs:       refs,
	})
	if err != nil {
		slog.Error("keyaddr failed", slog.Any("error", fmt.Errorf("open keystore: %w", err)))
		os.Exit(1)
	}
	local, ok := opened.(*signer.LocalSigner)
	if !ok {
		slog.Error("keyaddr failed", slog.Any("error", errors.New("keyaddr only supports local keystore directories")))
		os.Exit(1)
	}

	keys := local.Keys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].Ref < keys[j].Ref })
	for _, key := range keys {
		fmt.Printf("%s\t%s\t%s\n", key.Ref, key.Address, key.CompressedPubkey)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: keyaddr -dir DIR [-hrp HRP] [-password-env VAR] FILE...")
}
