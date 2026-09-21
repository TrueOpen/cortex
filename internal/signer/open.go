package signer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// Signer is the full surface cortexd needs: application digests plus chain
// transactions. Both Client (remote service) and LocalSigner (in-process key
// material) implement it.
type Signer interface {
	SignDigest(context.Context, DigestRequest) ([]byte, error)
	SignCosmosTx(context.Context, CosmosTxRequest) ([]byte, error)
	// CanSignCosmosTx reports whether this signer can actually produce chain
	// transactions. A signer that cannot must not let the daemon advertise a
	// ready tx broadcaster, because the node would then take on task
	// liabilities it is unable to settle.
	CanSignCosmosTx() bool
}

var (
	_ Signer = (*Client)(nil)
	_ Signer = (*LocalSigner)(nil)
)

// OpenOptions configures how a signer URI is resolved.
type OpenOptions struct {
	// PasswordEnv, PasswordFile and PasswordStdin locate the password for an
	// encrypted local key file. At most one may be set. They are ignored for
	// remote signers and for plaintext files.
	PasswordEnv   string
	PasswordFile  string
	PasswordStdin bool
	// Stdin overrides the reader used by PasswordStdin. Tests set it; callers
	// leave it nil to read the process stdin.
	Stdin io.Reader
	// HRP is the bech32 prefix used to derive signer addresses from local
	// keys. It is required for a file signer.
	HRP string
	// KeyRefs are the keys to load. Each ref is a keystore v3 file name under
	// the signer directory, or an absolute path.
	KeyRefs []KeyRef
}

// Open resolves a signer URI. http and https delegate to an external signing
// service; file loads key material into this process.
//
// In-process signing means a compromise of cortexd is a compromise of the
// keys. It exists for integration environments where running a separate
// signing service is not yet practical.
func Open(uri string, opts OpenOptions) (Signer, error) {
	trimmed := strings.TrimSpace(uri)
	if trimmed == "" {
		return nil, fmt.Errorf("signer uri is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse signer uri: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return NewClient(ClientConfig{Endpoint: trimmed}), nil
	case "file":
		// A non-empty host names a remote machine. Silently treating it as a
		// local path would open a different directory than the operator wrote.
		if parsed.Host != "" {
			return nil, fmt.Errorf("signer uri %q must not have a host: use file:///absolute/dir or file:relative/dir", uri)
		}
		dir := localKeyPath(parsed)
		if dir == "" {
			return nil, fmt.Errorf("signer uri %q has no directory path", uri)
		}
		password, err := resolveKeyFilePassword(opts)
		if err != nil {
			return nil, err
		}
		defer zero(password)
		return NewLocalSigner(dir, password, opts.HRP, opts.KeyRefs)
	default:
		return nil, fmt.Errorf("unsupported signer uri scheme %q: use http, https, or file", parsed.Scheme)
	}
}

// localKeyPath accepts file:///absolute/dir and file:relative/dir. A keystore
// directory is exactly what `geth account new --keystore <dir>` produces.
func localKeyPath(parsed *url.URL) string {
	if parsed.Path != "" {
		return parsed.Path
	}
	return parsed.Opaque
}

func resolveKeyFilePassword(opts OpenOptions) ([]byte, error) {
	env := strings.TrimSpace(opts.PasswordEnv)
	file := strings.TrimSpace(opts.PasswordFile)
	configured := 0
	for _, set := range []bool{env != "", file != "", opts.PasswordStdin} {
		if set {
			configured++
		}
	}
	switch {
	case configured > 1:
		return nil, fmt.Errorf("signer password_env, password_file and password_stdin are mutually exclusive")
	case opts.PasswordStdin:
		reader := opts.Stdin
		if reader == nil {
			reader = os.Stdin
		}
		line, err := bufio.NewReader(reader).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read signer password from stdin: %w", err)
		}
		return trimPassword([]byte(line))
	case env != "":
		value, ok := os.LookupEnv(env)
		if !ok {
			return nil, fmt.Errorf("signer password environment variable %q is not set", env)
		}
		return trimPassword([]byte(value))
	case file != "":
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read signer password file: %w", err)
		}
		return trimPassword(raw)
	default:
		// No password configured: only a plaintext key file can load, and
		// NewLocalSigner reports the mismatch if the file turns out encrypted.
		return nil, nil
	}
}

func trimPassword(raw []byte) ([]byte, error) {
	trimmed := strings.TrimRight(string(raw), "\r\n")
	if trimmed == "" {
		return nil, fmt.Errorf("signer password must not be empty")
	}
	return []byte(trimmed), nil
}
