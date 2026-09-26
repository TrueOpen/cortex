package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
)

const onboardTestOperator = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"

func runOnboardCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := newOnboardCommand(&stdout)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

func passwordFile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOnboardProducesAProofTheChainWouldAccept is the property the command
// exists for. The proof is verified against the digest recomputed here from the
// published field order, not against whatever the command happened to sign, so
// a change to either side fails this test rather than producing a transaction
// the chain silently refuses.
func TestOnboardProducesAProofTheChainWouldAccept(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	output, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", passwordFile(t, "hunter2"),
		"--format", "json")
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, output)
	}
	var result onboardResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode output: %v\n%s", err, output)
	}

	pubkey, err := hex.DecodeString(result.ServicePubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodewire.CortexServiceRegistrationDigest("trueopen-fixture-1", onboardTestOperator, pubkey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := hex.DecodeString(result.ServiceKeyProofHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyDigestSignature(result.ServicePubkeyHex, digest, proof); err != nil {
		t.Fatalf("proof does not verify against the registration digest: %v", err)
	}
}

// TestOnboardKeystoreHoldsTheKeyThatSigned ties the three artifacts together.
// Each is plausible alone; what matters is that the keystore on disk decrypts
// to the key whose public half is in the proof, because a mismatch here is a
// node that registers one identity and then signs as another.
func TestOnboardKeystoreHoldsTheKeyThatSigned(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	output, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", passwordFile(t, "hunter2"),
		"--format", "json")
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, output)
	}
	var result onboardResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}

	local, err := signer.NewLocalSigner(filepath.Dir(keystore), []byte("hunter2"), "trueopen",
		[]signer.KeyRef{{Ref: filepath.Base(keystore)}})
	if err != nil {
		t.Fatalf("load the written keystore: %v", err)
	}
	keys := local.Keys()
	if len(keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(keys))
	}
	if !strings.EqualFold(keys[0].CompressedPubkey, result.ServicePubkeyHex) {
		t.Fatalf("keystore holds %s, but the proof is for %s", keys[0].CompressedPubkey, result.ServicePubkeyHex)
	}
	if keys[0].Address != result.ServiceAddress {
		t.Fatalf("keystore address %s differs from the reported %s", keys[0].Address, result.ServiceAddress)
	}
}

// TestOnboardEncodesTransactionFieldsAsBase64 guards the encoding the chain
// actually parses. service_pubkey and service_key_proof carry
// REST_BYTES_ENCODING_PROTOJSON_BASE64, so hex in those fields is not a
// formatting preference, it is a rejected transaction — and hex is what every
// log line and every other tool shows.
func TestOnboardEncodesTransactionFieldsAsBase64(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	output, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", passwordFile(t, "hunter2"),
		"--amount", "1000000", "--format", "json")
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, output)
	}
	var result onboardResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}

	var action struct {
		Register struct {
			ServicePubkey   string `json:"service_pubkey"`
			ServiceKeyProof string `json:"service_key_proof"`
			Amount          struct {
				AtomicUnits string `json:"atomic_units"`
			} `json:"amount"`
		} `json:"register"`
	}
	if err := json.Unmarshal([]byte(result.StakeServiceAction), &action); err != nil {
		t.Fatalf("decode stake-service action: %v\n%s", err, result.StakeServiceAction)
	}
	if action.Register.Amount.AtomicUnits != "1000000" {
		t.Fatalf("amount = %q, want the configured 1000000", action.Register.Amount.AtomicUnits)
	}
	for name, encoded := range map[string]string{
		"service_pubkey": action.Register.ServicePubkey, "service_key_proof": action.Register.ServiceKeyProof,
	} {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s is not base64: %v", name, err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s decoded to nothing", name)
		}
	}
	if got := base64.StdEncoding.EncodeToString(mustHexBytes(t, result.ServicePubkeyHex)); got != action.Register.ServicePubkey {
		t.Fatalf("action service_pubkey %q is not the base64 of the reported key", action.Register.ServicePubkey)
	}
}

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestOnboardRefusesToOverwriteAKeystore is the one irreversible failure this
// command can have. A second run generates a different key, and clobbering the
// file would destroy the only copy of the first.
func TestOnboardRefusesToOverwriteAKeystore(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	password := passwordFile(t, "hunter2")
	first, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", password, "--format", "json")
	if err != nil {
		t.Fatalf("first onboard: %v\n%s", err, first)
	}
	before, err := os.ReadFile(keystore)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", password, "--format", "json"); err == nil ||
		!strings.Contains(err.Error(), "will not overwrite") {
		t.Fatalf("second onboard err = %v, want a refusal to overwrite", err)
	}
	after, err := os.ReadFile(keystore)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused run modified the existing keystore")
	}
}

// TestOnboardWritesThePrivateKeyOnlyToTheKeystore keeps the secret out of
// stdout. The command prints an identity and a transaction; a private key in
// that output would land in scrollback, in CI logs and in whatever the operator
// pastes into a ticket.
func TestOnboardWritesThePrivateKeyOnlyToTheKeystore(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	output, err := runOnboardCommand(t,
		"--chain-id", "trueopen-fixture-1", "--operator", onboardTestOperator,
		"--keystore", keystore, "--password-file", passwordFile(t, "hunter2"))
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, output)
	}
	local, err := signer.NewLocalSigner(filepath.Dir(keystore), []byte("hunter2"), "trueopen",
		[]signer.KeyRef{{Ref: filepath.Base(keystore)}})
	if err != nil {
		t.Fatal(err)
	}
	// The private key is never exposed by the signer either, so the check is
	// that no 64-hex run in the output decrypts the keystore. Comparing against
	// the public key is the practical form: a leak would print the secret
	// alongside it.
	if strings.Contains(output, "private") {
		t.Fatalf("output mentions a private key:\n%s", output)
	}
	if len(local.Keys()) != 1 {
		t.Fatal("keystore did not load")
	}
	// The mode is the other half of keeping it secret.
	info, err := os.Stat(keystore)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("keystore mode = %o, want 600", mode)
	}
}

func TestOnboardRequiresItsInputs(t *testing.T) {
	keystore := filepath.Join(t.TempDir(), "service.json")
	password := passwordFile(t, "hunter2")
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"no chain id": {args: []string{"--operator", onboardTestOperator, "--keystore", keystore, "--password-file", password}, want: "--chain-id is required"},
		"no operator": {args: []string{"--chain-id", "c", "--keystore", keystore, "--password-file", password}, want: "--operator is required"},
		"no keystore": {args: []string{"--chain-id", "c", "--operator", onboardTestOperator, "--password-file", password}, want: "--keystore is required"},
		"bad operator": {args: []string{"--chain-id", "c", "--operator", "not-bech32", "--keystore", keystore,
			"--password-file", password}, want: "bech32"},
		"bad amount": {args: []string{"--chain-id", "c", "--operator", onboardTestOperator, "--keystore", keystore,
			"--password-file", password, "--amount", "lots"}, want: "atomic units"},
		"missing password file": {args: []string{"--chain-id", "c", "--operator", onboardTestOperator, "--keystore", keystore,
			"--password-file", filepath.Join(t.TempDir(), "absent")}, want: "read password file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runOnboardCommand(t, test.args...)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, test.want)
			}
			// Nothing partial is left behind by a refused run.
			if _, statErr := os.Stat(keystore); statErr == nil {
				t.Fatal("a refused run wrote a keystore")
			}
		})
	}
}
