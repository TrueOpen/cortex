package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
)

// onboard produces everything a new Cortex node needs before its first
// MsgStakeService, and nothing else.
//
// It exists because the two artifacts that transaction requires could not be
// produced by any tool an operator could run. service_key_proof is a signature
// over a canonical digest that cannot be assembled in a shell, and `noded tx
// hub stake-service` takes the proof without being able to compute it. The
// keystore v3 file cortexd's signer.uri=file:// reads had to come from geth or
// an equivalent. Node ships scripts/servicekeyproof, but it prints the private
// key in the clear and says of itself: "Never use a key produced here on a real
// network."
//
// It deliberately does not broadcast. Staking moves funds and cannot be undone,
// and a command that generates a key and spends money in one step gives an
// operator no moment to check the values it derived. The transaction is printed
// ready to run instead.
func newOnboardCommand(stdout io.Writer) *cobra.Command {
	var (
		chainID      string
		operator     string
		keystorePath string
		amount       string
		passwordFile string
		format       string
	)
	cmd := &cobra.Command{
		Use:   "onboard",
		Short: "Generate a service key, its keystore and the stake-service registration proof",
		Long: "Generates a new Cortex service key, writes it as a keystore v3 file, and derives the\n" +
			"service_key_proof that MsgStakeService requires. Prints the registration transaction\n" +
			"ready to run; it never broadcasts one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOnboard(cmd, stdout, onboardOptions{
				ChainID: chainID, Operator: operator, KeystorePath: keystorePath,
				Amount: amount, PasswordFile: passwordFile, Format: format,
			})
		},
	}
	cmd.Flags().StringVar(&chainID, "chain-id", "", "chain id the registration will be broadcast to (required)")
	cmd.Flags().StringVar(&operator, "operator", "", "bech32 operator address that will sign MsgStakeService (required)")
	cmd.Flags().StringVar(&keystorePath, "keystore", "", "path to write the keystore v3 file to (required)")
	cmd.Flags().StringVar(&amount, "amount", "", "bond amount in atomic units, for the printed transaction only")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "read the keystore password from this file instead of prompting")
	format = *newFormatFlag(cmd, "table")
	cmd.Flags().Lookup("format").Usage = "output format: table or json"
	return cmd
}

type onboardOptions struct {
	ChainID      string
	Operator     string
	KeystorePath string
	Amount       string
	PasswordFile string
	Format       string
}

type onboardResult struct {
	ChainID         string `json:"chain_id"`
	OperatorAddress string `json:"operator_address"`
	KeystorePath    string `json:"keystore_path"`
	ServiceAddress  string `json:"service_address"`
	// ServicePubkeyHex and ServiceKeyProofHex are for reading and for comparing
	// against logs. The base64 forms are the ones that go in the transaction:
	// both fields carry REST_BYTES_ENCODING_PROTOJSON_BASE64, so hex pasted
	// into them is not a formatting preference, it is a rejected transaction.
	ServicePubkeyHex      string `json:"service_pubkey_hex"`
	ServicePubkeyBase64   string `json:"service_pubkey_base64"`
	ServiceKeyProofHex    string `json:"service_key_proof_hex"`
	ServiceKeyProofBase64 string `json:"service_key_proof_base64"`
	StakeServiceAction    string `json:"stake_service_action"`
}

func runOnboard(cmd *cobra.Command, stdout io.Writer, opts onboardOptions) error {
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	opts.Format = format
	for _, required := range []struct{ name, value string }{
		{"--chain-id", opts.ChainID},
		{"--operator", opts.Operator},
		{"--keystore", opts.KeystorePath},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%s is required", required.name)
		}
	}
	if opts.Amount != "" {
		if _, err := strconv.ParseUint(opts.Amount, 10, 64); err != nil {
			return fmt.Errorf("--amount must be a whole number of atomic units")
		}
	}
	// Refused before a key is generated rather than after. Writing the keystore
	// is the only step that cannot be repeated safely: a second run produces a
	// different key, and the first one is gone.
	if _, err := os.Stat(opts.KeystorePath); err == nil {
		return fmt.Errorf("%s already exists; onboarding will not overwrite a keystore", opts.KeystorePath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check keystore path: %w", err)
	}

	hrp := bech32HRPOf(opts.Operator)
	if hrp == "" {
		return fmt.Errorf("--operator must be a bech32 address")
	}
	// Decoded before anything is generated, so a mistyped operator address fails
	// here rather than after a key exists on disk.
	if _, err := nodewire.CanonicalOperatorAddressBytes("operator", opts.Operator); err != nil {
		return err
	}

	password, err := readKeystorePassword(cmd, opts.PasswordFile)
	if err != nil {
		return err
	}
	defer wipe(password)

	key, err := signer.GenerateServiceKey(hrp)
	if err != nil {
		return err
	}
	pubkey, err := hex.DecodeString(key.CompressedPubkey)
	if err != nil {
		return fmt.Errorf("decode generated service pubkey: %w", err)
	}
	digest, err := nodewire.CortexServiceRegistrationDigest(opts.ChainID, opts.Operator, pubkey)
	if err != nil {
		return err
	}
	proof, err := signer.SignDigestWithPrivateKeyHex(key.PrivateKeyHex, digest)
	if err != nil {
		return err
	}
	// Verified with the public key that goes in the transaction, not with the
	// private key that produced it. A proof this node cannot check is one the
	// chain will refuse, and finding that out here costs nothing.
	if err := signer.VerifyDigestSignature(key.CompressedPubkey, digest, proof); err != nil {
		return fmt.Errorf("verify generated registration proof: %w", err)
	}

	document, err := signer.EncryptKeystoreV3(key.PrivateKeyHex, password)
	if err != nil {
		return err
	}
	if err := writeKeystoreFile(opts.KeystorePath, document); err != nil {
		return err
	}

	result := onboardResult{
		ChainID: opts.ChainID, OperatorAddress: opts.Operator, KeystorePath: opts.KeystorePath,
		ServiceAddress:        key.Address,
		ServicePubkeyHex:      key.CompressedPubkey,
		ServicePubkeyBase64:   base64.StdEncoding.EncodeToString(pubkey),
		ServiceKeyProofHex:    hex.EncodeToString(proof),
		ServiceKeyProofBase64: base64.StdEncoding.EncodeToString(proof),
	}
	result.StakeServiceAction, err = stakeServiceAction(result.ServicePubkeyBase64, result.ServiceKeyProofBase64, opts.Amount)
	if err != nil {
		return err
	}
	if opts.Format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	printOnboardResult(stdout, result, opts.Amount)
	return nil
}

// stakeServiceAction builds the --action value for `noded tx hub stake-service`.
// MsgStakeService carries a ServiceStakeActionV1 oneof rather than flat fields,
// so the registration branch is a nested document and not three separate flags.
func stakeServiceAction(pubkeyBase64, proofBase64, amount string) (string, error) {
	if amount == "" {
		amount = "<ATOMIC_UNITS>"
	}
	action := map[string]any{
		"register": map[string]any{
			"service_pubkey":    pubkeyBase64,
			"service_key_proof": proofBase64,
			"amount":            map[string]any{"atomic_units": amount},
		},
	}
	encoded, err := json.Marshal(action)
	if err != nil {
		return "", fmt.Errorf("encode stake-service action: %w", err)
	}
	return string(encoded), nil
}

func printOnboardResult(stdout io.Writer, result onboardResult, amount string) {
	fmt.Fprintf(stdout, "keystore written   %s\n", result.KeystorePath)
	fmt.Fprintf(stdout, "service address    %s\n", result.ServiceAddress)
	fmt.Fprintf(stdout, "service pubkey     %s\n", result.ServicePubkeyHex)
	fmt.Fprintf(stdout, "operator address   %s\n", result.OperatorAddress)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "The operator address signs and pays for the registration; fund it before running the")
	fmt.Fprintln(stdout, "transaction below. The service address holds no funds and is never funded.")
	fmt.Fprintln(stdout)
	if amount == "" {
		fmt.Fprintln(stdout, "Replace <ATOMIC_UNITS> with the bond amount, then run:")
	} else {
		fmt.Fprintln(stdout, "Run:")
	}
	fmt.Fprintf(stdout, "\n  noded tx hub stake-service %s \\\n    --action '%s' \\\n    --chain-id %s --from <operator-key>\n\n",
		result.OperatorAddress, result.StakeServiceAction, result.ChainID)
	fmt.Fprintln(stdout, "Then point cortexd at the keystore:")
	fmt.Fprintf(stdout, "\n  signer.uri: file://%s\n", filepath.Dir(result.KeystorePath))
	// The ref is the file name as it sits in that directory, extension
	// included: LocalSigner joins it onto signer.uri's path rather than
	// treating it as a bare identifier.
	fmt.Fprintf(stdout, "  local_identity.service_key_ref: %s\n", filepath.Base(result.KeystorePath))
}

// writeKeystoreFile writes 0600 and refuses to clobber, because the file is the
// only copy of a key that was generated seconds ago.
func writeKeystoreFile(path string, document []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create keystore directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create keystore file: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(document); err != nil {
		return fmt.Errorf("write keystore file: %w", err)
	}
	return file.Sync()
}

// readKeystorePassword takes the password from a file when one is named, and
// prompts without echo otherwise.
//
// There is no --password flag. A password in argv is in the process list and in
// the shell history of every machine it is typed on, and an operator running
// this on 29 machines will paste it 29 times.
func readKeystorePassword(cmd *cobra.Command, passwordFile string) ([]byte, error) {
	if passwordFile != "" {
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		// One trailing newline is what an editor or `echo` leaves; stripping it
		// is what makes a password file interchangeable with a typed password.
		password := strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return nil, fmt.Errorf("password file %s is empty", passwordFile)
		}
		return []byte(password), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("no terminal to prompt on: pass --password-file")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "keystore password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("keystore password must not be empty")
	}
	// Confirmed because a typo here is unrecoverable: the key is generated after
	// this point and the keystore is its only copy.
	fmt.Fprint(cmd.ErrOrStderr(), "confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return nil, fmt.Errorf("read password confirmation: %w", err)
	}
	defer wipe(second)
	if string(first) != string(second) {
		wipe(first)
		return nil, fmt.Errorf("passwords do not match")
	}
	return first, nil
}

func wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

// bech32HRPOf is the prefix before the last separator, matching how the daemon
// derives the HRP it passes to the signer.
func bech32HRPOf(address string) string {
	trimmed := strings.TrimSpace(address)
	if cut := strings.LastIndex(trimmed, "1"); cut > 0 {
		return trimmed[:cut]
	}
	return ""
}
