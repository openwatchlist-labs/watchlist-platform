// screening-ledger-policy is ADR-0007 Addendum 2 D23 (F-A): the signer
// D10 specified could not be built as specified -- "exposed as a package
// function for whatever out-of-band tooling an operator runs it from"
// presumes an importer outside this module, and internal/screeningledger
// is a Go internal package, so no such importer can ever exist. This is
// a separate binary rather than a screening-ledger subcommand
// deliberately: the property D10 wanted -- "the private half never enters
// the appending process, the verifying process, or CI" -- is preserved by
// a separate executable and lost by a subcommand, which would make it
// possible to run the signer by accident in the place it must never run.
//
// Deliberately absent from runtime_executables
// (scripts/deployment/r2-4/harness/config/policy.json) -- do not add it
// on the reasoning that it is a cmd/ binary like the others. Its private
// key handling belongs on an offline host, never a deployed one.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: screening-ledger-policy <keygen|sign|fingerprint> [options]")
	}
	switch os.Args[1] {
	case "keygen":
		runKeygen(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "fingerprint":
		runFingerprint(os.Args[2:])
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

// runKeygen writes a fresh Ed25519 keypair. The private key file is
// created mode 0400 -- ADR-0007 §5.2's custody language for R, applied
// here to the policy signing key: it belongs on a host that is not the
// ledger directory's owner, and it is used only at ledger-provisioning
// and policy-change time, never by the appending or verifying process.
func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	privOut := fs.String("private-key-file", "", "path to write the Ed25519 private key, hex-encoded, mode 0400 (required)")
	pubOut := fs.String("public-key-file", "", "path to also write the Ed25519 public key, hex-encoded (optional -- the public key is always printed to stdout)")
	must(fs.Parse(args))
	if *privOut == "" {
		fatal("--private-key-file is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	must(os.WriteFile(*privOut, []byte(hex.EncodeToString(priv)), 0o400))
	if *pubOut != "" {
		must(os.WriteFile(*pubOut, []byte(hex.EncodeToString(pub)), 0o644))
	}
	fmt.Println(hex.EncodeToString(pub))
}

// runSign reads an unsigned VerificationPolicy document and the private
// key, and writes the signed envelope SignVerificationPolicy produces.
// This is the only non-test caller SignVerificationPolicy
// (internal/screeningledger/policy.go) has ever had.
func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	policyFile := fs.String("policy-file", "", "path to an unsigned VerificationPolicy JSON document (required)")
	privKeyFile := fs.String("private-key-file", "", "path to the Ed25519 private key")
	privKeyEnv := fs.String("private-key-env", "", "env var holding the Ed25519 private key")
	outputPath := fs.String("output", "", "path to write the signed envelope (default: stdout)")
	must(fs.Parse(args))
	if *policyFile == "" {
		fatal("--policy-file is required")
	}
	raw, err := os.ReadFile(*policyFile)
	must(err)
	var policy screeningledger.VerificationPolicy
	must(json.Unmarshal(raw, &policy))
	priv, err := screeningledger.LoadEd25519PrivateKey(*privKeyFile, *privKeyEnv)
	must(err)
	signed, err := screeningledger.SignVerificationPolicy(policy, priv)
	must(err)
	out, err := json.MarshalIndent(signed, "", "  ")
	must(err)
	out = append(out, '\n')
	if *outputPath == "" {
		os.Stdout.Write(out)
		return
	}
	must(os.WriteFile(*outputPath, out, 0o644))
}

// runFingerprint prints EA5's fingerprint for a public key -- the same
// value the screening-ledger verify/status/sync/anchor commands print in
// their JSON output -- so an operator can compare a trust-root key
// against an out-of-band record without running a verification.
func runFingerprint(args []string) {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	pubKeyFile := fs.String("public-key-file", "", "path to the Ed25519 public key")
	pubKeyEnv := fs.String("public-key-env", "", "env var holding the Ed25519 public key")
	must(fs.Parse(args))
	pub, err := screeningledger.LoadEd25519PublicKey(*pubKeyFile, *pubKeyEnv)
	must(err)
	fmt.Println(screeningledger.PolicyPublicKeyFingerprint(pub))
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
