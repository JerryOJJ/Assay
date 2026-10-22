package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/use-assay/assay/internal/attest"
)

const (
	verifyMatch           = "MATCH"
	verifyMismatch        = "MISMATCH"
	verifyEncodingDiffers = "ENCODING_DIFFERS"
)

type commandExitError struct {
	code int
	err  error
}

func (e *commandExitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return ""
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	expectedVersion := fs.String("version", "", "expected preimage encoding version")
	if err := fs.Parse(args); err != nil {
		return &commandExitError{code: 3, err: err}
	}
	if fs.NArg() != 2 {
		return &commandExitError{code: 3, err: fmt.Errorf("verify takes a hash and preimage path")}
	}

	preimage, err := readPreimage(fs.Arg(1))
	if err != nil {
		return &commandExitError{code: 3, err: err}
	}
	outcome, err := verifyPreimage(fs.Arg(0), preimage, *expectedVersion)
	if err != nil {
		return &commandExitError{code: 3, err: err}
	}
	fmt.Fprintln(os.Stdout, outcome)
	switch outcome {
	case verifyMatch:
		return nil
	case verifyMismatch:
		return &commandExitError{code: 1}
	case verifyEncodingDiffers:
		return &commandExitError{code: 2}
	default:
		return &commandExitError{code: 3, err: fmt.Errorf("unknown verification outcome %q", outcome)}
	}
}

func readPreimage(path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("read preimage: %w", err)
	}
	return string(data), nil
}

func verifyPreimage(storedHash, preimage, expectedVersion string) (string, error) {
	storedHash = strings.TrimSpace(storedHash)
	decoded, err := hex.DecodeString(storedHash)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("hash must be 64 hexadecimal characters")
	}
	storedHash = strings.ToLower(storedHash)

	versions := []string{attest.PreimageVersion, attest.PreimageVersionCheckSet}
	if expectedVersion != "" {
		if expectedVersion != attest.PreimageVersion && expectedVersion != attest.PreimageVersionCheckSet {
			return "", fmt.Errorf("unsupported encoding version %q", expectedVersion)
		}
		versions = []string{expectedVersion}
	}

	actualVersion := strings.SplitN(preimage, "\n", 2)[0]
	currentMatches := hashPreimage(preimage) == storedHash
	if expectedVersion == "" {
		if currentMatches {
			return verifyMatch, nil
		}
	} else if actualVersion == expectedVersion {
		if currentMatches {
			return verifyMatch, nil
		}
		return verifyMismatch, nil
	}

	for _, version := range versions {
		candidate, ok := preimageForVersion(preimage, version)
		if ok && candidate != preimage && hashPreimage(candidate) == storedHash {
			return verifyEncodingDiffers, nil
		}
	}
	if expectedVersion != "" && currentMatches &&
		(actualVersion == attest.PreimageVersion || actualVersion == attest.PreimageVersionCheckSet) {
		return verifyEncodingDiffers, nil
	}
	return verifyMismatch, nil
}

func preimageForVersion(preimage, version string) (string, bool) {
	lines := strings.Split(preimage, "\n")
	if len(lines) < 2 || (version != attest.PreimageVersion && version != attest.PreimageVersionCheckSet) {
		return "", false
	}
	if lines[0] != attest.PreimageVersion && lines[0] != attest.PreimageVersionCheckSet {
		return "", false
	}

	if version == attest.PreimageVersion {
		if lines[0] != attest.PreimageVersionCheckSet || len(lines) < 9 || !strings.HasPrefix(lines[7], "checks\t") {
			return "", false
		}
		lines = append(lines[:7], lines[8:]...)
	} else {
		return "", false
	}

	if lines[0] == version {
		return "", false
	}
	lines[0] = version
	return strings.Join(lines, "\n"), true
}

func hashPreimage(preimage string) string {
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:])
}
