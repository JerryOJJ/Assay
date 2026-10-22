package main

import (
	"testing"

	"github.com/use-assay/assay/internal/attest"
)

func TestVerifySameEvidenceDifferentVersion(t *testing.T) {
	headers := "asset\tAQUA\nseverity\t0\nbase_severity\t0\nescalated\tfalse\nmechanics\t0\naccountability\tverified\n"
	version2 := attest.PreimageVersionCheckSet + "\n" + headers + "checks\tdomain,horizon\nevidence\thorizon\turl\tclaim\n"
	version1 := attest.PreimageVersion + "\n" + headers + "evidence\thorizon\turl\tclaim\n"

	for _, expectedVersion := range []string{"", attest.PreimageVersion} {
		outcome, err := verifyPreimage(hashPreimage(version1), version2, expectedVersion)
		if err != nil {
			t.Fatalf("verifyPreimage: %v", err)
		}
		if outcome != verifyEncodingDiffers {
			t.Errorf("expected version %q: outcome = %q, want %q", expectedVersion, outcome, verifyEncodingDiffers)
		}
	}
}

func TestVerifyMatchingPreimage(t *testing.T) {
	preimage := attest.PreimageVersion + "\nasset\tAQUA\nevidence\thorizon\turl\tclaim\n"
	outcome, err := verifyPreimage(hashPreimage(preimage), preimage, "")
	if err != nil {
		t.Fatalf("verifyPreimage: %v", err)
	}
	if outcome != verifyMatch {
		t.Fatalf("outcome = %q, want %q", outcome, verifyMatch)
	}
}

func TestVerifyDifferentEvidenceIsMismatch(t *testing.T) {
	preimage := attest.PreimageVersion + "\nasset\tAQUA\nevidence\thorizon\turl\tclaim\n"
	other := attest.PreimageVersion + "\nasset\tAQUA\nevidence\thorizon\turl\tchanged\n"
	outcome, err := verifyPreimage(hashPreimage(other), preimage, "")
	if err != nil {
		t.Fatalf("verifyPreimage: %v", err)
	}
	if outcome != verifyMismatch {
		t.Fatalf("outcome = %q, want %q", outcome, verifyMismatch)
	}
}
