package cardauth

import (
	"testing"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

var cvk = keys.MustHex("0123456789ABCDEFFEDCBA9876543210")

func TestCVVVisaExample(t *testing.T) {
	// The worked example of the Visa CVV algorithm.
	got, err := CVV(cvk, "4123456789012345", "8701", "101")
	if err != nil {
		t.Fatal(err)
	}
	if got != "561" {
		t.Fatalf("CVV = %s, want 561", got)
	}
	ok, _ := VerifyCVV(cvk, "4123456789012345", "8701", "101", "561")
	if !ok {
		t.Fatal("VerifyCVV rejected the right CVV")
	}
	ok, _ = VerifyCVV(cvk, "4123456789012345", "8701", "101", "562")
	if ok {
		t.Fatal("VerifyCVV accepted a wrong CVV")
	}
}

func TestCVVServiceCodesDiffer(t *testing.T) {
	a, _ := CVV(cvk, "4123456789012345", "8701", "101")
	b, _ := CVV(cvk, "4123456789012345", "8701", ServiceCVV2)
	c, _ := CVV(cvk, "4123456789012345", "8701", ServiceICVV)
	if a == b && b == c {
		t.Fatal("CVV, CVV2 and iCVV should generally differ")
	}
}

func TestDecimalize(t *testing.T) {
	if got := decimalize("A1B2C3D4E5F67890"); got != "1234567890012345" {
		t.Fatalf("decimalize = %s", got)
	}
}

func TestPVVRoundTrip(t *testing.T) {
	pvv, err := PVV(cvk, "4123456789012345", 1, "1234")
	if err != nil {
		t.Fatal(err)
	}
	if len(pvv) != 4 || !isDigits(pvv, 4, 4) {
		t.Fatalf("PVV = %q", pvv)
	}
	if ok, _ := VerifyPVV(cvk, "4123456789012345", 1, "1234", pvv); !ok {
		t.Fatal("PVV did not verify")
	}
	if ok, _ := VerifyPVV(cvk, "4123456789012345", 2, "1234", pvv); ok {
		// A different PVKI changes the TSP; a collision is possible in
		// principle (1 in 10^4) but not for this fixed input.
		t.Fatal("PVV verified under another PVKI")
	}
}

func TestIBM3624(t *testing.T) {
	s := IBM3624{Key: cvk}
	nat, err := s.NaturalPIN("4123456789012345", 4)
	if err != nil {
		t.Fatal(err)
	}
	off, _ := s.Offset("4123456789012345", nat)
	if off != "0000" {
		t.Fatalf("offset of natural PIN = %s", off)
	}
	off, _ = s.Offset("4123456789012345", "9876")
	if ok, _ := s.Verify("4123456789012345", "9876", off); !ok {
		t.Fatal("offset did not verify")
	}
	if ok, _ := s.Verify("4123456789012345", "9877", off); ok {
		t.Fatal("wrong PIN verified")
	}
	if ok, _ := s.Verify("4123456789012345", "98765", off); ok {
		t.Fatal("length mismatch verified")
	}
	custom := IBM3624{Key: cvk, ValidationData: func(pan string) string { return "1234567890ABCDEF" }}
	if _, err := custom.NaturalPIN("4123456789012345", 6); err != nil {
		t.Fatal(err)
	}
}

func TestInputValidation(t *testing.T) {
	if _, err := CVV(cvk[:8], "4123456789012345", "8701", "101"); err != ErrKey {
		t.Fatal("short key")
	}
	if _, err := CVV(cvk, "41234", "8701", "101"); err != ErrInput {
		t.Fatal("short PAN")
	}
	if _, err := PVV(cvk, "4123456789012345", 10, "1234"); err != ErrInput {
		t.Fatal("bad PVKI")
	}
	if _, err := (IBM3624{Key: cvk, Decimalization: "012"}).NaturalPIN("4123456789012345", 4); err != ErrInput {
		t.Fatal("bad table")
	}
}
