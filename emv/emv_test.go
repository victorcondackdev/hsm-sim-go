package emv

import (
	"bytes"
	"testing"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

var imk = keys.MustHex("0123456789ABCDEFFEDCBA9876543210")

func sampleTx() Transaction {
	return Transaction{
		Amount:           12345,
		TerminalCountry:  76,
		Currency:         986,
		Date:             "261127",
		Type:             0x00,
		UnpredictableNum: [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
		AIP:              [2]byte{0x39, 0x00},
		ATC:              0x002A,
		IAD:              keys.MustHex("03A00000"),
	}
}

func TestDataLayout(t *testing.T) {
	d, err := sampleTx().Data()
	if err != nil {
		t.Fatal(err)
	}
	want := "000000012345" + "000000000000" + "0076" + "0000000000" + "0986" + "261127" + "00" + "DEADBEEF" + "3900" + "002A" + "03A00000"
	if got := keys.HexUpper(d); got != want {
		t.Fatalf("data\n got %s\nwant %s", got, want)
	}
}

func TestDeriveICCKeyPadsAndTruncates(t *testing.T) {
	a, err := DeriveICCKey(imk, "4761739001010119", "01")
	if err != nil {
		t.Fatal(err)
	}
	if !keys.HasOddParity(a) || len(a) != 16 {
		t.Fatal("ICC key must be 16 bytes with odd parity")
	}
	// 16+2 digits: only the rightmost 16 are used, so a different leading
	// digit gives the same key.
	b, _ := DeriveICCKey(imk, "5761739001010119", "01")
	if !bytes.Equal(a, b) {
		t.Fatal("leading digits beyond 16 must be ignored")
	}
	c, _ := DeriveICCKey(imk, "4761739001010119", "02")
	if bytes.Equal(a, c) {
		t.Fatal("PSN must change the key")
	}
	if _, err := DeriveICCKey(imk, "47617390", "01"); err != ErrInput {
		t.Fatal("short PAN accepted")
	}
}

func TestARQCRoundTrip(t *testing.T) {
	pan, psn := "4761739001010119", "01"
	mk, _ := DeriveICCKey(imk, pan, psn)
	for _, s := range []Scheme{CVN18, CVN10} {
		tx := sampleTx()
		arqc, err := ARQC(mk, tx, s)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyARQC(imk, pan, psn, tx, s, arqc)
		if err != nil || !ok {
			t.Fatalf("%v: ARQC did not verify (%v)", s, err)
		}
		tx.Amount++
		if ok, _ := VerifyARQC(imk, pan, psn, tx, s, arqc); ok {
			t.Fatalf("%v: ARQC verified for a different amount", s)
		}
	}
}

func TestSessionKeyChangesWithATC(t *testing.T) {
	mk, _ := DeriveICCKey(imk, "4761739001010119", "01")
	a, _ := SessionKey(mk, 1)
	b, _ := SessionKey(mk, 2)
	if bytes.Equal(a, b) {
		t.Fatal("session keys must differ per ATC")
	}
	tx := sampleTx()
	x, _ := ARQC(mk, tx, CVN18)
	tx.ATC++
	y, _ := ARQC(mk, tx, CVN18)
	if bytes.Equal(x, y) {
		t.Fatal("ARQC must change with ATC")
	}
}

func TestARPC(t *testing.T) {
	mk, _ := DeriveICCKey(imk, "4761739001010119", "01")
	sk, _ := SessionKey(mk, 42)
	arqc, _ := ARQC(mk, sampleTx(), CVN18)
	a1, err := ARPCMethod1(sk, arqc, [2]byte{'0', '0'})
	if err != nil {
		t.Fatal(err)
	}
	// Method 1 is invertible: decrypting must give ARQC ⊕ ARC.
	p, _ := keys.DecryptECB(sk, a1)
	x := keys.XOR(p, arqc)
	if x[0] != '0' || x[1] != '0' || !bytes.Equal(x[2:], make([]byte, 6)) {
		t.Fatalf("method 1 ARPC inverse = %X", x)
	}
	a2, err := ARPCMethod2(sk, arqc, [4]byte{0x00, 0x82, 0x00, 0x00}, nil)
	if err != nil || len(a2) != 4 {
		t.Fatalf("method 2 ARPC %X %v", a2, err)
	}
}

func TestBCD(t *testing.T) {
	if got := keys.HexUpper(bcd(986, 2)); got != "0986" {
		t.Fatal(got)
	}
	if got := keys.HexUpper(bcd(1234567890, 6)); got != "001234567890" {
		t.Fatal(got)
	}
}
