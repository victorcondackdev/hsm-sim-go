package keys

import (
	"bytes"
	"errors"
	"testing"
)

const testKey = "0123456789ABCDEFFEDCBA9876543210"

func TestKCVKnownValue(t *testing.T) {
	// The ubiquitous ANSI test key; its KCV appears in every HSM manual.
	got, err := KCV(MustHex(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if got != "08D7B4" {
		t.Fatalf("KCV = %s, want 08D7B4", got)
	}
}

func TestCMACRFC4493(t *testing.T) {
	key := MustHex("2b7e151628aed2a6abf7158809cf4f3c")
	cases := []struct{ msg, tag string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			"dfa66747de9ae63030ca32611497c827"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			"51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		got, err := CMAC(key, MustHex(c.msg))
		if err != nil {
			t.Fatal(err)
		}
		if HexUpper(got) != HexUpper(MustHex(c.tag)) {
			t.Errorf("CMAC(%q) = %x, want %s", c.msg, got, c.tag)
		}
	}
}

func TestRetailMACMatchesConstruction(t *testing.T) {
	key := MustHex(testKey)
	// One block: retail MAC is exactly double-length TDES encryption.
	block := MustHex("4E6F772069732074")
	mac, err := RetailMAC(key, block, Pad1)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := EncryptECB(key, block)
	if !bytes.Equal(mac, want) {
		t.Fatalf("single block retail MAC %x != TDES %x", mac, want)
	}
	// Several blocks: single-DES CBC-MAC under K1 for all but the last
	// block, then full TDES on the chained last block.
	data := []byte("Now is the time for all ")
	mac, _ = RetailMAC(key, data, Pad1)
	h, _ := CBCMAC(key[:8], data[:16], Pad1)
	last := XOR(h, data[16:24])
	want, _ = EncryptECB(key, last)
	if !bytes.Equal(mac, want) {
		t.Fatalf("multi block retail MAC %x != %x", mac, want)
	}
}

func TestPadding(t *testing.T) {
	cases := []struct {
		in   string
		p    Padding
		want string
	}{
		{"", Pad1, "0000000000000000"},
		{"01", Pad1, "0100000000000000"},
		{"0102030405060708", Pad1, "0102030405060708"},
		{"", Pad2, "8000000000000000"},
		{"0102030405060708", Pad2, "01020304050607088000000000000000"},
	}
	for _, c := range cases {
		if got := HexUpper(Pad(MustHex(c.in), 8, c.p)); got != c.want {
			t.Errorf("Pad(%s,%d) = %s, want %s", c.in, c.p, got, c.want)
		}
	}
}

func TestParity(t *testing.T) {
	k := FixParity(MustHex("0000000000000000"))
	if HexUpper(k) != "0101010101010101" || !HasOddParity(k) {
		t.Fatalf("FixParity = %X", k)
	}
	if !HasOddParity(MustHex(testKey)) {
		t.Fatal("test key should have odd parity")
	}
	if HasOddParity(MustHex("00")) {
		t.Fatal("00 has even parity")
	}
}

func TestSplitCombine(t *testing.T) {
	key, err := Random(16)
	if err != nil {
		t.Fatal(err)
	}
	for n := 2; n <= 5; n++ {
		comps, err := Split(key, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range comps {
			if !HasOddParity(c) {
				t.Fatalf("component %X lacks parity", c)
			}
		}
		got, err := Combine(comps...)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) {
			t.Fatalf("n=%d: Combine(Split(k)) = %X, want %X", n, got, key)
		}
	}
	if _, err := Split(key, 1); err == nil {
		t.Fatal("Split(1) should fail")
	}
}

func TestECBCBCRoundTrip(t *testing.T) {
	for _, l := range []int{8, 16, 24} {
		k, _ := Random(l)
		data := []byte("0123456789abcdef")
		c, err := EncryptECB(k, data)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := DecryptECB(k, c)
		if !bytes.Equal(p, data) {
			t.Fatal("ECB round trip")
		}
		c, _ = EncryptCBC(k, nil, data)
		p, _ = DecryptCBC(k, nil, c)
		if !bytes.Equal(p, data) {
			t.Fatal("CBC round trip")
		}
	}
	if _, err := EncryptECB(make([]byte, 7), make([]byte, 8)); !errors.Is(err, ErrKeyLength) {
		t.Fatalf("want ErrKeyLength, got %v", err)
	}
	if _, err := EncryptECB(make([]byte, 16), make([]byte, 7)); !errors.Is(err, ErrBlockLength) {
		t.Fatalf("want ErrBlockLength, got %v", err)
	}
}

func TestKCVAESIsCMACPrefix(t *testing.T) {
	k := MustHex("2b7e151628aed2a6abf7158809cf4f3c")
	kcv, err := KCVAES(k)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := CMAC(k, make([]byte, 16))
	if kcv != HexUpper(m[:5]) || len(kcv) != 10 {
		t.Fatalf("KCVAES = %s", kcv)
	}
}
