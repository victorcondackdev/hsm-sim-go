package pinblock

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// fixed returns a deterministic "random" reader.
func fixed() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x5C, 0xA1, 0x37}, 32)) }

func TestFormat0Textbook(t *testing.T) {
	// The classic ISO 9564 example: PIN 1234, PAN 43219876543210987.
	b, err := Encode(Format0, "1234", "43219876543210987", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.HexUpper(b); got != "0412AC89ABCDEF67" {
		t.Fatalf("format 0 = %s, want 0412AC89ABCDEF67", got)
	}
	pin, err := Decode(Format0, b, "43219876543210987")
	if err != nil || pin != "1234" {
		t.Fatalf("Decode = %q, %v", pin, err)
	}
}

func TestFormat2(t *testing.T) {
	b, _ := Encode(Format2, "12345", "", nil)
	if got := keys.HexUpper(b); got != "2512345FFFFFFFFF" {
		t.Fatalf("format 2 = %s", got)
	}
}

func TestFormat3FillRange(t *testing.T) {
	b, _ := Encode(Format3, "1234", "4111111111111111", fixed())
	af, _ := panField("4111111111111111")
	n := unpackNibbles(keys.XOR(b, af))
	if n[0] != 3 || n[1] != 4 {
		t.Fatalf("header %v", n[:2])
	}
	for _, v := range n[6:] {
		if v < 0xA {
			t.Fatalf("fill nibble %X outside A-F", v)
		}
	}
}

func TestFormat4Layout(t *testing.T) {
	b, _ := Encode(Format4, "1234", "", fixed())
	if got := keys.HexUpper(b[:8]); got != "441234AAAAAAAAAA" {
		t.Fatalf("format 4 PIN field = %s", got)
	}
	af, _ := panField4("1234567890123456789")
	if got := keys.HexUpper(af); got != "71234567890123456789000000000000" {
		t.Fatalf("format 4 PAN field (19) = %s", got)
	}
	af, _ = panField4("432198765432")
	if got := keys.HexUpper(af); got != "04321987654320000000000000000000" {
		t.Fatalf("format 4 PAN field (12) = %s", got)
	}
	af, _ = panField4("12345")
	if got := keys.HexUpper(af); got != "00000000123450000000000000000000" {
		t.Fatalf("format 4 PAN field (short) = %s", got)
	}
}

func TestRoundTripAllFormats(t *testing.T) {
	tdes := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	aes := keys.MustHex("2b7e151628aed2a6abf7158809cf4f3c")
	pans := []string{"4111111111111111", "5555555555554444", "6062820000000000012"}
	pins := []string{"0000", "1234", "987654", "123456789012"}
	for f := Format0; f <= Format4; f++ {
		key := tdes
		if f == Format4 {
			key = aes
		}
		for _, pan := range pans {
			for _, pin := range pins {
				enc, err := Encrypt(f, key, pin, pan, fixed())
				if err != nil {
					t.Fatalf("%v %s: %v", f, pin, err)
				}
				if len(enc) != f.BlockSize() {
					t.Fatalf("%v: block size %d", f, len(enc))
				}
				got, err := Decrypt(f, key, enc, pan)
				if err != nil || got != pin {
					t.Fatalf("%v: Decrypt = %q, %v; want %q", f, got, err, pin)
				}
			}
		}
	}
}

func TestPANBinding(t *testing.T) {
	key := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	enc, _ := Encrypt(Format0, key, "1234", "4111111111111111", nil)
	if pin, err := Decrypt(Format0, key, enc, "4111111111111129"); err == nil && pin == "1234" {
		t.Fatal("format 0 block must not decode to the same PIN under another PAN")
	}
	aes := keys.MustHex("2b7e151628aed2a6abf7158809cf4f3c")
	enc, _ = Encrypt(Format4, aes, "1234", "4111111111111111", fixed())
	if _, err := Decrypt(Format4, aes, enc, "4111111111111129"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("format 4 under wrong PAN: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for _, pin := range []string{"", "123", "1234567890123", "12a4"} {
		if _, err := Encode(Format0, pin, "4111111111111111", nil); !errors.Is(err, ErrPIN) {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
	if _, err := Encode(Format0, "1234", "41x1", nil); !errors.Is(err, ErrPAN) {
		t.Errorf("bad pan: %v", err)
	}
	if _, err := Encode(Format4, "1234", strings.Repeat("1", 20), fixed()); err != nil {
		t.Errorf("format 4 encode ignores PAN: %v", err)
	}
	if _, err := Decode(Format0, make([]byte, 7), "4111111111111111"); !errors.Is(err, ErrMalformed) {
		t.Errorf("short block: %v", err)
	}
	bad := keys.MustHex("0412AC89ABCDEF60") // fill nibble no longer F
	if _, err := Decode(Format0, bad, "43219876543210987"); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad fill: %v", err)
	}
	if _, err := Encode(Format(9), "1234", "4111111111111111", nil); !errors.Is(err, ErrFormat) {
		t.Errorf("format 9: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0x04, 0x12, 0xAC, 0x89, 0xAB, 0xCD, 0xEF, 0x67}, "43219876543210987")
	f.Fuzz(func(t *testing.T, b []byte, pan string) {
		for fm := Format0; fm <= Format4; fm++ {
			pin, err := Decode(fm, b, pan)
			if err == nil && !validPIN(pin) {
				t.Fatalf("decoded invalid PIN %q", pin)
			}
		}
	})
}
