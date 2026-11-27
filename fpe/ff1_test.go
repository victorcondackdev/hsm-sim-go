package fpe

import (
	"errors"
	"testing"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// NIST SP 800-38G FF1 samples 1–3 (AES-128).
func TestFF1NISTSamples(t *testing.T) {
	key := keys.MustHex("2B7E151628AED2A6ABF7158809CF4F3C")
	cases := []struct {
		alphabet, tweak, pt, ct string
	}{
		{Digits, "", "0123456789", "2433477484"},
		{Digits, "39383736353433323130", "0123456789", "6124200773"},
		{Alphanumeric, "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum"},
	}
	for _, c := range cases {
		f, err := NewFF1(key, c.alphabet)
		if err != nil {
			t.Fatal(err)
		}
		tw := keys.MustHex(c.tweak)
		got, err := f.Encrypt(c.pt, tw)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.ct {
			t.Errorf("Encrypt(%s) = %s, want %s", c.pt, got, c.ct)
		}
		back, _ := f.Decrypt(got, tw)
		if back != c.pt {
			t.Errorf("Decrypt(%s) = %s, want %s", got, back, c.pt)
		}
	}
}

func TestFF1AES256Sample7(t *testing.T) {
	// Sample 7: AES-256, radix 10, empty tweak.
	key := keys.MustHex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
	f, _ := NewFF1(key, Digits)
	got, _ := f.Encrypt("0123456789", nil)
	if got != "6657667009" {
		t.Fatalf("sample 7 = %s", got)
	}
}

func TestFF1RoundTripLengths(t *testing.T) {
	f, _ := NewFF1(keys.MustHex("2B7E151628AED2A6ABF7158809CF4F3C"), Digits)
	in := "12345678901234567890123456789012345678901234567890"
	for n := f.MinLen(); n <= len(in); n++ {
		x := in[:n]
		c, err := f.Encrypt(x, []byte("tw"))
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != n || !f.Contains(c) {
			t.Fatalf("ciphertext %q not in domain", c)
		}
		p, _ := f.Decrypt(c, []byte("tw"))
		if p != x {
			t.Fatalf("round trip n=%d: %s != %s", n, p, x)
		}
	}
}

func TestFF1Errors(t *testing.T) {
	f, _ := NewFF1(keys.MustHex("2B7E151628AED2A6ABF7158809CF4F3C"), Digits)
	if f.MinLen() != 6 {
		t.Fatalf("radix 10 minlen = %d", f.MinLen())
	}
	if _, err := f.Encrypt("12345", nil); !errors.Is(err, ErrLength) {
		t.Fatal("short input accepted")
	}
	if _, err := f.Encrypt("12345a", nil); !errors.Is(err, ErrSymbol) {
		t.Fatal("bad symbol accepted")
	}
	if _, err := NewFF1(make([]byte, 16), "aa"); !errors.Is(err, ErrAlphabet) {
		t.Fatal("duplicate alphabet accepted")
	}
}
