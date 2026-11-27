package tokenize

import (
	"fmt"
	"sync"
	"testing"
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	k, err := RandomKeys()
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// luhnComplete appends the check digit that makes body Luhn-valid.
func luhnComplete(body string) string {
	for d := '0'; d <= '9'; d++ {
		if Luhn(body + string(d)) {
			return body + string(d)
		}
	}
	panic("unreachable")
}

func TestLuhn(t *testing.T) {
	for _, s := range []string{"4111111111111111", "5555555555554444", "378282246310005", "6062825624254001"} {
		if !Luhn(s) {
			t.Errorf("%s should be valid", s)
		}
	}
	for _, s := range []string{"4111111111111112", "", "41x1"} {
		if Luhn(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestTokenShape(t *testing.T) {
	v := newVault(t)
	for _, pan := range []string{"4111111111111111", "5555555555554444", "378282246310005", "4222222222222", "6062820000000000006"} {
		if !Luhn(pan) {
			pan = luhnComplete(pan[:len(pan)-1])
		}
		tok, err := v.Tokenize(pan)
		if err != nil {
			t.Fatalf("%s: %v", pan, err)
		}
		if len(tok) != len(pan) || tok[:6] != pan[:6] || tok[len(tok)-4:] != pan[len(pan)-4:] {
			t.Fatalf("token %s does not preserve shape of %s", tok, pan)
		}
		if Luhn(tok) {
			t.Fatalf("token %s passes Luhn", tok)
		}
		if tok == pan {
			t.Fatal("token equals PAN")
		}
		again, _ := v.Tokenize(pan)
		if again != tok {
			t.Fatal("tokenization must be deterministic per vault")
		}
		back, err := v.Detokenize(tok)
		if err != nil || back != pan {
			t.Fatalf("Detokenize = %s, %v", back, err)
		}
	}
}

func TestUniqueTokensUnderConcurrency(t *testing.T) {
	v := newVault(t)
	var wg sync.WaitGroup
	tokens := make([]string, 2000)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pan := luhnComplete(fmt.Sprintf("411111%09d", i))
			tok, err := v.Tokenize(pan)
			if err != nil {
				t.Error(err)
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, tok := range tokens {
		if seen[tok] {
			t.Fatalf("duplicate token %s", tok)
		}
		seen[tok] = true
	}
	if v.Len() != len(tokens) {
		t.Fatalf("vault has %d tokens", v.Len())
	}
}

func TestErrors(t *testing.T) {
	v := newVault(t)
	if _, err := v.Tokenize("4111111111111112"); err != ErrPAN {
		t.Fatal("bad Luhn accepted")
	}
	if _, err := v.Detokenize("4111110000001111"); err != ErrNotFound {
		t.Fatal("unknown token")
	}
	if _, err := v.Detokenize("41"); err != ErrToken {
		t.Fatal("short token")
	}
	if Mask("4111111111111111") != "411111******1111" {
		t.Fatal(Mask("4111111111111111"))
	}
}
