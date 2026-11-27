// Package fpe implements FF1 format-preserving encryption (NIST SP 800-38G)
// over AES. FF1 encrypts a string of digits (or any alphabet up to radix 36)
// into another string of the same length and alphabet, which is what lets a
// tokenization service replace the middle of a PAN without changing its
// shape.
package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math/big"
	"strings"
)

// Alphabets for common radixes; the radix is the alphabet length.
const (
	Digits       = "0123456789"
	Alphanumeric = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// Errors returned by this package.
var (
	ErrAlphabet = errors.New("fpe: alphabet must have 2 to 36 distinct symbols")
	ErrLength   = errors.New("fpe: input length out of range for this radix")
	ErrSymbol   = errors.New("fpe: input contains a symbol outside the alphabet")
)

// FF1 is an FF1 cipher bound to a key and an alphabet. It is safe for
// concurrent use.
type FF1 struct {
	block    cipher.Block
	alphabet string
	radix    int
	index    [256]int
	minLen   int
}

// maxLen bounds input length (SP 800-38G allows up to 2^32; this keeps
// big-number work small and is ample for card numbers and identifiers).
const maxLen = 256

// NewFF1 returns an FF1 cipher for an AES key (16, 24 or 32 bytes) and an
// alphabet whose length is the radix.
func NewFF1(key []byte, alphabet string) (*FF1, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(alphabet) < 2 || len(alphabet) > 36 {
		return nil, ErrAlphabet
	}
	f := &FF1{block: b, alphabet: alphabet, radix: len(alphabet)}
	for i := range f.index {
		f.index[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		if f.index[alphabet[i]] != -1 {
			return nil, ErrAlphabet
		}
		f.index[alphabet[i]] = i
	}
	// radix^minlen >= 1,000,000 (SP 800-38G Rev. 1 domain size floor).
	f.minLen = 2
	p := new(big.Int).Exp(big.NewInt(int64(f.radix)), big.NewInt(2), nil)
	for p.Cmp(big.NewInt(1_000_000)) < 0 {
		f.minLen++
		p.Mul(p, big.NewInt(int64(f.radix)))
	}
	return f, nil
}

// MinLen is the shortest input this radix accepts (domain of at least 10^6).
func (f *FF1) MinLen() int { return f.minLen }

func (f *FF1) num(s string) *big.Int {
	n := new(big.Int)
	r := big.NewInt(int64(f.radix))
	for i := 0; i < len(s); i++ {
		n.Mul(n, r)
		n.Add(n, big.NewInt(int64(f.index[s[i]])))
	}
	return n
}

func (f *FF1) str(n *big.Int, m int) string {
	out := make([]byte, m)
	r := big.NewInt(int64(f.radix))
	x := new(big.Int).Set(n)
	d := new(big.Int)
	for i := m - 1; i >= 0; i-- {
		x.DivMod(x, r, d)
		out[i] = f.alphabet[d.Int64()]
	}
	return string(out)
}

// prf is AES-CBC-MAC with a zero IV.
func (f *FF1) prf(data []byte) []byte {
	y := make([]byte, 16)
	for i := 0; i < len(data); i += 16 {
		for j := 0; j < 16; j++ {
			y[j] ^= data[i+j]
		}
		f.block.Encrypt(y, y)
	}
	return y
}

func (f *FF1) check(x string) error {
	if len(x) < f.minLen || len(x) > maxLen {
		return ErrLength
	}
	for i := 0; i < len(x); i++ {
		if f.index[x[i]] < 0 {
			return ErrSymbol
		}
	}
	return nil
}

// Encrypt encrypts x under the tweak.
func (f *FF1) Encrypt(x string, tweak []byte) (string, error) { return f.crypt(x, tweak, true) }

// Decrypt decrypts x under the tweak.
func (f *FF1) Decrypt(x string, tweak []byte) (string, error) { return f.crypt(x, tweak, false) }

func (f *FF1) crypt(x string, tweak []byte, enc bool) (string, error) {
	if err := f.check(x); err != nil {
		return "", err
	}
	n := len(x)
	t := len(tweak)
	u := n / 2
	v := n - u
	a, b := x[:u], x[u:]

	radix := big.NewInt(int64(f.radix))
	rv := new(big.Int).Exp(radix, big.NewInt(int64(v)), nil)
	bl := new(big.Int).Sub(rv, big.NewInt(1)).BitLen()
	bb := (bl + 7) / 8
	d := 4*((bb+3)/4) + 4

	p := []byte{1, 2, 1,
		byte(f.radix >> 16), byte(f.radix >> 8), byte(f.radix),
		10, byte(u),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		byte(t >> 24), byte(t >> 16), byte(t >> 8), byte(t)}

	pad := (16 - (t+bb+1)%16) % 16
	modU := new(big.Int).Exp(radix, big.NewInt(int64(u)), nil)
	modV := rv

	round := func(i int, half string) *big.Int {
		q := make([]byte, 0, t+pad+1+bb)
		q = append(q, tweak...)
		q = append(q, make([]byte, pad)...)
		q = append(q, byte(i))
		nb := f.num(half).Bytes()
		q = append(q, make([]byte, bb-len(nb))...)
		q = append(q, nb...)
		r := f.prf(append(append([]byte(nil), p...), q...))
		s := append([]byte(nil), r...)
		for j := 1; len(s) < d; j++ {
			blk := make([]byte, 16)
			copy(blk, r)
			var c [16]byte
			c[12], c[13], c[14], c[15] = byte(j>>24), byte(j>>16), byte(j>>8), byte(j)
			for k := range blk {
				blk[k] ^= c[k]
			}
			f.block.Encrypt(blk, blk)
			s = append(s, blk...)
		}
		return new(big.Int).SetBytes(s[:d])
	}

	if enc {
		for i := 0; i < 10; i++ {
			y := round(i, b)
			m, mod := u, modU
			if i%2 == 1 {
				m, mod = v, modV
			}
			c := new(big.Int).Add(f.num(a), y)
			c.Mod(c, mod)
			a, b = b, f.str(c, m)
		}
	} else {
		for i := 9; i >= 0; i-- {
			y := round(i, a)
			m, mod := u, modU
			if i%2 == 1 {
				m, mod = v, modV
			}
			c := new(big.Int).Sub(f.num(b), y)
			c.Mod(c, mod)
			b, a = a, f.str(c, m)
		}
	}
	return a + b, nil
}

// Contains reports whether every byte of s is in the alphabet.
func (f *FF1) Contains(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r > 255 || f.index[r] < 0 }) < 0
}
