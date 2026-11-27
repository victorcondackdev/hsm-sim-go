package keys

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/subtle"
)

// Padding selects an ISO/IEC 9797-1 padding method.
type Padding int

const (
	// Pad1 appends zero bytes up to a block boundary (nothing if already
	// aligned; empty data becomes one zero block).
	Pad1 Padding = 1
	// Pad2 appends 0x80 then zero bytes; it always adds at least one byte.
	// This is the EMV and ISO 9797-1 method 2 padding.
	Pad2 Padding = 2
)

// Pad pads data to a multiple of bs bytes using method p.
func Pad(data []byte, bs int, p Padding) []byte {
	out := append([]byte(nil), data...)
	switch p {
	case Pad2:
		out = append(out, 0x80)
		fallthrough
	default:
		for len(out)%bs != 0 || len(out) == 0 {
			out = append(out, 0)
		}
	}
	return out
}

// RetailMAC computes the ISO/IEC 9797-1 MAC algorithm 3 ("retail MAC", ANSI
// X9.19) with a double-length key K1‖K2: single-DES CBC under K1 over every
// block, then the final block decrypted under K2 and encrypted under K1. It
// returns the full 8-byte MAC; callers truncate (EMV uses all 8 bytes, ANSI
// X9.19 commonly 4).
func RetailMAC(key, data []byte, p Padding) ([]byte, error) {
	if len(key) != 16 {
		return nil, ErrKeyLength
	}
	k1, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	k2, err := des.NewCipher(key[8:])
	if err != nil {
		return nil, err
	}
	d := Pad(data, 8, p)
	h := make([]byte, 8)
	for i := 0; i < len(d); i += 8 {
		subtle.XORBytes(h, h, d[i:i+8])
		k1.Encrypt(h, h)
	}
	k2.Decrypt(h, h)
	k1.Encrypt(h, h)
	return h, nil
}

// CBCMAC computes ISO/IEC 9797-1 MAC algorithm 1: plain CBC-MAC under a
// DES/TDES key, returning the last 8-byte block.
func CBCMAC(key, data []byte, p Padding) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	d := Pad(data, 8, p)
	h := make([]byte, 8)
	for i := 0; i < len(d); i += 8 {
		subtle.XORBytes(h, h, d[i:i+8])
		b.Encrypt(h, h)
	}
	return h, nil
}

// CMAC computes AES-CMAC (NIST SP 800-38B, RFC 4493) and returns the full
// 16-byte tag.
func CMAC(key, data []byte) ([]byte, error) {
	b, err := Block(key, true)
	if err != nil {
		return nil, err
	}
	return cmac(b, data), nil
}

// TDESCMAC computes CMAC over a TDES key (8-byte tag), as used by TDES TR-31
// key blocks and some DUKPT variants.
func TDESCMAC(key, data []byte) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	return cmac(b, data), nil
}

func cmac(b cipher.Block, data []byte) []byte {
	bs := b.BlockSize()
	rb := byte(0x87)
	if bs == 8 {
		rb = 0x1b
	}
	l := make([]byte, bs)
	b.Encrypt(l, l)
	k1 := shiftLeft(l, rb)
	k2 := shiftLeft(k1, rb)

	n := (len(data) + bs - 1) / bs
	complete := n > 0 && len(data)%bs == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, bs)
	if complete {
		subtle.XORBytes(last, data[(n-1)*bs:], k1)
	} else {
		rest := data[(n-1)*bs:]
		copy(last, rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last, last, k2)
	}
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x, x, data[i*bs:(i+1)*bs])
		b.Encrypt(x, x)
	}
	subtle.XORBytes(x, x, last)
	b.Encrypt(x, x)
	return x
}

func shiftLeft(in []byte, rb byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if carry != 0 {
		out[len(out)-1] ^= rb
	}
	return out
}

// Equal compares two MACs or check values in constant time.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
