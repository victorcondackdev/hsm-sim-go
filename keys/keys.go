// Package keys holds the symmetric-key primitives every other package in
// hsm-sim-go is built on: single, double and triple length DES keys, AES
// keys, odd parity, key check values, component splitting and the block
// operations (ECB, CBC, ISO 9797-1 MACs and AES-CMAC) used by payment
// cryptography.
//
// Keys are plain byte slices. A TDES key is 8, 16 or 24 bytes (16 means the
// usual double-length K1‖K2‖K1); an AES key is 16, 24 or 32 bytes. Functions
// never retain or modify the slices they are given.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// Errors returned by this package.
var (
	ErrKeyLength   = errors.New("keys: invalid key length")
	ErrBlockLength = errors.New("keys: data is not a multiple of the block size")
	ErrHex         = errors.New("keys: invalid hex")
)

// Hex decodes s, ignoring spaces, and reports odd lengths and bad digits
// with ErrHex.
func Hex(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHex, err)
	}
	return b, nil
}

// MustHex is Hex for constants in tests and examples; it panics on error.
func MustHex(s string) []byte {
	b, err := Hex(s)
	if err != nil {
		panic(err)
	}
	return b
}

// HexUpper encodes b as upper-case hex, the convention of HSM consoles.
func HexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// tdes returns a block cipher for an 8, 16 or 24 byte DES key.
func tdes(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 8:
		return des.NewCipher(key)
	case 16:
		k := make([]byte, 24)
		copy(k, key)
		copy(k[16:], key[:8])
		return des.NewTripleDESCipher(k)
	case 24:
		return des.NewTripleDESCipher(key)
	}
	return nil, fmt.Errorf("%w: TDES key must be 8, 16 or 24 bytes, got %d", ErrKeyLength, len(key))
}

// Block returns a cipher.Block for key: TDES for 8/16/24 byte keys when aes is
// false, AES for 16/24/32 byte keys when aes is true.
func Block(key []byte, useAES bool) (cipher.Block, error) {
	if useAES {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyLength, err)
		}
		return b, nil
	}
	return tdes(key)
}

func ecb(b cipher.Block, data []byte, encrypt bool) ([]byte, error) {
	bs := b.BlockSize()
	if len(data)%bs != 0 {
		return nil, ErrBlockLength
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		if encrypt {
			b.Encrypt(out[i:i+bs], data[i:i+bs])
		} else {
			b.Decrypt(out[i:i+bs], data[i:i+bs])
		}
	}
	return out, nil
}

// EncryptECB encrypts data (a multiple of 8 bytes) with a DES/TDES key.
func EncryptECB(key, data []byte) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	return ecb(b, data, true)
}

// DecryptECB is the inverse of EncryptECB.
func DecryptECB(key, data []byte) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	return ecb(b, data, false)
}

// EncryptAESECB encrypts data (a multiple of 16 bytes) with an AES key.
func EncryptAESECB(key, data []byte) ([]byte, error) {
	b, err := Block(key, true)
	if err != nil {
		return nil, err
	}
	return ecb(b, data, true)
}

// DecryptAESECB is the inverse of EncryptAESECB.
func DecryptAESECB(key, data []byte) ([]byte, error) {
	b, err := Block(key, true)
	if err != nil {
		return nil, err
	}
	return ecb(b, data, false)
}

// EncryptCBC encrypts data with a DES/TDES key in CBC mode. A nil iv means
// eight zero bytes, the usual choice for key and PIN transport.
func EncryptCBC(key, iv, data []byte) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	return cbc(b, iv, data, true)
}

// DecryptCBC is the inverse of EncryptCBC.
func DecryptCBC(key, iv, data []byte) ([]byte, error) {
	b, err := tdes(key)
	if err != nil {
		return nil, err
	}
	return cbc(b, iv, data, false)
}

func cbc(b cipher.Block, iv, data []byte, encrypt bool) ([]byte, error) {
	bs := b.BlockSize()
	if len(data)%bs != 0 {
		return nil, ErrBlockLength
	}
	if iv == nil {
		iv = make([]byte, bs)
	}
	if len(iv) != bs {
		return nil, fmt.Errorf("keys: iv must be %d bytes", bs)
	}
	out := make([]byte, len(data))
	if encrypt {
		cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, data)
	} else {
		cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, data)
	}
	return out, nil
}

// XOR returns a ⊕ b. It panics if the lengths differ: every caller in this
// module XORs fixed-size blocks and a mismatch is a programming error.
func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("keys: XOR of unequal lengths")
	}
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out
}

// FixParity returns a copy of key with every byte set to odd parity, as DES
// keys require (the least significant bit of each byte is the parity bit).
func FixParity(key []byte) []byte {
	out := make([]byte, len(key))
	for i, b := range key {
		b &^= 1
		if bits.OnesCount8(b)%2 == 0 {
			b |= 1
		}
		out[i] = b
	}
	return out
}

// HasOddParity reports whether every byte of key has odd parity.
func HasOddParity(key []byte) bool {
	for _, b := range key {
		if bits.OnesCount8(b)%2 == 0 {
			return false
		}
	}
	return true
}

// KCV returns the key check value of a DES/TDES key: the first three bytes
// of the key encrypting a block of zeros, as six upper-case hex digits.
func KCV(key []byte) (string, error) {
	c, err := EncryptECB(key, make([]byte, 8))
	if err != nil {
		return "", err
	}
	return HexUpper(c[:3]), nil
}

// KCVAES returns the key check value of an AES key as defined by ANSI
// X9.24-1:2017 and TR-31: the first five bytes of AES-CMAC over a block of
// zeros, as ten upper-case hex digits. (Some vendors print only six digits;
// they are a prefix of this value.)
func KCVAES(key []byte) (string, error) {
	m, err := CMAC(key, make([]byte, 16))
	if err != nil {
		return "", err
	}
	return HexUpper(m[:5]), nil
}

// Combine XORs key components into a key, the way key custodians load a
// zone master key from two or three paper components. The result has its
// parity fixed. All components must have the same length.
func Combine(components ...[]byte) ([]byte, error) {
	if len(components) < 2 {
		return nil, errors.New("keys: at least two components are required")
	}
	out := make([]byte, len(components[0]))
	copy(out, components[0])
	for _, c := range components[1:] {
		if len(c) != len(out) {
			return nil, ErrKeyLength
		}
		subtle.XORBytes(out, out, c)
	}
	return FixParity(out), nil
}

// Split splits key into n >= 2 random components, each with odd parity, such
// that Combine(components...) == key. Because every component is forced to
// odd parity, their raw XOR may differ from key in parity bits only; Combine
// fixes parity, so the round trip is exact for any key with odd parity.
func Split(key []byte, n int) ([][]byte, error) {
	if n < 2 {
		return nil, errors.New("keys: n must be >= 2")
	}
	if !HasOddParity(key) {
		return nil, errors.New("keys: key must have odd parity")
	}
	comps := make([][]byte, n)
	acc := make([]byte, len(key))
	copy(acc, key)
	for i := 0; i < n-1; i++ {
		c := make([]byte, len(key))
		if _, err := rand.Read(c); err != nil {
			return nil, err
		}
		c = FixParity(c)
		comps[i] = c
		subtle.XORBytes(acc, acc, c)
	}
	comps[n-1] = FixParity(acc)
	return comps, nil
}

// Random returns a random DES/TDES key of the given length (8, 16 or 24) with
// odd parity.
func Random(length int) ([]byte, error) {
	if length != 8 && length != 16 && length != 24 {
		return nil, ErrKeyLength
	}
	k := make([]byte, length)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return FixParity(k), nil
}
