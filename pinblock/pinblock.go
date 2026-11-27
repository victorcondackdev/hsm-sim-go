// Package pinblock encodes, decodes, encrypts and decrypts ISO 9564-1 PIN
// blocks: formats 0 (ANSI X9.8), 1, 2 and 3, which are 8-byte blocks
// protected with TDES, and format 4, the 16-byte block protected with AES.
//
// A PIN block is the only shape in which a PIN ever leaves a PIN pad or an
// HSM. The format decides what else is mixed into it: formats 0, 3 and 4 bind
// the PIN to the card's PAN, so a block captured for one card is useless for
// another; formats 1 and 2 carry no PAN.
package pinblock

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// Format is an ISO 9564-1 PIN block format.
type Format int

// ISO 9564-1 formats.
const (
	Format0 Format = 0 // PIN ⊕ PAN, 'F' fill (ANSI X9.8, ECI-1)
	Format1 Format = 1 // PIN with random fill, no PAN
	Format2 Format = 2 // PIN with 'F' fill, no PAN (offline ICC PIN only)
	Format3 Format = 3 // PIN ⊕ PAN, random fill in A–F
	Format4 Format = 4 // AES, 16 bytes, two-pass encryption bound to the PAN
)

func (f Format) String() string { return fmt.Sprintf("ISO-%d", int(f)) }

// BlockSize returns 16 for format 4 and 8 otherwise.
func (f Format) BlockSize() int {
	if f == Format4 {
		return 16
	}
	return 8
}

// Errors returned by this package. Decoding errors deliberately do not say
// which nibble was wrong: an HSM that explains why a PIN block is malformed
// is an oracle.
var (
	ErrFormat    = errors.New("pinblock: unsupported format")
	ErrPIN       = errors.New("pinblock: PIN must be 4 to 12 decimal digits")
	ErrPAN       = errors.New("pinblock: PAN must be decimal digits")
	ErrMalformed = errors.New("pinblock: malformed PIN block")
)

func validPIN(pin string) bool {
	if len(pin) < 4 || len(pin) > 12 {
		return false
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			return false
		}
	}
	return true
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// panField returns the 8-byte PAN field of formats 0 and 3: four zero
// nibbles then the rightmost 12 PAN digits excluding the check digit.
func panField(pan string) ([]byte, error) {
	if !digits(pan) || len(pan) < 2 {
		return nil, ErrPAN
	}
	body := pan[:len(pan)-1]
	if len(body) > 12 {
		body = body[len(body)-12:]
	}
	n := make([]byte, 16)
	for i := range n {
		n[i] = 0
	}
	off := 16 - len(body)
	for i := 0; i < len(body); i++ {
		n[off+i] = body[i] - '0'
	}
	return packNibbles(n), nil
}

// panField4 returns the 16-byte PAN field of format 4: nibble M = len−12,
// the PAN (left-padded with zeros to 12 digits when shorter), zero fill.
func panField4(pan string) ([]byte, error) {
	if !digits(pan) || len(pan) > 19 {
		return nil, ErrPAN
	}
	m := 0
	if len(pan) < 12 {
		pan = fmt.Sprintf("%012s", pan)
	} else {
		m = len(pan) - 12
	}
	n := make([]byte, 32)
	n[0] = byte(m)
	for i := 0; i < len(pan); i++ {
		n[1+i] = pan[i] - '0'
	}
	return packNibbles(n), nil
}

func packNibbles(n []byte) []byte {
	out := make([]byte, len(n)/2)
	for i := range out {
		out[i] = n[2*i]<<4 | n[2*i+1]
	}
	return out
}

func unpackNibbles(b []byte) []byte {
	out := make([]byte, 2*len(b))
	for i, v := range b {
		out[2*i] = v >> 4
		out[2*i+1] = v & 0x0F
	}
	return out
}

func randomNibbles(r io.Reader, n int, lo byte) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	span := 16 - lo
	for i, b := range buf {
		out[i] = lo + b%span
	}
	return out, nil
}

// pinField builds the 16-nibble plain PIN field: control nibble, length,
// PIN digits and fill.
func pinField(f Format, pin string, r io.Reader) ([]byte, error) {
	n := make([]byte, 16)
	n[0] = byte(f)
	n[1] = byte(len(pin))
	for i := 0; i < len(pin); i++ {
		n[2+i] = pin[i] - '0'
	}
	fill := 14 - len(pin)
	var rest []byte
	var err error
	switch f {
	case Format0, Format2:
		rest = make([]byte, fill)
		for i := range rest {
			rest[i] = 0xF
		}
	case Format1:
		rest, err = randomNibbles(r, fill, 0)
	case Format3:
		rest, err = randomNibbles(r, fill, 0xA)
	case Format4:
		rest = make([]byte, fill)
		for i := range rest {
			rest[i] = 0xA
		}
	}
	if err != nil {
		return nil, err
	}
	copy(n[2+len(pin):], rest)
	return packNibbles(n), nil
}

// Encode returns the clear PIN block for pin and pan. For format 4 this is
// the 16-byte plain-text PIN field (the PAN only enters during encryption,
// see Encrypt). rnd supplies fill for formats 1, 3 and 4; nil means
// crypto/rand. pan is ignored for formats 1 and 2.
func Encode(f Format, pin, pan string, rnd io.Reader) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	if !validPIN(pin) {
		return nil, ErrPIN
	}
	switch f {
	case Format0, Format3:
		pf, err := pinField(f, pin, rnd)
		if err != nil {
			return nil, err
		}
		af, err := panField(pan)
		if err != nil {
			return nil, err
		}
		return keys.XOR(pf, af), nil
	case Format1, Format2:
		return pinField(f, pin, rnd)
	case Format4:
		pf, err := pinField(f, pin, rnd)
		if err != nil {
			return nil, err
		}
		tail := make([]byte, 8)
		if _, err := io.ReadFull(rnd, tail); err != nil {
			return nil, err
		}
		return append(pf, tail...), nil
	}
	return nil, ErrFormat
}

// Decode extracts the PIN from a clear PIN block, validating control nibble,
// length, digits and fill.
func Decode(f Format, block []byte, pan string) (string, error) {
	if len(block) != f.BlockSize() {
		return "", ErrMalformed
	}
	pf := block
	switch f {
	case Format0, Format3:
		af, err := panField(pan)
		if err != nil {
			return "", err
		}
		pf = keys.XOR(block, af)
	case Format1, Format2:
	case Format4:
		pf = block[:8]
	default:
		return "", ErrFormat
	}
	n := unpackNibbles(pf)
	if n[0] != byte(f) {
		return "", ErrMalformed
	}
	l := int(n[1])
	if l < 4 || l > 12 {
		return "", ErrMalformed
	}
	pin := make([]byte, l)
	for i := 0; i < l; i++ {
		if n[2+i] > 9 {
			return "", ErrMalformed
		}
		pin[i] = '0' + n[2+i]
	}
	for _, v := range n[2+l:] {
		ok := true
		switch f {
		case Format0, Format2:
			ok = v == 0xF
		case Format3:
			ok = v >= 0xA
		case Format4:
			ok = v == 0xA
		}
		if !ok {
			return "", ErrMalformed
		}
	}
	return string(pin), nil
}

// Encrypt encodes pin into a PIN block and encrypts it: TDES ECB for formats
// 0–3 (key 8/16/24 bytes), and for format 4 the ISO 9564-1 two-pass AES
// scheme E(K, E(K, PIN field) ⊕ PAN field).
func Encrypt(f Format, key []byte, pin, pan string, rnd io.Reader) ([]byte, error) {
	clear, err := Encode(f, pin, pan, rnd)
	if err != nil {
		return nil, err
	}
	return EncryptClear(f, key, clear, pan)
}

// EncryptClear encrypts an already encoded clear block.
func EncryptClear(f Format, key, clear []byte, pan string) ([]byte, error) {
	if f != Format4 {
		return keys.EncryptECB(key, clear)
	}
	af, err := panField4(pan)
	if err != nil {
		return nil, err
	}
	i, err := keys.EncryptAESECB(key, clear)
	if err != nil {
		return nil, err
	}
	return keys.EncryptAESECB(key, keys.XOR(i, af))
}

// DecryptClear decrypts an encrypted PIN block to its clear block.
func DecryptClear(f Format, key, block []byte, pan string) ([]byte, error) {
	if len(block) != f.BlockSize() {
		return nil, ErrMalformed
	}
	if f != Format4 {
		return keys.DecryptECB(key, block)
	}
	af, err := panField4(pan)
	if err != nil {
		return nil, err
	}
	i, err := keys.DecryptAESECB(key, block)
	if err != nil {
		return nil, err
	}
	return keys.DecryptAESECB(key, keys.XOR(i, af))
}

// Decrypt decrypts and decodes an encrypted PIN block.
func Decrypt(f Format, key, block []byte, pan string) (string, error) {
	clear, err := DecryptClear(f, key, block, pan)
	if err != nil {
		return "", err
	}
	return Decode(f, clear, pan)
}
