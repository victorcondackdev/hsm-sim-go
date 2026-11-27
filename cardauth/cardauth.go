// Package cardauth implements the classic card verification algorithms an
// issuer HSM runs: Visa CVV/CVC (and CVV2, iCVV by service code), Visa PVV
// and IBM 3624 PIN offsets.
//
// All functions take double-length (16 byte) TDES keys. The "key pair" of
// the Visa manuals (CVK A, CVK B / PVK A, PVK B) is simply the left and right
// halves of that key.
package cardauth

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// Errors returned by this package.
var (
	ErrInput = errors.New("cardauth: invalid input")
	ErrKey   = errors.New("cardauth: key must be 16 bytes")
)

// Service codes used to derive the different card verification values from
// the same algorithm.
const (
	ServiceCVV2 = "000" // printed on the card, card-not-present
	ServiceICVV = "999" // Visa iCVV in chip track 2 equivalent data
)

func isDigits(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// decimalize extracts decimal digits from hex text: first the digits 0–9 in
// order, then A–F mapped to 0–5, as the Visa algorithms specify.
func decimalize(hexText string) string {
	var digits, letters strings.Builder
	for i := 0; i < len(hexText); i++ {
		c := hexText[i]
		if c <= '9' {
			digits.WriteByte(c)
		} else {
			letters.WriteByte('0' + c - 'A')
		}
	}
	return digits.String() + letters.String()
}

// CVV computes a Visa CVV / Mastercard CVC1 (three digits) for a PAN, an
// expiry date in YYMM and a three-digit service code. Use ServiceCVV2 for
// CVV2/CVC2 and ServiceICVV for iCVV.
func CVV(key []byte, pan, expiry, service string) (string, error) {
	if len(key) != 16 {
		return "", ErrKey
	}
	if !isDigits(pan, 12, 19) || !isDigits(expiry, 4, 4) || !isDigits(service, 3, 3) {
		return "", ErrInput
	}
	data := pan + expiry + service
	data += strings.Repeat("0", 32-len(data))
	b1 := keys.MustHex(data[:16])
	b2 := keys.MustHex(data[16:])
	r, err := keys.EncryptECB(key[:8], b1)
	if err != nil {
		return "", err
	}
	r, err = keys.EncryptECB(key, keys.XOR(r, b2))
	if err != nil {
		return "", err
	}
	return decimalize(keys.HexUpper(r))[:3], nil
}

// VerifyCVV recomputes a CVV and compares it in constant time.
func VerifyCVV(key []byte, pan, expiry, service, cvv string) (bool, error) {
	want, err := CVV(key, pan, expiry, service)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(cvv)) == 1, nil
}

// PVV computes the four-digit Visa PIN verification value. pvki is the PIN
// verification key index (one digit, 0–6 in practice) that selects which PVK
// pair the issuer used.
func PVV(key []byte, pan string, pvki int, pin string) (string, error) {
	if len(key) != 16 {
		return "", ErrKey
	}
	if !isDigits(pan, 12, 19) || pvki < 0 || pvki > 9 || !isDigits(pin, 4, 12) {
		return "", ErrInput
	}
	body := pan[:len(pan)-1]
	tsp := body[len(body)-11:] + string(rune('0'+pvki)) + pin[:4]
	r, err := keys.EncryptECB(key, keys.MustHex(tsp))
	if err != nil {
		return "", err
	}
	return decimalize(keys.HexUpper(r))[:4], nil
}

// VerifyPVV checks a PIN against a stored PVV.
func VerifyPVV(key []byte, pan string, pvki int, pin, pvv string) (bool, error) {
	want, err := PVV(key, pan, pvki, pin)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pvv)) == 1, nil
}

// DefaultDecimalization is the decimalization table most IBM 3624 issuers
// use: 0–9 map to themselves, A–F to 0–5.
const DefaultDecimalization = "0123456789012345"

// IBM3624 carries the parameters of an IBM 3624 PIN verification scheme.
type IBM3624 struct {
	Key            []byte // PIN verification key, 16 bytes
	Decimalization string // 16 digits; empty means DefaultDecimalization
	// ValidationData builds the 16 hex digits encrypted under Key from the
	// PAN. Nil means the common choice: the rightmost 12 PAN digits excluding
	// the check digit, left-padded with 'F' (pad character) to 16 nibbles.
	ValidationData func(pan string) string
}

func (s IBM3624) validation(pan string) (string, error) {
	if s.ValidationData != nil {
		v := s.ValidationData(pan)
		if _, err := keys.Hex(v); err != nil || len(v) != 16 {
			return "", ErrInput
		}
		return strings.ToUpper(v), nil
	}
	if !isDigits(pan, 13, 19) {
		return "", ErrInput
	}
	body := pan[:len(pan)-1]
	body = body[len(body)-12:]
	return "FFFF" + body, nil
}

// natural returns the natural PIN of the given length for pan.
func (s IBM3624) natural(pan string, length int) (string, error) {
	if len(s.Key) != 16 {
		return "", ErrKey
	}
	table := s.Decimalization
	if table == "" {
		table = DefaultDecimalization
	}
	if !isDigits(table, 16, 16) || length < 4 || length > 12 {
		return "", ErrInput
	}
	v, err := s.validation(pan)
	if err != nil {
		return "", err
	}
	r, err := keys.EncryptECB(s.Key, keys.MustHex(v))
	if err != nil {
		return "", err
	}
	h := keys.HexUpper(r)
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		c := h[i]
		var n int
		if c <= '9' {
			n = int(c - '0')
		} else {
			n = int(c-'A') + 10
		}
		out[i] = table[n]
	}
	return string(out), nil
}

// NaturalPIN returns the PIN the issuer would assign with offset 0.
func (s IBM3624) NaturalPIN(pan string, length int) (string, error) { return s.natural(pan, length) }

// Offset returns the offset to store so that a customer-selected pin
// verifies: offset = pin − natural PIN, digit by digit modulo 10.
func (s IBM3624) Offset(pan, pin string) (string, error) {
	if !isDigits(pin, 4, 12) {
		return "", ErrInput
	}
	nat, err := s.natural(pan, len(pin))
	if err != nil {
		return "", err
	}
	out := make([]byte, len(pin))
	for i := range out {
		out[i] = '0' + byte((int(pin[i]-'0')-int(nat[i]-'0')+10)%10)
	}
	return string(out), nil
}

// Verify checks pin against a stored offset.
func (s IBM3624) Verify(pan, pin, offset string) (bool, error) {
	if len(offset) != len(pin) {
		return false, nil
	}
	got, err := s.Offset(pan, pin)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(offset)) == 1, nil
}
