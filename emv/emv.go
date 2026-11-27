// Package emv implements the issuer side of EMV chip authentication:
// ICC master key derivation (Option A), the EMV common session key
// derivation, ARQC generation and verification and both ARPC methods.
//
// The flow it models: the card computes an ARQC over transaction data with a
// key derived from its own master key (which the issuer derives from the
// issuer master key, PAN and PAN sequence number); the issuer HSM rederives
// the same key, verifies the ARQC and answers with an ARPC the card checks.
package emv

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// Errors returned by this package.
var (
	ErrInput = errors.New("emv: invalid input")
	ErrKey   = errors.New("emv: key must be 16 bytes")
)

// DeriveICCKey derives the ICC master key (MK-AC, "UDK") from an issuer
// master key with EMV Book 2 Annex A1.4.1 Option A: Y is the rightmost 16
// digits of PAN‖PSN (left-padded with zeros), ZL = TDES(IMK, Y),
// ZR = TDES(IMK, Y ⊕ FF…FF), result ZL‖ZR with odd parity.
// psn is the two-digit PAN sequence number (tag 5F34); "" means "00".
func DeriveICCKey(imk []byte, pan, psn string) ([]byte, error) {
	if len(imk) != 16 {
		return nil, ErrKey
	}
	if psn == "" {
		psn = "00"
	}
	s := pan + psn
	if !allDigits(s) || len(pan) < 12 || len(psn) != 2 {
		return nil, ErrInput
	}
	if len(s) > 16 {
		s = s[len(s)-16:]
	} else {
		s = strings.Repeat("0", 16-len(s)) + s
	}
	y := keys.MustHex(s)
	zl, err := keys.EncryptECB(imk, y)
	if err != nil {
		return nil, err
	}
	inv := make([]byte, 8)
	for i := range inv {
		inv[i] = ^y[i]
	}
	zr, err := keys.EncryptECB(imk, inv)
	if err != nil {
		return nil, err
	}
	return keys.FixParity(append(zl, zr...)), nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// SessionKey derives the EMV common session key (EMV Book 2 Annex A1.3)
// for an application transaction counter:
// SK = TDES(MK, ATC‖F0‖00…) ‖ TDES(MK, ATC‖0F‖00…).
func SessionKey(mk []byte, atc uint16) ([]byte, error) {
	if len(mk) != 16 {
		return nil, ErrKey
	}
	l := make([]byte, 8)
	r := make([]byte, 8)
	binary.BigEndian.PutUint16(l, atc)
	binary.BigEndian.PutUint16(r, atc)
	l[2], r[2] = 0xF0, 0x0F
	a, err := keys.EncryptECB(mk, l)
	if err != nil {
		return nil, err
	}
	b, err := keys.EncryptECB(mk, r)
	if err != nil {
		return nil, err
	}
	return keys.FixParity(append(a, b...)), nil
}

// Scheme selects how the application cryptogram is computed.
type Scheme int

const (
	// CVN18 is the EMV CSK scheme (Visa CVN 18/22, Mastercard M/Chip with
	// EMV CSK): session key per ATC, ISO 9797-1 padding method 2.
	CVN18 Scheme = iota
	// CVN10 is Visa CVN 10: the ICC master key is used directly (no session
	// key) and the data is zero-padded (method 1).
	CVN10
)

func (s Scheme) String() string {
	switch s {
	case CVN18:
		return "cvn18"
	case CVN10:
		return "cvn10"
	}
	return fmt.Sprintf("scheme(%d)", int(s))
}

// Transaction holds the data elements the card MACs, in the order of the
// EMV recommended minimum CDOL1 set.
type Transaction struct {
	Amount           uint64 // 9F02, minor units
	AmountOther      uint64 // 9F03
	TerminalCountry  uint16 // 9F1A, ISO 3166 numeric (Brazil 076)
	TVR              [5]byte
	Currency         uint16 // 5F2A, ISO 4217 numeric (BRL 986)
	Date             string // 9A, YYMMDD
	Type             byte   // 9C (00 purchase, 01 cash, 20 refund)
	UnpredictableNum [4]byte
	AIP              [2]byte // 82
	ATC              uint16  // 9F36
	// IAD carries issuer application data (9F10) bytes to include, such as
	// the card verification results. Schemes differ in which part of 9F10
	// is MACed; pass exactly the bytes your scheme covers.
	IAD []byte
}

// bcd encodes v as n bytes of packed BCD.
func bcd(v uint64, n int) []byte {
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		lo := v % 10
		v /= 10
		hi := v % 10
		v /= 10
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

// Data returns the byte string the cryptogram is computed over.
func (t Transaction) Data() ([]byte, error) {
	if len(t.Date) != 6 || !allDigits(t.Date) {
		return nil, fmt.Errorf("%w: date must be YYMMDD", ErrInput)
	}
	var d []byte
	d = append(d, bcd(t.Amount, 6)...)
	d = append(d, bcd(t.AmountOther, 6)...)
	d = append(d, bcd(uint64(t.TerminalCountry), 2)...)
	d = append(d, t.TVR[:]...)
	d = append(d, bcd(uint64(t.Currency), 2)...)
	d = append(d, keys.MustHex(t.Date)...)
	d = append(d, t.Type)
	d = append(d, t.UnpredictableNum[:]...)
	d = append(d, t.AIP[:]...)
	d = append(d, byte(t.ATC>>8), byte(t.ATC))
	d = append(d, t.IAD...)
	return d, nil
}

func acKey(mk []byte, atc uint16, s Scheme) ([]byte, keys.Padding, error) {
	switch s {
	case CVN18:
		sk, err := SessionKey(mk, atc)
		return sk, keys.Pad2, err
	case CVN10:
		if len(mk) != 16 {
			return nil, 0, ErrKey
		}
		return mk, keys.Pad1, nil
	}
	return nil, 0, fmt.Errorf("%w: unknown scheme", ErrInput)
}

// ARQC computes the authorization request cryptogram the card would send,
// given the ICC master key.
func ARQC(mk []byte, t Transaction, s Scheme) ([]byte, error) {
	d, err := t.Data()
	if err != nil {
		return nil, err
	}
	k, p, err := acKey(mk, t.ATC, s)
	if err != nil {
		return nil, err
	}
	return keys.RetailMAC(k, d, p)
}

// VerifyARQC recomputes the ARQC from the issuer master key and compares
// it in constant time.
func VerifyARQC(imk []byte, pan, psn string, t Transaction, s Scheme, arqc []byte) (bool, error) {
	mk, err := DeriveICCKey(imk, pan, psn)
	if err != nil {
		return false, err
	}
	want, err := ARQC(mk, t, s)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(want, arqc) == 1, nil
}

// ARPCMethod1 computes the ARPC of EMV Book 2 A1.2.1:
// TDES(key, ARQC ⊕ (ARC‖000000000000)), where arc is the 2-byte
// authorisation response code (e.g. "00" = 0x3030).
func ARPCMethod1(key, arqc []byte, arc [2]byte) ([]byte, error) {
	if len(arqc) != 8 {
		return nil, ErrInput
	}
	x := make([]byte, 8)
	x[0], x[1] = arc[0], arc[1]
	return keys.EncryptECB(key, keys.XOR(arqc, x))
}

// ARPCMethod2 computes the 4-byte ARPC of EMV Book 2 A1.2.2: MAC algorithm 3
// with padding method 2 over ARQC‖CSU‖proprietary data.
func ARPCMethod2(key, arqc []byte, csu [4]byte, propAuthData []byte) ([]byte, error) {
	if len(arqc) != 8 || len(propAuthData) > 8 {
		return nil, ErrInput
	}
	d := append(append(append([]byte(nil), arqc...), csu[:]...), propAuthData...)
	m, err := keys.RetailMAC(key, d, keys.Pad2)
	if err != nil {
		return nil, err
	}
	return m[:4], nil
}
