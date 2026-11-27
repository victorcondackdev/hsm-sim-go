// Package dukpt implements TDES DUKPT (Derived Unique Key Per Transaction,
// ANSI X9.24-1:2009): IPEK derivation from a base derivation key, the
// non-reversible key generation process, the PIN, MAC and data key variants,
// and a terminal model that issues key serial numbers.
//
// The host side (Derive, PINKey, ...) is what an acquirer HSM runs to decrypt
// a PIN block from a PIN pad; the Terminal type is what the PIN pad runs to
// produce one.
package dukpt

import (
	"crypto/des"
	"errors"
	"fmt"
	"math/bits"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// KSN is a 10-byte key serial number: key set ID, device ID and a 21-bit
// transaction counter in the rightmost bits.
type KSN [10]byte

// Errors returned by this package.
var (
	ErrKSN       = errors.New("dukpt: KSN must be 10 bytes (20 hex digits)")
	ErrBDK       = errors.New("dukpt: BDK and IPEK must be 16 bytes")
	ErrExhausted = errors.New("dukpt: transaction counter exhausted")
)

const counterMask = 0x1FFFFF // 21 bits

// MaxCounter is the largest valid transaction counter.
const MaxCounter = counterMask

// ParseKSN parses 20 hex digits.
func ParseKSN(s string) (KSN, error) {
	var k KSN
	b, err := keys.Hex(s)
	if err != nil || len(b) != 10 {
		return k, ErrKSN
	}
	copy(k[:], b)
	return k, nil
}

func (k KSN) String() string { return keys.HexUpper(k[:]) }

// Counter returns the 21-bit transaction counter.
func (k KSN) Counter() uint32 {
	return (uint32(k[7])<<16 | uint32(k[8])<<8 | uint32(k[9])) & counterMask
}

// WithCounter returns k with its counter replaced.
func (k KSN) WithCounter(c uint32) KSN {
	c &= counterMask
	k[7] = k[7]&^0x1F | byte(c>>16)
	k[8] = byte(c >> 8)
	k[9] = byte(c)
	return k
}

var c0 = keys.MustHex("C0C0C0C000000000C0C0C0C000000000")

// IPEK derives the initial PIN encryption key loaded into a device from the
// BDK and the device's KSN (its counter is ignored).
func IPEK(bdk []byte, ksn KSN) ([]byte, error) {
	if len(bdk) != 16 {
		return nil, ErrBDK
	}
	base := ksn.WithCounter(0)
	reg := base[:8]
	left, err := keys.EncryptECB(bdk, reg)
	if err != nil {
		return nil, err
	}
	right, err := keys.EncryptECB(keys.XOR(bdk, c0), reg)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

// nrkgp is the non-reversible key generation process.
func nrkgp(key, reg []byte) []byte {
	half := func(k []byte) []byte {
		kl, kr := k[:8], k[8:]
		b, _ := des.NewCipher(kl)
		x := keys.XOR(reg, kr)
		b.Encrypt(x, x)
		return keys.XOR(x, kr)
	}
	right := half(key)
	left := half(keys.XOR(key, c0))
	return append(left, right...)
}

// FromIPEK derives the current transaction key for ksn from an IPEK.
func FromIPEK(ipek []byte, ksn KSN) ([]byte, error) {
	if len(ipek) != 16 {
		return nil, ErrBDK
	}
	key := append([]byte(nil), ipek...)
	// The 64-bit register is the rightmost 8 bytes of the KSN with the
	// counter cleared; counter bits are set one at a time, highest first.
	r := ksn.WithCounter(0)
	reg := append([]byte(nil), r[2:]...)
	counter := ksn.Counter()
	for bit := uint32(1 << 20); bit > 0; bit >>= 1 {
		if counter&bit == 0 {
			continue
		}
		reg[5] |= byte(bit >> 16)
		reg[6] |= byte(bit >> 8)
		reg[7] |= byte(bit)
		key = nrkgp(key, reg)
	}
	return key, nil
}

// Derive derives the current transaction key for ksn from the BDK.
func Derive(bdk []byte, ksn KSN) ([]byte, error) {
	ipek, err := IPEK(bdk, ksn)
	if err != nil {
		return nil, err
	}
	return FromIPEK(ipek, ksn)
}

// Key variants applied to the transaction key.
var (
	variantPIN  = keys.MustHex("00000000000000FF00000000000000FF")
	variantMAC  = keys.MustHex("000000000000FF00000000000000FF00")
	variantMACR = keys.MustHex("00000000FF00000000000000FF000000")
	variantData = keys.MustHex("0000000000FF00000000000000FF0000")
	variantDatR = keys.MustHex("000000FF00000000000000FF00000000")
)

// Usage selects a working key variant.
type Usage int

// Key usages.
const (
	PIN          Usage = iota // PIN encryption
	MACRequest                // MAC, request (terminal to host)
	MACResponse               // MAC, response (host to terminal)
	DataRequest               // data encryption, request
	DataResponse              // data encryption, response
)

func (u Usage) String() string {
	switch u {
	case PIN:
		return "pin"
	case MACRequest:
		return "mac-request"
	case MACResponse:
		return "mac-response"
	case DataRequest:
		return "data-request"
	case DataResponse:
		return "data-response"
	}
	return fmt.Sprintf("usage(%d)", int(u))
}

// WorkingKey applies the usage variant to a transaction key. Data keys get
// the extra one-way step of X9.24-1:2009 (the variant key encrypts its own
// halves), so a data key never equals a PIN or MAC key.
func WorkingKey(txKey []byte, u Usage) ([]byte, error) {
	if len(txKey) != 16 {
		return nil, ErrBDK
	}
	switch u {
	case PIN:
		return keys.XOR(txKey, variantPIN), nil
	case MACRequest:
		return keys.XOR(txKey, variantMAC), nil
	case MACResponse:
		return keys.XOR(txKey, variantMACR), nil
	case DataRequest, DataResponse:
		v := variantData
		if u == DataResponse {
			v = variantDatR
		}
		k := keys.XOR(txKey, v)
		l, err := keys.EncryptECB(k, k[:8])
		if err != nil {
			return nil, err
		}
		r, err := keys.EncryptECB(k, k[8:])
		if err != nil {
			return nil, err
		}
		return append(l, r...), nil
	}
	return nil, fmt.Errorf("dukpt: unknown usage %d", int(u))
}

// HostKey derives the working key for usage u from the BDK in one step.
func HostKey(bdk []byte, ksn KSN, u Usage) ([]byte, error) {
	tx, err := Derive(bdk, ksn)
	if err != nil {
		return nil, err
	}
	return WorkingKey(tx, u)
}

// validCounter reports whether c is a counter a compliant device can use:
// at most ten bits set (X9.24 caps the number of one bits so that the
// device never needs more than 21 future keys).
func validCounter(c uint32) bool { return c > 0 && c <= MaxCounter && bits.OnesCount32(c) <= 10 }

// NextCounter returns the next valid counter after c.
func NextCounter(c uint32) (uint32, error) {
	for n := c + 1; n <= MaxCounter; n++ {
		if validCounter(n) {
			return n, nil
		}
	}
	return 0, ErrExhausted
}

// Terminal models a DUKPT PIN pad. It is a simulator: it keeps the IPEK and
// derives each key from it, whereas a real device keeps only its future key
// registers and erases the IPEK after the first use. The keys it produces are
// identical.
type Terminal struct {
	ipek []byte
	ksn  KSN
}

// NewTerminal loads a terminal with its IPEK and initial KSN (counter 0).
func NewTerminal(ipek []byte, initial KSN) (*Terminal, error) {
	if len(ipek) != 16 {
		return nil, ErrBDK
	}
	return &Terminal{ipek: append([]byte(nil), ipek...), ksn: initial.WithCounter(0)}, nil
}

// KSN returns the KSN of the last transaction (counter 0 before the first).
func (t *Terminal) KSN() KSN { return t.ksn }

// Next advances to the next transaction and returns its KSN and working key.
func (t *Terminal) Next(u Usage) (KSN, []byte, error) {
	c, err := NextCounter(t.ksn.Counter())
	if err != nil {
		return KSN{}, nil, err
	}
	t.ksn = t.ksn.WithCounter(c)
	tx, err := FromIPEK(t.ipek, t.ksn)
	if err != nil {
		return KSN{}, nil, err
	}
	k, err := WorkingKey(tx, u)
	return t.ksn, k, err
}
