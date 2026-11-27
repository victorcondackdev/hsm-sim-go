// Package tokenize is a PCI DSS style PAN tokenization vault: it replaces a
// card number with a token of the same length that keeps the BIN and the
// last four digits (so routing, receipts and support still work) and fails
// the Luhn check (so a token can never be mistaken for, or charged as, a
// real card).
//
// Tokens are produced with FF1 over the middle digits; the vault stores the
// PAN encrypted with AES-GCM and indexes it by HMAC-SHA-256, so the store
// never holds a clear PAN and tokenizing the same PAN twice returns the same
// token.
package tokenize

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/victorcondackdev/hsm-sim-go/fpe"
)

// Errors returned by the vault.
var (
	ErrPAN      = errors.New("tokenize: PAN must be 13 to 19 digits with a valid Luhn check digit")
	ErrNotFound = errors.New("tokenize: unknown token")
	ErrToken    = errors.New("tokenize: malformed token")
)

// Luhn reports whether s (all digits) has a valid Luhn check digit.
func Luhn(s string) bool {
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return len(s) > 0 && sum%10 == 0
}

// Mask returns the PAN with everything but the first six and last four
// digits replaced by '*', the PCI DSS display rule.
func Mask(pan string) string {
	if len(pan) < 11 {
		return strings.Repeat("*", len(pan))
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

// Keys holds the three independent keys a vault needs.
type Keys struct {
	FPE  []byte // AES key for FF1 token generation
	Data []byte // AES key (16/24/32) encrypting PANs at rest
	MAC  []byte // HMAC-SHA-256 key for the PAN index
}

// RandomKeys returns fresh 256-bit keys.
func RandomKeys() (Keys, error) {
	var k Keys
	for _, p := range []*[]byte{&k.FPE, &k.Data, &k.MAC} {
		*p = make([]byte, 32)
		if _, err := rand.Read(*p); err != nil {
			return Keys{}, err
		}
	}
	return k, nil
}

type record struct {
	nonce, sealed []byte
}

// Vault is an in-memory token vault, safe for concurrent use. Swap the maps
// for a table with unique indexes on token and index to persist it.
type Vault struct {
	ff1  *fpe.FF1
	aead cipher.AEAD
	mac  []byte

	mu      sync.RWMutex
	byIndex map[string]string // HMAC(PAN) -> token
	byToken map[string]record
}

// New returns an empty vault.
func New(k Keys) (*Vault, error) {
	f, err := fpe.NewFF1(k.FPE, fpe.Digits)
	if err != nil {
		return nil, fmt.Errorf("tokenize: FPE key: %w", err)
	}
	b, err := aes.NewCipher(k.Data)
	if err != nil {
		return nil, fmt.Errorf("tokenize: data key: %w", err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(k.MAC) < 16 {
		return nil, errors.New("tokenize: MAC key must be at least 16 bytes")
	}
	return &Vault{ff1: f, aead: g, mac: append([]byte(nil), k.MAC...),
		byIndex: map[string]string{}, byToken: map[string]record{}}, nil
}

func (v *Vault) index(pan string) string {
	m := hmac.New(sha256.New, v.mac)
	m.Write([]byte(pan))
	return hex.EncodeToString(m.Sum(nil))
}

func validPAN(pan string) bool { return len(pan) >= 13 && len(pan) <= 19 && Luhn(pan) }

// Tokenize returns the token for pan, creating it on first use.
func (v *Vault) Tokenize(pan string) (string, error) {
	if !validPAN(pan) {
		return "", ErrPAN
	}
	idx := v.index(pan)
	v.mu.RLock()
	tok, ok := v.byIndex[idx]
	v.mu.RUnlock()
	if ok {
		return tok, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if tok, ok := v.byIndex[idx]; ok {
		return tok, nil
	}
	bin, mid, last := pan[:6], pan[6:len(pan)-4], pan[len(pan)-4:]
	// Retry with a new tweak when the candidate passes Luhn (about one in
	// ten) or collides with an existing token.
	for attempt := 0; attempt < 1000; attempt++ {
		tweak := []byte(fmt.Sprintf("%s%s/%d", bin, last, attempt))
		enc, err := v.encryptMiddle(mid, tweak)
		if err != nil {
			return "", err
		}
		cand := bin + enc + last
		if Luhn(cand) {
			continue
		}
		if _, taken := v.byToken[cand]; taken {
			continue
		}
		nonce := make([]byte, v.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		sealed := v.aead.Seal(nil, nonce, []byte(pan), []byte(cand))
		v.byToken[cand] = record{nonce: nonce, sealed: sealed}
		v.byIndex[idx] = cand
		return cand, nil
	}
	return "", errors.New("tokenize: token space exhausted for this BIN and suffix")
}

// encryptMiddle encrypts the middle digits. When there are fewer than FF1's
// minimum (short PANs), it pads with zeros, encrypts, and keeps the
// rightmost len(mid) digits: the vault, not FF1, is the source of truth for
// reversal, so the map only needs to be collision-checked, which Tokenize
// does.
func (v *Vault) encryptMiddle(mid string, tweak []byte) (string, error) {
	if len(mid) >= v.ff1.MinLen() {
		return v.ff1.Encrypt(mid, tweak)
	}
	padded := strings.Repeat("0", v.ff1.MinLen()-len(mid)) + mid
	enc, err := v.ff1.Encrypt(padded, tweak)
	if err != nil {
		return "", err
	}
	return enc[len(enc)-len(mid):], nil
}

// Detokenize returns the PAN behind a token.
func (v *Vault) Detokenize(token string) (string, error) {
	if len(token) < 13 || len(token) > 19 {
		return "", ErrToken
	}
	v.mu.RLock()
	r, ok := v.byToken[token]
	v.mu.RUnlock()
	if !ok {
		return "", ErrNotFound
	}
	pan, err := v.aead.Open(nil, r.nonce, r.sealed, []byte(token))
	if err != nil {
		return "", fmt.Errorf("tokenize: vault record failed authentication: %w", err)
	}
	return string(pan), nil
}

// Len returns the number of tokens in the vault.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.byToken)
}
