package hsm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/victorcondackdev/hsm-sim-go/keys"
)

// KeyType binds a key to its usage. A key wrapped as one type is refused
// by commands that expect another: a CVK cannot be used to translate PINs,
// and a PIN key cannot be used to compute CVVs. That single rule defeats most
// of the classic HSM API attacks.
type KeyType string

// Key types.
const (
	PINKey     KeyType = "P0" // TDES PIN encryption key (TPK, ZPK)
	PINKeyAES  KeyType = "P1" // AES PIN encryption key, ISO format 4
	PVK        KeyType = "V0" // PIN verification key (Visa PVV, IBM 3624)
	CVK        KeyType = "C0" // card verification key
	EMVMasterK KeyType = "E0" // EMV issuer master key for application cryptograms
	BDK        KeyType = "B0" // DUKPT base derivation key
	DataKey    KeyType = "D0" // general data encryption
)

func (t KeyType) aes() bool { return t == PINKeyAES }

func (t KeyType) valid() bool {
	switch t {
	case PINKey, PINKeyAES, PVK, CVK, EMVMasterK, BDK, DataKey:
		return true
	}
	return false
}

// length is 16 bytes for every type: double-length TDES or AES-128.
func (t KeyType) length() int { return 16 }

// keystore wraps keys under the local master key (LMK) with AES-GCM, using
// the key type as additional data. A key token is "S" + type + hex(nonce ‖
// ciphertext ‖ tag); the HSM never stores keys, callers keep tokens.
type keystore struct {
	lmk cipher.AEAD
	kcv string
}

var errToken = errors.New("hsm: invalid key token")

func newKeystore(lmk []byte) (*keystore, error) {
	if len(lmk) != 32 {
		return nil, errors.New("hsm: LMK must be 32 bytes (AES-256)")
	}
	b, err := aes.NewCipher(lmk)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	kcv, err := keys.KCVAES(lmk)
	if err != nil {
		return nil, err
	}
	return &keystore{lmk: g, kcv: kcv}, nil
}

func (k *keystore) wrap(t KeyType, clear []byte) (string, error) {
	nonce := make([]byte, k.lmk.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := k.lmk.Seal(nonce, nonce, clear, []byte(t))
	return "S" + string(t) + strings.ToUpper(hex.EncodeToString(sealed)), nil
}

// unwrap returns the clear key behind token, requiring one of the allowed
// types. It reports a usage mismatch separately from a corrupt token, as a
// real HSM does with distinct error codes.
func (k *keystore) unwrap(token string, allowed ...KeyType) ([]byte, KeyType, error) {
	if len(token) < 4 || token[0] != 'S' {
		return nil, "", errToken
	}
	t := KeyType(token[1:3])
	if !t.valid() {
		return nil, "", errToken
	}
	ok := len(allowed) == 0
	for _, a := range allowed {
		if a == t {
			ok = true
		}
	}
	if !ok {
		return nil, t, errUsage
	}
	raw, err := hex.DecodeString(token[3:])
	if err != nil || len(raw) < k.lmk.NonceSize() {
		return nil, "", errToken
	}
	clear, err := k.lmk.Open(nil, raw[:k.lmk.NonceSize()], raw[k.lmk.NonceSize():], []byte(t))
	if err != nil {
		return nil, "", errToken
	}
	return clear, t, nil
}

var errUsage = errors.New("hsm: key type not permitted for this command")

func checkValue(t KeyType, key []byte) (string, error) {
	if t.aes() {
		return keys.KCVAES(key)
	}
	return keys.KCV(key)
}

func generate(t KeyType) ([]byte, error) {
	if t.aes() {
		k := make([]byte, t.length())
		_, err := rand.Read(k)
		return k, err
	}
	return keys.Random(t.length())
}

func validateClear(t KeyType, key []byte) error {
	if len(key) != t.length() {
		return fmt.Errorf("hsm: %s key must be %d bytes", t, t.length())
	}
	if !t.aes() && !keys.HasOddParity(key) {
		return errParity
	}
	return nil
}

var errParity = errors.New("hsm: key parity error")
