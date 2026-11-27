// Package hsm is a payment HSM simulator: a command processor with a
// payShield-inspired host command set (two-letter commands, responses whose
// second letter is incremented, two-digit error codes), keys wrapped under a
// local master key and bound to a usage, and fault injection for testing
// how an authorization system behaves when its HSM is slow or failing.
//
// It is a simulator for development and CI, not a security device: keys
// live in process memory and the LMK is an ordinary byte slice. The command
// syntax is inspired by, not compatible with, any vendor's.
package hsm

import (
	"context"
	"errors"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/victorcondackdev/hsm-sim-go/cardauth"
	"github.com/victorcondackdev/hsm-sim-go/dukpt"
	"github.com/victorcondackdev/hsm-sim-go/emv"
	"github.com/victorcondackdev/hsm-sim-go/keys"
	"github.com/victorcondackdev/hsm-sim-go/pinblock"
	"github.com/victorcondackdev/hsm-sim-go/tokenize"
)

// Error codes returned in Response.Error.
const (
	OK                = "00"
	VerifyFailed      = "01" // PIN, CVV or cryptogram did not verify
	InvalidKeyType    = "04"
	ParityError       = "10"
	InvalidInput      = "15"
	PINBlockError     = "20" // decrypted block is malformed
	InvalidPINFormat  = "23"
	KeyUsageViolation = "27"
	InvalidToken      = "33" // key token corrupt or wrapped under another LMK
	DUKPTError        = "42"
	CommandDisabled   = "68"
	UnknownCommand    = "90"
	InternalError     = "99"
)

// Request is one host command.
type Request struct {
	Header  string   // echoed back, used by clients to match responses
	Command string   // two characters, e.g. "CA"
	Fields  []string // positional fields
}

// Response is the HSM's answer. Code is the command with its second
// character incremented ("CA" → "CB").
type Response struct {
	Header string
	Code   string
	Error  string
	Fields []string
}

// OK reports whether Error is "00".
func (r Response) OK() bool { return r.Error == OK }

// Faults configures failure injection. All fields are optional.
type Faults struct {
	// Latency is added before every command (plus up to Jitter more).
	Latency, Jitter time.Duration
	// ErrorRate is the probability (0–1) that a command fails with
	// InternalError instead of running.
	ErrorRate float64
	// Seed makes injected faults reproducible; 0 means time-based.
	Seed int64
}

// Options configures an HSM.
type Options struct {
	LMK    []byte // 32 bytes; required
	Vault  *tokenize.Vault
	Faults Faults
	// Disabled lists commands that answer CommandDisabled, the way a
	// production HSM has most of its command set switched off.
	Disabled []string
}

// HSM executes host commands. It is safe for concurrent use.
type HSM struct {
	ks    *keystore
	vault *tokenize.Vault

	mu       sync.Mutex
	rnd      *rand.Rand
	faults   Faults
	disabled map[string]bool
	stats    map[string]int
}

// New returns an HSM.
func New(o Options) (*HSM, error) {
	ks, err := newKeystore(o.LMK)
	if err != nil {
		return nil, err
	}
	seed := o.Faults.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	h := &HSM{ks: ks, vault: o.Vault, rnd: rand.New(rand.NewSource(seed)),
		faults: o.Faults, disabled: map[string]bool{}, stats: map[string]int{}}
	for _, c := range o.Disabled {
		h.disabled[c] = true
	}
	return h, nil
}

// SetFaults replaces the fault configuration at run time (chaos testing).
func (h *HSM) SetFaults(f Faults) {
	h.mu.Lock()
	h.faults = f
	h.mu.Unlock()
}

// Stats returns how many times each command ran, sorted by command.
func (h *HSM) Stats() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.stats))
	for c, n := range h.stats {
		out = append(out, c+"="+strconv.Itoa(n))
	}
	sort.Strings(out)
	return out
}

// ResponseCode returns the response code for a command.
func ResponseCode(cmd string) string {
	if len(cmd) != 2 {
		return "ZZ"
	}
	b := []byte(cmd)
	b[1]++
	return string(b)
}

type handler func(h *HSM, f []string) ([]string, string)

var commands map[string]handler

func init() {
	commands = map[string]handler{
		"A0": (*HSM).generateKey,
		"A6": (*HSM).importKey,
		"BU": (*HSM).keyCheckValue,
		"CA": (*HSM).translatePIN,
		"G0": (*HSM).translateDUKPT,
		"DC": (*HSM).verifyPVV,
		"DA": (*HSM).verifyIBM,
		"DG": (*HSM).generatePVV,
		"CW": (*HSM).generateCVV,
		"CY": (*HSM).verifyCVV,
		"KQ": (*HSM).verifyARQC,
		"T0": (*HSM).tokenizePAN,
		"T2": (*HSM).detokenize,
		"NC": (*HSM).diagnostics,
	}
}

// Commands lists the supported command codes.
func Commands() []string {
	out := make([]string, 0, len(commands))
	for c := range commands {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Execute runs one command. ctx bounds injected latency.
func (h *HSM) Execute(ctx context.Context, r Request) Response {
	resp := Response{Header: r.Header, Code: ResponseCode(r.Command)}
	h.mu.Lock()
	h.stats[r.Command]++
	f := h.faults
	delay := f.Latency
	if f.Jitter > 0 {
		delay += time.Duration(h.rnd.Int63n(int64(f.Jitter)))
	}
	fail := f.ErrorRate > 0 && h.rnd.Float64() < f.ErrorRate
	disabled := h.disabled[r.Command]
	h.mu.Unlock()

	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			resp.Error = InternalError
			return resp
		}
	}
	if fail {
		resp.Error = InternalError
		return resp
	}
	if disabled {
		resp.Error = CommandDisabled
		return resp
	}
	fn, ok := commands[r.Command]
	if !ok {
		resp.Error = UnknownCommand
		return resp
	}
	resp.Fields, resp.Error = fn(h, r.Fields)
	if resp.Error != OK {
		resp.Fields = nil
	}
	return resp
}

func need(f []string, n int) bool { return len(f) == n }

func keyErr(err error) string {
	switch {
	case errors.Is(err, errUsage):
		return KeyUsageViolation
	case errors.Is(err, errToken):
		return InvalidToken
	case errors.Is(err, errParity):
		return ParityError
	}
	return InvalidInput
}

// A0 generate key: [type] → [token, kcv]
func (h *HSM) generateKey(f []string) ([]string, string) {
	if !need(f, 1) {
		return nil, InvalidInput
	}
	t := KeyType(f[0])
	if !t.valid() {
		return nil, InvalidKeyType
	}
	k, err := generate(t)
	if err != nil {
		return nil, InternalError
	}
	return h.wrapOut(t, k)
}

func (h *HSM) wrapOut(t KeyType, k []byte) ([]string, string) {
	tok, err := h.ks.wrap(t, k)
	if err != nil {
		return nil, InternalError
	}
	kcv, err := checkValue(t, k)
	if err != nil {
		return nil, InternalError
	}
	return []string{tok, kcv}, OK
}

// A6 import key from clear components: [type, component, component...] →
// [token, kcv]. One component imports a clear key (test environments only).
func (h *HSM) importKey(f []string) ([]string, string) {
	if len(f) < 2 {
		return nil, InvalidInput
	}
	t := KeyType(f[0])
	if !t.valid() {
		return nil, InvalidKeyType
	}
	var comps [][]byte
	for _, c := range f[1:] {
		b, err := keys.Hex(c)
		if err != nil {
			return nil, InvalidInput
		}
		comps = append(comps, b)
	}
	k := comps[0]
	if len(comps) > 1 {
		var err error
		if t.aes() {
			k = make([]byte, len(comps[0]))
			for _, c := range comps {
				if len(c) != len(k) {
					return nil, InvalidInput
				}
				k = keys.XOR(k, c)
			}
		} else if k, err = keys.Combine(comps...); err != nil {
			return nil, InvalidInput
		}
	}
	if err := validateClear(t, k); err != nil {
		return nil, keyErr(err)
	}
	return h.wrapOut(t, k)
}

// BU key check value: [token] → [type, kcv]
func (h *HSM) keyCheckValue(f []string) ([]string, string) {
	if !need(f, 1) {
		return nil, InvalidInput
	}
	k, t, err := h.ks.unwrap(f[0])
	if err != nil {
		return nil, keyErr(err)
	}
	kcv, _ := checkValue(t, k)
	return []string{string(t), kcv}, OK
}

func parseFormat(s string) (pinblock.Format, bool) {
	if len(s) != 2 || s[0] != '0' || s[1] < '0' || s[1] > '4' {
		return 0, false
	}
	return pinblock.Format(s[1] - '0'), true
}

func pinKeyFor(fm pinblock.Format) KeyType {
	if fm == pinblock.Format4 {
		return PINKeyAES
	}
	return PINKey
}

// decryptPIN unwraps a PIN key, checks it matches the format, and decrypts.
func (h *HSM) decryptPIN(token, format, block, pan string) (string, string) {
	fm, ok := parseFormat(format)
	if !ok {
		return "", InvalidPINFormat
	}
	k, _, err := h.ks.unwrap(token, pinKeyFor(fm))
	if err != nil {
		return "", keyErr(err)
	}
	b, err := keys.Hex(block)
	if err != nil {
		return "", InvalidInput
	}
	pin, err := pinblock.Decrypt(fm, k, b, pan)
	if err != nil {
		if errors.Is(err, pinblock.ErrPAN) {
			return "", InvalidInput
		}
		return "", PINBlockError
	}
	return pin, OK
}

func (h *HSM) encryptPIN(token, format, pin, pan string) (string, string) {
	fm, ok := parseFormat(format)
	if !ok {
		return "", InvalidPINFormat
	}
	k, _, err := h.ks.unwrap(token, pinKeyFor(fm))
	if err != nil {
		return "", keyErr(err)
	}
	out, err := pinblock.Encrypt(fm, k, pin, pan, nil)
	if err != nil {
		return "", InvalidInput
	}
	return keys.HexUpper(out), OK
}

// CA translate PIN: [srcKey, srcFmt, block, pan, dstKey, dstFmt] → [block, pinLen]
func (h *HSM) translatePIN(f []string) ([]string, string) {
	if !need(f, 6) {
		return nil, InvalidInput
	}
	pin, code := h.decryptPIN(f[0], f[1], f[2], f[3])
	if code != OK {
		return nil, code
	}
	out, code := h.encryptPIN(f[4], f[5], pin, f[3])
	if code != OK {
		return nil, code
	}
	return []string{out, strconv.Itoa(len(pin))}, OK
}

// G0 translate PIN from DUKPT: [bdk, ksn, block, pan, dstKey, dstFmt] → [block]
func (h *HSM) translateDUKPT(f []string) ([]string, string) {
	if !need(f, 6) {
		return nil, InvalidInput
	}
	bdk, _, err := h.ks.unwrap(f[0], BDK)
	if err != nil {
		return nil, keyErr(err)
	}
	ksn, err := dukpt.ParseKSN(f[1])
	if err != nil {
		return nil, DUKPTError
	}
	pk, err := dukpt.HostKey(bdk, ksn, dukpt.PIN)
	if err != nil {
		return nil, DUKPTError
	}
	b, err := keys.Hex(f[2])
	if err != nil {
		return nil, InvalidInput
	}
	pin, err := pinblock.Decrypt(pinblock.Format0, pk, b, f[3])
	if err != nil {
		return nil, PINBlockError
	}
	out, code := h.encryptPIN(f[4], f[5], pin, f[3])
	if code != OK {
		return nil, code
	}
	return []string{out}, OK
}

// DG generate PVV: [pinKey, fmt, block, pan, pvk, pvki] → [pvv]
func (h *HSM) generatePVV(f []string) ([]string, string) {
	if !need(f, 6) {
		return nil, InvalidInput
	}
	pin, code := h.decryptPIN(f[0], f[1], f[2], f[3])
	if code != OK {
		return nil, code
	}
	pvk, _, err := h.ks.unwrap(f[4], PVK)
	if err != nil {
		return nil, keyErr(err)
	}
	pvki, err := strconv.Atoi(f[5])
	if err != nil {
		return nil, InvalidInput
	}
	pvv, err := cardauth.PVV(pvk, f[3], pvki, pin)
	if err != nil {
		return nil, InvalidInput
	}
	return []string{pvv}, OK
}

// DC verify PIN against a PVV: [pinKey, fmt, block, pan, pvk, pvki, pvv] → []
func (h *HSM) verifyPVV(f []string) ([]string, string) {
	if !need(f, 7) {
		return nil, InvalidInput
	}
	pin, code := h.decryptPIN(f[0], f[1], f[2], f[3])
	if code != OK {
		return nil, code
	}
	pvk, _, err := h.ks.unwrap(f[4], PVK)
	if err != nil {
		return nil, keyErr(err)
	}
	pvki, err := strconv.Atoi(f[5])
	if err != nil {
		return nil, InvalidInput
	}
	ok, err := cardauth.VerifyPVV(pvk, f[3], pvki, pin, f[6])
	if err != nil {
		return nil, InvalidInput
	}
	if !ok {
		return nil, VerifyFailed
	}
	return []string{}, OK
}

// DA verify PIN against an IBM 3624 offset: [pinKey, fmt, block, pan, pvk, offset] → []
func (h *HSM) verifyIBM(f []string) ([]string, string) {
	if !need(f, 6) {
		return nil, InvalidInput
	}
	pin, code := h.decryptPIN(f[0], f[1], f[2], f[3])
	if code != OK {
		return nil, code
	}
	pvk, _, err := h.ks.unwrap(f[4], PVK)
	if err != nil {
		return nil, keyErr(err)
	}
	ok, err := cardauth.IBM3624{Key: pvk}.Verify(f[3], pin, f[5])
	if err != nil {
		return nil, InvalidInput
	}
	if !ok {
		return nil, VerifyFailed
	}
	return []string{}, OK
}

// CW generate CVV: [cvk, pan, expiry, service] → [cvv]
func (h *HSM) generateCVV(f []string) ([]string, string) {
	if !need(f, 4) {
		return nil, InvalidInput
	}
	k, _, err := h.ks.unwrap(f[0], CVK)
	if err != nil {
		return nil, keyErr(err)
	}
	cvv, err := cardauth.CVV(k, f[1], f[2], f[3])
	if err != nil {
		return nil, InvalidInput
	}
	return []string{cvv}, OK
}

// CY verify CVV: [cvk, pan, expiry, service, cvv] → []
func (h *HSM) verifyCVV(f []string) ([]string, string) {
	if !need(f, 5) {
		return nil, InvalidInput
	}
	k, _, err := h.ks.unwrap(f[0], CVK)
	if err != nil {
		return nil, keyErr(err)
	}
	ok, err := cardauth.VerifyCVV(k, f[1], f[2], f[3], f[4])
	if err != nil {
		return nil, InvalidInput
	}
	if !ok {
		return nil, VerifyFailed
	}
	return []string{}, OK
}

// KQ verify ARQC and generate ARPC (method 1):
// [imk, scheme(18|10), pan, psn, txData(hex), atc(hex4), arqc, arc] → [arpc]
// txData is the exact byte string the card MACed (see emv.Transaction.Data).
func (h *HSM) verifyARQC(f []string) ([]string, string) {
	if !need(f, 8) {
		return nil, InvalidInput
	}
	imk, _, err := h.ks.unwrap(f[0], EMVMasterK)
	if err != nil {
		return nil, keyErr(err)
	}
	var scheme emv.Scheme
	switch f[1] {
	case "18":
		scheme = emv.CVN18
	case "10":
		scheme = emv.CVN10
	default:
		return nil, InvalidInput
	}
	mk, err := emv.DeriveICCKey(imk, f[2], f[3])
	if err != nil {
		return nil, InvalidInput
	}
	data, err1 := keys.Hex(f[4])
	atc, err2 := strconv.ParseUint(f[5], 16, 16)
	arqc, err3 := keys.Hex(f[6])
	if err1 != nil || err2 != nil || err3 != nil || len(arqc) != 8 || len(f[7]) != 2 || len(f[5]) != 4 {
		return nil, InvalidInput
	}
	key := mk
	pad := keys.Pad1
	if scheme == emv.CVN18 {
		if key, err = emv.SessionKey(mk, uint16(atc)); err != nil {
			return nil, InternalError
		}
		pad = keys.Pad2
	}
	want, err := keys.RetailMAC(key, data, pad)
	if err != nil {
		return nil, InternalError
	}
	if !keys.Equal(want, arqc) {
		return nil, VerifyFailed
	}
	arpc, err := emv.ARPCMethod1(key, arqc, [2]byte{f[7][0], f[7][1]})
	if err != nil {
		return nil, InternalError
	}
	return []string{keys.HexUpper(arpc)}, OK
}

// T0 tokenize: [pan] → [token, masked]
func (h *HSM) tokenizePAN(f []string) ([]string, string) {
	if h.vault == nil {
		return nil, CommandDisabled
	}
	if !need(f, 1) {
		return nil, InvalidInput
	}
	tok, err := h.vault.Tokenize(f[0])
	if err != nil {
		return nil, InvalidInput
	}
	return []string{tok, tokenize.Mask(f[0])}, OK
}

// T2 detokenize: [token] → [pan]
func (h *HSM) detokenize(f []string) ([]string, string) {
	if h.vault == nil {
		return nil, CommandDisabled
	}
	if !need(f, 1) {
		return nil, InvalidInput
	}
	pan, err := h.vault.Detokenize(f[0])
	if err != nil {
		return nil, InvalidInput
	}
	return []string{pan}, OK
}

// NC diagnostics: [] → [lmkKCV, version, commands]
func (h *HSM) diagnostics(f []string) ([]string, string) {
	return []string{h.ks.kcv, Version, strings.Join(Commands(), ",")}, OK
}

// Version is reported by NC.
const Version = "hsm-sim-go/0.1.0"
