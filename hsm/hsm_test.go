package hsm

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victorcondackdev/hsm-sim-go/dukpt"
	"github.com/victorcondackdev/hsm-sim-go/emv"
	"github.com/victorcondackdev/hsm-sim-go/keys"
	"github.com/victorcondackdev/hsm-sim-go/pinblock"
	"github.com/victorcondackdev/hsm-sim-go/tokenize"
)

var lmk = keys.MustHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

func newHSM(t *testing.T, o Options) *HSM {
	t.Helper()
	if o.LMK == nil {
		o.LMK = lmk
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func run(t *testing.T, h *HSM, cmd string, f ...string) Response {
	t.Helper()
	return h.Execute(context.Background(), Request{Header: "0001", Command: cmd, Fields: f})
}

func must(t *testing.T, r Response) []string {
	t.Helper()
	if !r.OK() {
		t.Fatalf("%s failed with %s", r.Code, r.Error)
	}
	return r.Fields
}

func TestGenerateAndKCV(t *testing.T) {
	h := newHSM(t, Options{})
	f := must(t, run(t, h, "A0", "P0"))
	tok, kcv := f[0], f[1]
	if !strings.HasPrefix(tok, "SP0") || len(kcv) != 6 {
		t.Fatalf("A0 = %v", f)
	}
	g := must(t, run(t, h, "BU", tok))
	if g[0] != "P0" || g[1] != kcv {
		t.Fatalf("BU = %v", g)
	}
	if r := run(t, h, "A0", "ZZ"); r.Error != InvalidKeyType {
		t.Fatalf("bad type: %s", r.Error)
	}
	aes := must(t, run(t, h, "A0", "P1"))
	if len(aes[1]) != 10 {
		t.Fatalf("AES KCV %s", aes[1])
	}
}

func TestImportComponentsKCV(t *testing.T) {
	h := newHSM(t, Options{})
	f := must(t, run(t, h, "A6", "P0", "0123456789ABCDEFFEDCBA9876543210"))
	if f[1] != "08D7B4" {
		t.Fatalf("KCV %s", f[1])
	}
	c1 := "0123456789ABCDEFFEDCBA9876543210"
	c2 := "1111111111111111" + "1111111111111111"
	c3 := c2
	// c2 ⊕ c3 = 0, so the three components combine back to c1.
	f = must(t, run(t, h, "A6", "P0", c1, c2, c3))
	if f[1] != "08D7B4" {
		t.Fatalf("component KCV %s", f[1])
	}
	if r := run(t, h, "A6", "P0", "0023456789ABCDEFFEDCBA9876543210"); r.Error != ParityError {
		t.Fatalf("parity: %s", r.Error)
	}
}

func TestTranslatePIN(t *testing.T) {
	h := newHSM(t, Options{})
	tpkClear := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	tpk := must(t, run(t, h, "A6", "P0", keys.HexUpper(tpkClear)))[0]
	zpk := must(t, run(t, h, "A0", "P0"))[0]
	aesZPK := must(t, run(t, h, "A0", "P1"))[0]
	pan := "4111111111111111"
	blk, _ := pinblock.Encrypt(pinblock.Format0, tpkClear, "4321", pan, nil)

	out := must(t, run(t, h, "CA", tpk, "00", keys.HexUpper(blk), pan, zpk, "03"))
	if out[1] != "4" || len(out[0]) != 16 {
		t.Fatalf("CA = %v", out)
	}
	// Translate on to AES format 4 and back to format 0 under the TPK.
	f4 := must(t, run(t, h, "CA", zpk, "03", out[0], pan, aesZPK, "04"))[0]
	if len(f4) != 32 {
		t.Fatalf("format 4 block %s", f4)
	}
	back := must(t, run(t, h, "CA", aesZPK, "04", f4, pan, tpk, "00"))[0]
	pin, err := pinblock.Decrypt(pinblock.Format0, tpkClear, keys.MustHex(back), pan)
	if err != nil || pin != "4321" {
		t.Fatalf("round trip PIN %q %v", pin, err)
	}
	// A TDES key cannot serve format 4 and vice versa.
	if r := run(t, h, "CA", tpk, "04", f4, pan, zpk, "00"); r.Error != KeyUsageViolation {
		t.Fatalf("format/key mismatch: %s", r.Error)
	}
}

func TestKeyUsageAndTokenIntegrity(t *testing.T) {
	h := newHSM(t, Options{})
	cvk := must(t, run(t, h, "A0", "C0"))[0]
	zpk := must(t, run(t, h, "A0", "P0"))[0]
	// A CVK presented as a PIN key is refused.
	if r := run(t, h, "CA", cvk, "00", "0000000000000000", "4111111111111111", zpk, "00"); r.Error != KeyUsageViolation {
		t.Fatalf("usage: %s", r.Error)
	}
	// Re-labelling the token's type breaks the GCM tag (type is AAD).
	forged := "SP0" + cvk[3:]
	if r := run(t, h, "CA", forged, "00", "0000000000000000", "4111111111111111", zpk, "00"); r.Error != InvalidToken {
		t.Fatalf("forged type: %s", r.Error)
	}
	// A token from another HSM (different LMK) is unreadable.
	other := newHSM(t, Options{LMK: make([]byte, 32)})
	if r := run(t, other, "BU", cvk); r.Error != InvalidToken {
		t.Fatalf("foreign LMK: %s", r.Error)
	}
}

func TestDUKPTTranslate(t *testing.T) {
	h := newHSM(t, Options{})
	bdkClear := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	bdk := must(t, run(t, h, "A6", "B0", keys.HexUpper(bdkClear)))[0]
	zpkClear := keys.FixParity(keys.MustHex("1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A"))
	zpk := must(t, run(t, h, "A6", "P0", keys.HexUpper(zpkClear)))[0]

	// X9.24 Annex A: KSN ...E00001, PIN 1234, PAN 4012345678909.
	out := must(t, run(t, h, "G0", bdk, "FFFF9876543210E00001", "1B9C1845EB993A7A", "4012345678909", zpk, "00"))[0]
	pin, err := pinblock.Decrypt(pinblock.Format0, zpkClear, keys.MustHex(out), "4012345678909")
	if err != nil || pin != "1234" {
		t.Fatalf("G0 PIN %q %v", pin, err)
	}

	// And with a simulated terminal.
	ksn0, _ := dukpt.ParseKSN("FFFF9876543210E00000")
	ipek, _ := dukpt.IPEK(bdkClear, ksn0)
	term, _ := dukpt.NewTerminal(ipek, ksn0)
	for i := 0; i < 5; i++ {
		ksn, pk, _ := term.Next(dukpt.PIN)
		blk, _ := pinblock.Encrypt(pinblock.Format0, pk, "909090", "5555555555554444", nil)
		out := must(t, run(t, h, "G0", bdk, ksn.String(), keys.HexUpper(blk), "5555555555554444", zpk, "00"))[0]
		if pin, _ := pinblock.Decrypt(pinblock.Format0, zpkClear, keys.MustHex(out), "5555555555554444"); pin != "909090" {
			t.Fatalf("terminal txn %d: %q", i, pin)
		}
	}
	if r := run(t, h, "G0", bdk, "FFFF", "1B9C1845EB993A7A", "4012345678909", zpk, "00"); r.Error != DUKPTError {
		t.Fatalf("bad KSN: %s", r.Error)
	}
}

func TestCVVAndPINVerification(t *testing.T) {
	h := newHSM(t, Options{})
	cvk := must(t, run(t, h, "A6", "C0", "0123456789ABCDEFFEDCBA9876543210"))[0]
	cvv := must(t, run(t, h, "CW", cvk, "4123456789012345", "8701", "101"))[0]
	if cvv != "561" {
		t.Fatalf("CVV %s", cvv)
	}
	must(t, run(t, h, "CY", cvk, "4123456789012345", "8701", "101", "561"))
	if r := run(t, h, "CY", cvk, "4123456789012345", "8701", "101", "562"); r.Error != VerifyFailed {
		t.Fatalf("bad CVV: %s", r.Error)
	}

	tpkClear := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	tpk := must(t, run(t, h, "A6", "P0", keys.HexUpper(tpkClear)))[0]
	pvk := must(t, run(t, h, "A0", "V0"))[0]
	pan := "4123456789012345"
	good, _ := pinblock.Encrypt(pinblock.Format0, tpkClear, "2468", pan, nil)
	bad, _ := pinblock.Encrypt(pinblock.Format0, tpkClear, "2469", pan, nil)

	pvv := must(t, run(t, h, "DG", tpk, "00", keys.HexUpper(good), pan, pvk, "1"))[0]
	must(t, run(t, h, "DC", tpk, "00", keys.HexUpper(good), pan, pvk, "1", pvv))
	if r := run(t, h, "DC", tpk, "00", keys.HexUpper(bad), pan, pvk, "1", pvv); r.Error != VerifyFailed {
		t.Fatalf("wrong PIN PVV: %s", r.Error)
	}
	// IBM 3624 offset 0000 verifies the natural PIN only.
	if r := run(t, h, "DA", tpk, "00", keys.HexUpper(good), pan, pvk, "0000"); r.Error != VerifyFailed && r.Error != OK {
		t.Fatalf("DA: %s", r.Error)
	}
	if r := run(t, h, "DA", tpk, "00", "FFFFFFFFFFFFFFFF", pan, pvk, "0000"); r.Error != PINBlockError {
		t.Fatalf("garbage block: %s", r.Error)
	}
}

func TestARQC(t *testing.T) {
	h := newHSM(t, Options{})
	imkClear := keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	imk := must(t, run(t, h, "A6", "E0", keys.HexUpper(imkClear)))[0]
	pan, psn := "4761739001010119", "01"
	mk, _ := emv.DeriveICCKey(imkClear, pan, psn)
	tx := emv.Transaction{Amount: 1000, TerminalCountry: 76, Currency: 986, Date: "261127",
		UnpredictableNum: [4]byte{1, 2, 3, 4}, AIP: [2]byte{0x39, 0}, ATC: 7}
	data, _ := tx.Data()
	for _, sc := range []struct {
		name string
		s    emv.Scheme
	}{{"18", emv.CVN18}, {"10", emv.CVN10}} {
		arqc, _ := emv.ARQC(mk, tx, sc.s)
		arpc := must(t, run(t, h, "KQ", imk, sc.name, pan, psn, keys.HexUpper(data), "0007", keys.HexUpper(arqc), "00"))[0]
		if len(arpc) != 16 {
			t.Fatalf("ARPC %s", arpc)
		}
		bad := append([]byte(nil), arqc...)
		bad[0] ^= 1
		if r := run(t, h, "KQ", imk, sc.name, pan, psn, keys.HexUpper(data), "0007", keys.HexUpper(bad), "00"); r.Error != VerifyFailed {
			t.Fatalf("bad ARQC: %s", r.Error)
		}
	}
}

func TestTokenizeCommands(t *testing.T) {
	k, _ := tokenize.RandomKeys()
	v, _ := tokenize.New(k)
	h := newHSM(t, Options{Vault: v})
	f := must(t, run(t, h, "T0", "4111111111111111"))
	if f[1] != "411111******1111" {
		t.Fatalf("mask %s", f[1])
	}
	if pan := must(t, run(t, h, "T2", f[0]))[0]; pan != "4111111111111111" {
		t.Fatalf("T2 %s", pan)
	}
	if r := run(t, newHSM(t, Options{}), "T0", "4111111111111111"); r.Error != CommandDisabled {
		t.Fatalf("no vault: %s", r.Error)
	}
}

func TestFaultsAndDisabled(t *testing.T) {
	h := newHSM(t, Options{Disabled: []string{"A6"}, Faults: Faults{Seed: 1}})
	if r := run(t, h, "A6", "P0", "0123456789ABCDEFFEDCBA9876543210"); r.Error != CommandDisabled || r.Code != "A7" {
		t.Fatalf("disabled: %+v", r)
	}
	if r := run(t, h, "XX"); r.Error != UnknownCommand {
		t.Fatalf("unknown: %s", r.Error)
	}
	h.SetFaults(Faults{ErrorRate: 1, Seed: 1})
	if r := run(t, h, "NC"); r.Error != InternalError {
		t.Fatalf("error rate 1: %s", r.Error)
	}
	h.SetFaults(Faults{Latency: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := h.Execute(ctx, Request{Header: "0001", Command: "NC"})
	if r.Error != InternalError || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("latency not bounded by ctx: %s after %v", r.Error, time.Since(start))
	}
	h.SetFaults(Faults{})
	if !strings.Contains(strings.Join(h.Stats(), ","), "NC=2") {
		t.Fatalf("stats %v", h.Stats())
	}
}

func TestWireRoundTripOverTCP(t *testing.T) {
	h := newHSM(t, Options{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{HSM: h}
	go srv.Serve(ln)
	defer srv.Close()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := Dial(context.Background(), ln.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			for i := 0; i < 50; i++ {
				r, err := c.Do(context.Background(), "A0", "C0")
				if err != nil || !r.OK() || r.Code != "A1" {
					t.Errorf("A0 over TCP: %+v %v", r, err)
					return
				}
				r, err = c.Do(context.Background(), "BU", r.Fields[0])
				if err != nil || !r.OK() || r.Fields[0] != "C0" {
					t.Errorf("BU over TCP: %+v %v", r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	nc, _ := Dial(context.Background(), ln.Addr().String())
	r, _ := nc.Do(context.Background(), "NC")
	if r.Fields[0] != h.ks.kcv || r.Fields[1] != Version {
		t.Fatalf("NC %v", r.Fields)
	}
	nc.Close()
}

func TestMarshal(t *testing.T) {
	p, _ := MarshalRequest(Request{Header: "0042", Command: "CW", Fields: []string{"a", "", "b"}})
	if string(p) != "0042CW;a;;b" {
		t.Fatalf("%s", p)
	}
	r, err := UnmarshalRequest(p)
	if err != nil || len(r.Fields) != 3 || r.Fields[1] != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := MarshalRequest(Request{Header: "1", Command: "CW"}); err != ErrFrame {
		t.Fatal("short header")
	}
	if _, err := MarshalRequest(Request{Header: "0001", Command: "CW", Fields: []string{"a;b"}}); err != ErrFrame {
		t.Fatal("separator in field")
	}
	if _, err := UnmarshalResponse([]byte("0001CX00x")); err != ErrFrame {
		t.Fatal("garbage after header")
	}
	if ResponseCode("CA") != "CB" || ResponseCode("KQ") != "KR" {
		t.Fatal("response codes")
	}
}

func FuzzUnmarshalRequest(f *testing.F) {
	f.Add([]byte("0001CA;a;b"))
	f.Fuzz(func(t *testing.T, p []byte) {
		r, err := UnmarshalRequest(p)
		if err != nil {
			return
		}
		h, _ := New(Options{LMK: lmk})
		h.Execute(context.Background(), r) // must not panic
	})
}
