package dukpt

import (
	"bytes"
	"testing"

	"github.com/victorcondackdev/hsm-sim-go/keys"
	"github.com/victorcondackdev/hsm-sim-go/pinblock"
)

// Test data from ANSI X9.24-1:2009 Annex A (the values every DUKPT
// implementation is checked against).
var (
	bdk = keys.MustHex("0123456789ABCDEFFEDCBA9876543210")
	ksn = mustKSN("FFFF9876543210E00000")
)

func mustKSN(s string) KSN {
	k, err := ParseKSN(s)
	if err != nil {
		panic(err)
	}
	return k
}

func TestIPEK(t *testing.T) {
	ipek, err := IPEK(bdk, ksn)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.HexUpper(ipek); got != "6AC292FAA1315B4D858AB3A3D7D5933A" {
		t.Fatalf("IPEK = %s", got)
	}
}

func TestAnnexAPINKeysAndBlocks(t *testing.T) {
	cases := []struct {
		counter uint32
		txKey   string
		pinKey  string
		block   string
	}{
		{1, "042666B49184CFA368DE9628D0397BC9", "042666B49184CF5C68DE9628D0397B36", "1B9C1845EB993A7A"},
		{2, "C46551CEF9FD24B0AA9AD834130D3BC7", "C46551CEF9FD244FAA9AD834130D3B38", "10A01C8D02C69107"},
	}
	for _, c := range cases {
		tx, _ := Derive(bdk, ksn.WithCounter(c.counter))
		if got := keys.HexUpper(tx); got != c.txKey {
			t.Errorf("counter %d: transaction key %s, want %s", c.counter, got, c.txKey)
		}
		k, err := HostKey(bdk, ksn.WithCounter(c.counter), PIN)
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.HexUpper(k); got != c.pinKey {
			t.Errorf("counter %d: PIN key %s, want %s", c.counter, got, c.pinKey)
		}
		blk, err := pinblock.Encrypt(pinblock.Format0, k, "1234", "4012345678909", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.HexUpper(blk); got != c.block {
			t.Errorf("counter %d: PIN block %s, want %s", c.counter, got, c.block)
		}
	}
}

func TestTerminalMatchesHost(t *testing.T) {
	ipek, _ := IPEK(bdk, ksn)
	term, err := NewTerminal(ipek, ksn)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		k, key, err := term.Next(PIN)
		if err != nil {
			t.Fatal(err)
		}
		host, _ := HostKey(bdk, k, PIN)
		if !bytes.Equal(host, key) {
			t.Fatalf("KSN %s: terminal and host keys differ", k)
		}
		if seen[keys.HexUpper(key)] {
			t.Fatalf("KSN %s: key reused", k)
		}
		seen[keys.HexUpper(key)] = true
	}
}

func TestCounterRules(t *testing.T) {
	if validCounter(0) || !validCounter(1) || validCounter(0x3FF<<1|1) {
		t.Fatal("ten-bit rule")
	}
	n, _ := NextCounter(0x3FF) // ten bits set; 0x400 is next
	if n != 0x400 {
		t.Fatalf("NextCounter(0x3FF) = %#x", n)
	}
	// 0x7FE has ten bits, 0x7FF eleven: skipped.
	n, _ = NextCounter(0x7FE)
	if n != 0x800 {
		t.Fatalf("NextCounter(0x7FE) = %#x", n)
	}
	if _, err := NextCounter(MaxCounter); err != ErrExhausted {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
	k := ksn.WithCounter(0x1ABCDE)
	if k.Counter() != 0x1ABCDE || k.String()[:14] != "FFFF9876543210" {
		t.Fatalf("WithCounter: %s", k)
	}
}

func TestVariantsDiffer(t *testing.T) {
	tx, _ := Derive(bdk, ksn.WithCounter(1))
	seen := map[string]Usage{}
	for u := PIN; u <= DataResponse; u++ {
		k, err := WorkingKey(tx, u)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[keys.HexUpper(k)]; dup {
			t.Fatalf("%v and %v share a key", prev, u)
		}
		seen[keys.HexUpper(k)] = u
	}
}

func TestParseKSN(t *testing.T) {
	if _, err := ParseKSN("FFFF"); err != ErrKSN {
		t.Fatal("short KSN accepted")
	}
	if _, err := IPEK(make([]byte, 8), ksn); err != ErrBDK {
		t.Fatal("short BDK accepted")
	}
}
