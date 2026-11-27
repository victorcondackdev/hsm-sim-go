// Command hsm-demo walks a card transaction through the simulator end to
// end: a DUKPT PIN pad encrypts the PIN, the acquirer HSM translates it to
// the issuer zone, the issuer HSM verifies the PIN (PVV) and the chip
// cryptogram (ARQC) and answers with an ARPC, then an e-commerce payment is
// checked by CVV2 and the card is tokenized for card-on-file.
//
// Every key is a published test key, so the output is reproducible.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/victorcondackdev/hsm-sim-go/cardauth"
	"github.com/victorcondackdev/hsm-sim-go/dukpt"
	"github.com/victorcondackdev/hsm-sim-go/emv"
	"github.com/victorcondackdev/hsm-sim-go/hsm"
	"github.com/victorcondackdev/hsm-sim-go/keys"
	"github.com/victorcondackdev/hsm-sim-go/pinblock"
	"github.com/victorcondackdev/hsm-sim-go/tokenize"
)

const (
	testKey = "0123456789ABCDEFFEDCBA9876543210"
	zpkHex  = "1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A"
	pan     = "4761739001010119"
	psn     = "01"
	pin     = "2580"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hsm-demo:", err)
		os.Exit(1)
	}
}

type step struct {
	h *hsm.HSM
}

func (s step) do(cmd string, f ...string) ([]string, error) {
	r := s.h.Execute(context.Background(), hsm.Request{Header: "DEMO", Command: cmd, Fields: f})
	if !r.OK() {
		return nil, fmt.Errorf("%s answered %s error %s", cmd, r.Code, r.Error)
	}
	return r.Fields, nil
}

func run() error {
	lmk := make([]byte, 32)
	k, _ := tokenize.RandomKeys()
	vault, _ := tokenize.New(k)
	h, err := hsm.New(hsm.Options{LMK: lmk, Vault: vault})
	if err != nil {
		return err
	}
	s := step{h}

	fmt.Println("== key ceremony ==")
	imp := func(t hsm.KeyType, hex string) (string, error) {
		f, err := s.do("A6", string(t), hex)
		if err != nil {
			return "", err
		}
		fmt.Printf("  %-3s KCV %s\n", t, f[1])
		return f[0], nil
	}
	bdk, err := imp(hsm.BDK, testKey)
	if err != nil {
		return err
	}
	zpkClear := keys.FixParity(keys.MustHex(zpkHex))
	zpk, err := imp(hsm.PINKey, keys.HexUpper(zpkClear))
	if err != nil {
		return err
	}
	pvk, err := imp(hsm.PVK, testKey)
	if err != nil {
		return err
	}
	cvk, err := imp(hsm.CVK, testKey)
	if err != nil {
		return err
	}
	imk, err := imp(hsm.EMVMasterK, testKey)
	if err != nil {
		return err
	}

	fmt.Println("== issuance ==")
	pvvClear, _ := cardauth.PVV(keys.MustHex(testKey), pan, 1, pin)
	cvv2, err := s.do("CW", cvk, pan, "2912", cardauth.ServiceCVV2)
	if err != nil {
		return err
	}
	fmt.Printf("  PAN %s  PVV %s  CVV2 %s\n", tokenize.Mask(pan), pvvClear, cvv2[0])

	fmt.Println("== chip and PIN at a POS ==")
	ksn0, _ := dukpt.ParseKSN("FFFF9876543210E00000")
	ipek, _ := dukpt.IPEK(keys.MustHex(testKey), ksn0)
	term, _ := dukpt.NewTerminal(ipek, ksn0)
	ksn, pk, err := term.Next(dukpt.PIN)
	if err != nil {
		return err
	}
	blk, _ := pinblock.Encrypt(pinblock.Format0, pk, pin, pan, nil)
	fmt.Printf("  terminal KSN %s PIN block %s\n", ksn, keys.HexUpper(blk))
	zoneBlk, err := s.do("G0", bdk, ksn.String(), keys.HexUpper(blk), pan, zpk, "00")
	if err != nil {
		return err
	}
	fmt.Printf("  acquirer G0 -> ZPK block %s\n", zoneBlk[0])
	if _, err := s.do("DC", zpk, "00", zoneBlk[0], pan, pvk, "1", pvvClear); err != nil {
		return err
	}
	fmt.Println("  issuer DC: PIN verified")

	mk, _ := emv.DeriveICCKey(keys.MustHex(testKey), pan, psn)
	tx := emv.Transaction{Amount: 15990, TerminalCountry: 76, Currency: 986, Date: "261127",
		UnpredictableNum: [4]byte{0x11, 0x22, 0x33, 0x44}, AIP: [2]byte{0x39, 0x00}, ATC: 0x0042,
		IAD: keys.MustHex("03A00000")}
	arqc, _ := emv.ARQC(mk, tx, emv.CVN18)
	data, _ := tx.Data()
	fmt.Printf("  card ARQC %s (ATC %04X, R$ 159,90)\n", keys.HexUpper(arqc), tx.ATC)
	arpc, err := s.do("KQ", imk, "18", pan, psn, keys.HexUpper(data), fmt.Sprintf("%04X", tx.ATC), keys.HexUpper(arqc), "00")
	if err != nil {
		return err
	}
	fmt.Printf("  issuer KQ: ARQC valid, ARPC %s\n", arpc[0])

	fmt.Println("== card not present ==")
	if _, err := s.do("CY", cvk, pan, "2912", cardauth.ServiceCVV2, cvv2[0]); err != nil {
		return err
	}
	fmt.Println("  CVV2 verified")
	r := h.Execute(context.Background(), hsm.Request{Header: "DEMO", Command: "CY", Fields: []string{cvk, pan, "2912", cardauth.ServiceCVV2, "000"}})
	fmt.Printf("  wrong CVV2 -> %s error %s\n", r.Code, r.Error)
	tok, err := s.do("T0", pan)
	if err != nil {
		return err
	}
	fmt.Printf("  card on file: token keeps BIN and last 4 (%s), fails Luhn: %v\n", tok[1], !tokenize.Luhn(tok[0]))

	fmt.Println("== attack: CVK presented as a PIN key ==")
	r = h.Execute(context.Background(), hsm.Request{Header: "DEMO", Command: "CA", Fields: []string{cvk, "00", zoneBlk[0], pan, zpk, "00"}})
	fmt.Printf("  CA -> %s error %s (key usage violation)\n", r.Code, r.Error)
	return nil
}
