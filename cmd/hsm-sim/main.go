// Command hsm-sim runs the payment HSM simulator on a TCP port.
//
//	hsm-sim -addr :1500 -latency 5ms -jitter 10ms -error-rate 0.01 -disable A6
//
// Without -lmk a random LMK is generated, so key tokens do not survive a
// restart; pass -lmk (64 hex digits) or HSM_SIM_LMK for stable tokens in CI.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/victorcondackdev/hsm-sim-go/hsm"
	"github.com/victorcondackdev/hsm-sim-go/keys"
	"github.com/victorcondackdev/hsm-sim-go/tokenize"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hsm-sim:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("hsm-sim", flag.ContinueOnError)
	addr := fs.String("addr", ":1500", "listen address")
	lmkHex := fs.String("lmk", os.Getenv("HSM_SIM_LMK"), "LMK, 64 hex digits (default: random)")
	latency := fs.Duration("latency", 0, "added latency per command")
	jitter := fs.Duration("jitter", 0, "random extra latency up to this value")
	errRate := fs.Float64("error-rate", 0, "probability of an injected internal error (0-1)")
	seed := fs.Int64("seed", 0, "seed for injected faults (0: time based)")
	disable := fs.String("disable", "", "comma-separated commands to disable")
	vault := fs.Bool("vault", true, "enable the tokenization vault (T0/T2)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var lmk []byte
	var err error
	if *lmkHex != "" {
		if lmk, err = keys.Hex(*lmkHex); err != nil || len(lmk) != 32 {
			return fmt.Errorf("-lmk must be 64 hex digits")
		}
	} else {
		lmk = make([]byte, 32)
		if _, err := rand.Read(lmk); err != nil {
			return err
		}
	}
	o := hsm.Options{LMK: lmk, Faults: hsm.Faults{Latency: *latency, Jitter: *jitter, ErrorRate: *errRate, Seed: *seed}}
	if *disable != "" {
		o.Disabled = strings.Split(*disable, ",")
	}
	if *vault {
		k, err := tokenize.RandomKeys()
		if err != nil {
			return err
		}
		if o.Vault, err = tokenize.New(k); err != nil {
			return err
		}
	}
	h, err := hsm.New(o)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	kcv, _ := keys.KCVAES(lmk)
	log.Info("hsm-sim listening", "addr", ln.Addr().String(), "lmk_kcv", kcv, "version", hsm.Version, "commands", hsm.Commands())
	srv := &hsm.Server{HSM: h, Logger: log}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Info("shutting down")
		done := make(chan struct{})
		go func() { srv.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}()
	return srv.Serve(ln)
}
