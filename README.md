# hsm-sim-go

[![CI](https://github.com/victorcondackdev/hsm-sim-go/actions/workflows/ci.yml/badge.svg)](https://github.com/victorcondackdev/hsm-sim-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/victorcondackdev/hsm-sim-go.svg)](https://pkg.go.dev/github.com/victorcondackdev/hsm-sim-go)

A payment HSM simulator and card cryptography toolkit for Go: ISO 9564 PIN
blocks (formats 0–4), TDES DUKPT, Visa CVV/PVV, IBM 3624 offsets, EMV
ARQC/ARPC, FF1 format-preserving encryption and a PCI-style tokenization
vault, behind a TCP server with a payShield-inspired command set, usage-bound
key tokens and fault injection.

Built for the place where card authorization code is usually untestable:
CI pipelines and laptops with no HSM. Pair it with
[iso8583-go](https://github.com/victorcondackdev/iso8583-go) and you can run
a full acquirer → issuer authorization, PIN and chip cryptogram included,
inside `go test`.

Standard library only. Go 1.22+.

```
keys/       TDES/AES block ops, parity, KCV, components, retail MAC, CMAC
pinblock/   ISO 9564-1 formats 0, 1, 2, 3 (TDES) and 4 (AES)
dukpt/      ANSI X9.24-1:2009 TDES DUKPT: IPEK, key derivation, variants, terminal
cardauth/   CVV / CVV2 / iCVV, Visa PVV, IBM 3624 natural PIN and offsets
emv/        ICC key derivation (option A), session keys, ARQC, ARPC methods 1 and 2
fpe/        FF1 (NIST SP 800-38G) over AES, any radix up to 36
tokenize/   token vault: BIN + last 4 preserved, Luhn-failing tokens, AES-GCM at rest
hsm/        command processor, LMK key tokens, wire protocol, TCP server and client
cmd/        hsm-sim (server) and hsm-demo (end-to-end card transaction)
```

## Quick start

```sh
go run ./cmd/hsm-demo
```

```
== key ceremony ==
  B0  KCV 08D7B4
  P0  KCV B29243
  ...
== chip and PIN at a POS ==
  terminal KSN FFFF9876543210E00001 PIN block 0F88290BCB09444A
  acquirer G0 -> ZPK block BAC990BE1135FC81
  issuer DC: PIN verified
  card ARQC 837D747AC0F9DD1D (ATC 0042, R$ 159,90)
  issuer KQ: ARQC valid, ARPC 477F5E344C77C8B2
== card not present ==
  CVV2 verified
  wrong CVV2 -> CZ error 01
  card on file: token keeps BIN and last 4 (476173******0119), fails Luhn: true
== attack: CVK presented as a PIN key ==
  CA -> CB error 27 (key usage violation)
```

Run the server (or `docker build -t hsm-sim . && docker run -p 1500:1500 hsm-sim`):

```sh
go run ./cmd/hsm-sim -addr :1500 -latency 3ms -jitter 7ms -error-rate 0.005 -disable A6
```

## Verified against published test data

Correctness of payment crypto is not a matter of opinion, so the tests pin
the implementation to the vectors the standards publish:

| Area | Vector |
|---|---|
| TDES KCV | `0123456789ABCDEFFEDCBA9876543210` → `08D7B4` |
| AES-CMAC | RFC 4493 examples 1–4 |
| PIN block format 0 | PIN 1234, PAN 43219876543210987 → `0412AC89ABCDEF67` |
| DUKPT | X9.24-1 Annex A: IPEK `6AC292FA…D7D5933A`, transaction and PIN keys for counters 1 and 2, encrypted PIN blocks `1B9C1845EB993A7A` and `10A01C8D02C69107` |
| CVV | Visa worked example: PAN 4123456789012345, exp 8701, service 101 → `561` |
| FF1 | NIST SP 800-38G samples 1, 2, 3 and 7 |

Everything without a public vector (PVV, IBM 3624, EMV session keys and
cryptograms, format 4) is covered by structural tests: a single-block retail
MAC must equal TDES, a format 4 block must not decrypt under another PAN, a
terminal and a host must derive the same 300 DUKPT keys, an ARQC must stop
verifying when the amount or ATC changes, and so on.

## The HSM

Keys never leave the HSM in the clear. `A0` generates a key and returns a
**key token**: the key sealed with AES-256-GCM under the local master key
(LMK), with its **type** as additional authenticated data. Commands state
which types they accept, so a CVK cannot be used to translate PINs and
relabelling a token's type breaks its tag. The classic API attacks on HSMs
(using a key in a role it was not meant for) fail with error `27`.

| Cmd | Resp | Function | Fields |
|---|---|---|---|
| `A0` | `A1` | generate key | type → token, KCV |
| `A6` | `A7` | import from clear components (test only; disable in shared envs) | type, comp… → token, KCV |
| `BU` | `BV` | key check value | token → type, KCV |
| `CA` | `CB` | translate PIN block between keys/formats | src key, src fmt, block, PAN, dst key, dst fmt → block, PIN length |
| `G0` | `G1` | translate PIN block from DUKPT | BDK, KSN, block, PAN, dst key, dst fmt → block |
| `DG` | `DH` | generate Visa PVV | PIN key, fmt, block, PAN, PVK, PVKI → PVV |
| `DC` | `DD` | verify PIN against PVV | PIN key, fmt, block, PAN, PVK, PVKI, PVV |
| `DA` | `DB` | verify PIN against IBM 3624 offset | PIN key, fmt, block, PAN, PVK, offset |
| `CW` | `CX` | generate CVV / CVV2 / iCVV | CVK, PAN, YYMM, service code → CVV |
| `CY` | `CZ` | verify CVV | CVK, PAN, YYMM, service code, CVV |
| `KQ` | `KR` | verify ARQC, generate ARPC (method 1) | IMK, scheme 18/10, PAN, PSN, data, ATC, ARQC, ARC → ARPC |
| `T0` | `T1` | tokenize PAN | PAN → token, masked PAN |
| `T2` | `T3` | detokenize | token → PAN |
| `NC` | `ND` | diagnostics | → LMK KCV, version, commands |

Key types: `P0` TDES PIN key (TPK/ZPK), `P1` AES PIN key (format 4), `V0` PVK,
`C0` CVK, `E0` EMV issuer master key, `B0` DUKPT BDK, `D0` data key.

Error codes: `00` ok, `01` verification failed, `04` invalid key type, `10`
parity, `15` invalid input, `20` PIN block error, `23` invalid PIN block
format, `27` key usage violation, `33` invalid key token, `42` DUKPT error,
`68` command disabled, `90` unknown command, `99` internal error (also what
fault injection returns).

Wire format: 2-byte big-endian length, then ASCII `HHHH CC ;field;field…`
(response `HHHH RR EE ;field…`). The header is echoed back. The command
layout is *inspired by* payShield host commands so it feels familiar; it is
not compatible with any vendor's HSM.

### Fault injection

Authorization code has to cope with an HSM that is slow or failing, and
that is exactly what is hard to reproduce. `Faults` adds latency and jitter
(bounded by the caller's context) and a seeded error rate, switchable at run
time with `SetFaults`; `-disable` reproduces a production HSM where most
commands are switched off.

## Library use

```go
// Acquirer side: decrypt a PIN pad's DUKPT PIN block.
ksn, _ := dukpt.ParseKSN("FFFF9876543210E00001")
pk, _ := dukpt.HostKey(bdk, ksn, dukpt.PIN)
pin, err := pinblock.Decrypt(pinblock.Format0, pk, block, pan)

// Issuer side: verify the chip cryptogram.
ok, err := emv.VerifyARQC(imk, pan, "01", tx, emv.CVN18, arqc)

// Over the wire.
c, _ := hsm.Dial(ctx, "localhost:1500")
r, _ := c.Do(ctx, "CY", cvk, pan, "2912", cardauth.ServiceCVV2, "224")
if r.Error == hsm.VerifyFailed { /* decline */ }
```

## Not a security device

This is a simulator. Keys sit in process memory, the LMK is a byte slice, and
`A6` happily imports clear keys. Use it to develop and test against, never to
protect real cardholder data. AES DUKPT (X9.24-3), TR-31 key blocks and
Mastercard session key derivation are on the roadmap.

## .NET

[hsm-sim-dotnet](https://github.com/victorcondackdev/hsm-sim-dotnet) ports the
cryptography and the wire client to .NET 8, checked against vectors generated
from this repository.

## License

MIT
