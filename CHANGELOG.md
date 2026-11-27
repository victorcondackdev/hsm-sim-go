# Changelog

## 0.1.0 — 2026-11-27

- `keys`: TDES/AES ECB and CBC, parity, KCV (TDES and AES CMAC), key components, ISO 9797-1 MAC algorithms 1 and 3, AES-CMAC and TDES-CMAC.
- `pinblock`: ISO 9564-1 formats 0–4.
- `dukpt`: ANSI X9.24-1:2009 TDES DUKPT with PIN, MAC and data variants and a terminal model.
- `cardauth`: CVV/CVV2/iCVV, Visa PVV, IBM 3624.
- `emv`: ICC key derivation option A, EMV common session keys, ARQC (CVN 18 and 10), ARPC methods 1 and 2.
- `fpe`: FF1.
- `tokenize`: in-memory token vault.
- `hsm`: command processor, usage-bound LMK key tokens, wire protocol, TCP server and client, fault injection.
- `cmd/hsm-sim`, `cmd/hsm-demo`, Dockerfile.
