# V.E.R.A. (vera-cbom)

Verified Enumeration of Risky Algorithms: cryptographic discovery that produces a CycloneDX 1.7 CBOM (cryptographic bill of materials), including from stripped binaries.

V.E.R.A. is research software, developed and maintained by one person, and it is in development. Interfaces and results may change between versions.

## What it does

It looks for cryptographic assets in source code, dependencies, compiled binaries, container images, configuration, keystores, certificates, HSM / KMIP / cloud key services, and live TLS and SSH. For findings that come from compiled code (including stripped binaries with no source and no symbols) it attaches a q-value, a bound on how often such findings are wrong. That bound is carried into the CBOM, which is checked against CERT-In's Table 9 and can be signed with the post-quantum signature ML-DSA-65.

It runs offline by default, reads metadata only (no key material is read or stored), and every reported number carries its source.

## Install

```bash
pip install vera-cbom                 # engine and CLI (`vera`)
pip install "vera-cbom[server]"       # adds uvicorn, to run the API server (`vera serve`)
pip install "vera-cbom[mcp]"          # adds the MCP adapter
pip install "vera-cbom[all]"          # everything above
```

Python 3.11 or newer.

## Quick start

```bash
vera scan --source ./my-project --binary ./build/app -o cbom.json
vera version
```

`vera serve` starts the API and OpenAPI docs on http://127.0.0.1:8000/docs (needs the `server` extra). Writable state lives under `~/.vera`; set `VERA_HOME` to change it.

## Highlights

- 11 collectors across four evidence planes; output as CycloneDX 1.7 (and 1.6) CBOM, SARIF 2.1.0 and a PDF report, with an ML-DSA-65-signed evidence manifest and a hash-chained audit log.
- A binary detector with a conformal false-discovery-rate bound, evaluated on IndiCrypt-Bench (30 libraries, 4 toolchains, 128,288 labelled functions, 8 sealed crypto libraries). It runs on a CPU and covers x86-64, AArch64 and ARM32.
- Quantum-risk scoring per asset (Mosca's inequality with a per-primitive horizon) and post-quantum migration recommendations.

Results, limits and the evaluation protocol are described in the repository README and the `research/` folder.

## Links

- Homepage: https://papertoanything.com/products/vera/
- Repository: https://github.com/dhruva137/V.E.R.A
- Benchmark: https://github.com/dhruva137/indicrypt-bench
- Documentation: https://github.com/dhruva137/V.E.R.A#readme

Part of Paper To Anything (https://papertoanything.com), research software developed and maintained by Dhruva P Gowda.

## Licence

To be announced.
