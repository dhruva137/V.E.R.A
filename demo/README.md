# Demo import files

**Founder / CISO walkthrough (no Azure, no AWS, no bank network):**
[`showcase/`](showcase/) — operator script, industry scenarios, offline runner.

```bash
python demo/showcase/make_all.py    # regenerate demo/vault + check invariants
python demo/showcase/run_demo.py    # adapters + HNDL/TNFL + blocked count
```

Live server script (exact curl): [`showcase/README.md`](showcase/README.md).
Synthetic key-manager shapes: [`vault/`](vault/). Optional public TLS: [`live/`](live/).

---

Three files to import live during a walkthrough. Each one goes in through a
route the project already documents, and each was generated from the engine and
tested end to end, so none of them will surprise you on stage.

| File | Import via | Produces |
|---|---|---|
| `cmdb_inventory.csv` | Scanner → CSV import | 22 assets · 15 quantum-vulnerable · 4 classically broken · 3 past deadline |
| `partner_scanner_cbom.json` | Scanner → CBOM import | 22 assets · 12 quantum-vulnerable · 4 classically broken · 0 past deadline |
| `vera_full_estate_cbom.json` | Scanner → CBOM import | 195 assets · 173 quantum-vulnerable · 15 past deadline |

## `cmdb_inventory.csv`

A bank's asset register as it would come out of a CMDB or a spreadsheet — open
it in Excel first and show the columns, because the point of this route is that
it takes what an organisation already has rather than requiring a scan.

Twenty-two rows covering every asset class the model treats differently: TLS
certificates and key exchange, a root CA and an issuing CA, firmware signing
keys in an HSM, payment HSM keys, device identities, token signing, an IPsec
tunnel, database TDE, backups, SSH, code signing, and three unresolved source
call sites.

What to point at once it lands:

- **Tejomaya Root CA G3** comes out `critical` with **-1.6 months** of slack —
  it cannot meet its statutory milestone even starting today. That is the output
  the whole two-axis argument exists to produce.
- The two **firmware signing keys** score the highest QIRS in the estate
  (0.1910) while sitting at `medium` risk. Worth explaining rather than hiding:
  QIRS is the ranking score, risk level also accounts for slack, and they are
  deliberately different questions.
- Four assets escalate to the **CII** persona from the payment-switch and UPI
  signals in their hostnames, above the Banking baseline you selected. That is
  highest-risk-persona-governs, visible in the asset's `persona_source`.
- **3DES**, **DES** and **MD5** rows come back `informational` and classically
  broken — already broken without a quantum computer.

## `partner_scanner_cbom.json`

A CycloneDX 1.6 CBOM as another discovery tool would emit it — the same 22
assets, with V.E.R.A.'s own namespaced properties stripped out and the metadata
attributing it to a third-party scanner.

Import this **after** the CSV to make the complementarity argument concrete: the
same estate, discovered by someone else's tool, scored by the same engine. Note
that it reports **0 assets past deadline** where the CSV reported 3. That is not
a defect — a CBOM records cryptography, not business context, so the tags that
drive persona escalation are not in the file and the deadlines fall back to the
sector baseline you pick in the UI. It is a good answer to "why would I import a
CMDB when I already have a scanner?"

## `vera_full_estate_cbom.json`

V.E.R.A.'s own export of the 195-asset bundled estate, 465 components, 16/16
validation rules passing.

Use this to show the round trip: export a CBOM, hand it to another team, they
import it and get the identical estate back — 195 assets, 173 vulnerable, 15
past deadline, mean QIRS 0.1159, maximum 0.1910. Every headline figure in the
documentation is reproduced exactly.

## Regenerating these

They are ordinary outputs, not fixtures:

```bash
curl -s http://127.0.0.1:8000/api/cbom -o demo/vera_full_estate_cbom.json
```
