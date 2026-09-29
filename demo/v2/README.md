# v2 demo data

Nine sector estates, one per profile the engine supports. Upload one and the
whole product re-shapes around it: the fit verdict, the required sensors, the
regulations cited, the board framing and the milestone calendar all change.

**Everything here is synthetic.** No host, serial, key or organisation is real.
What is *not* synthetic is the shape: each estate is generated from the asset
composition the sector profile declares (`backend/engine/profiles.py`), so a
payments estate really is HSM-heavy and an industrial one really is dominated by
device identities. The generator reads the same numbers the product is judged
against, which is what stops the demo being staged.

## The files

| File | Assets | Dominant classes |
|---|---|---|
| `payments_estate.csv` | 400 | TLS certs, key exchange, **payment HSM** |
| `banking_estate.csv` | 400 | TLS, database TLS, HSM, archives |
| `erp_estate.csv` | 400 | TLS, **token signing**, config |
| `saas_estate.csv` | 400 | TLS, token signing, **code signing** |
| `industrial_estate.csv` | 400 | **device identity**, **firmware signing**, config |
| `healthcare_estate.csv` | 400 | TLS, **backup encryption**, database TLS |
| `telecom_estate.csv` | 400 | TLS, **device identity**, VPN/IPsec |
| `energy_estate.csv` | 400 | **device identity**, config, firmware signing |
| `government_estate.csv` | 400 | TLS, token signing, archives, source |

Each carries a deliberate ~15% ownership gap, because "nobody knows who owns
this key" is a real migration blocker and the product reports it rather than
leaving the column blank.

## How to use it in a demo

1. **Settings → Sector** — choose the sector you are demonstrating. This is the
   only place the sector is set; everything else follows it.
2. **Discovery → Import CSV** — upload the matching estate. Use *replace*, not
   merge, unless you deliberately want two sectors in one estate.
3. **Dashboard** — the fit verdict now speaks in that sector's language and
   names its regulator.
4. **Engine** — run the pipeline. Watch the six stages light up, the output
   checks, the Mosca categories, and which assets are flagged for verification.

### The moment worth rehearsing

Import `payments_estate.csv`, then open the dashboard. The verdict reads:

> *"Not audit-ready for a Payments / PSP / acquirer: the required sensor
> hsm_pkcs11 is not connected, so part of the estate that this vertical is
> judged on has not been measured."*

The product is telling the buyer its own inventory is incomplete. That is the
thing no competitor does, and it is why they trust the rest of the numbers.

Then switch the sector to ERP in Settings and the same estate is judged against
a different standard, with a different verdict. Same engine, no code change.

## Regenerating

```bash
python demo/v2/make_sector_estate.py <sector> <count>
```

Sectors: `payments banking erp saas industrial healthcare telecom energy government`

The generator is seeded, so the same arguments produce the same estate every
time and two runs are comparable.

## A note on the post-quantum entries

Post-quantum assets are written with their FIPS parameter set — `ML-KEM-768`,
`ML-DSA-65` — never as a bare `ML-KEM`. The taxonomy treats an unqualified name
as underspecified and refuses to call it quantum-safe. That is correct, and the
generator respects it rather than working around it: a demo that quietly
inflates its own PQC-readiness number would be exactly the dishonesty this
product exists to remove.
