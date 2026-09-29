# Demo script: seven minutes, offline, one laptop

This script runs the demo beat by beat, on the redesigned screens. Each beat below
says where to click, what the screen shows, and the one line to say. The numbers are from the bundled demo
estate, measured on 2026-09-25. Before going on stage, run `.\run.ps1 -Rehearse` (or
`python scripts/rehearse.py`). It checks every beat against the running engine and prints the numbers to say. If a
number here differs from the rehearsal output, say the rehearsal's number.

## Before the judges arrive
1. Run `.\run.ps1`. Wait for API, dashboard and model to show "up" and "warm".
2. Sign in as the admin. Open **Settings → Runtime**. All three posture facts should be green: read-only
   assistant, local qwen3:1.7b, offline enforced.
3. Open **Scan** and run the demo estate once, so the second run on stage is the same as the rehearsal.
4. Set **Display** to Light, 100%, English. Close the assistant panel.

## The seven minutes

| Min | Click | The screen shows | Say |
|---|---|---|---|
| 0:00 | The top bar: *3 of 3 safeguards on* | Read-only assistant, local model, offline guard, each with its reason | "Nothing leaves this laptop, and no key is ever read." |
| 0:30 | **Scan** → Run scan (demo register) | Each surface reads live: 52 collector runs over 15 targets, then 229 findings resolved to 219 assets | "Code, libraries, binaries, containers, configs, keys, key managers and recorded traffic, in one pass." |
| 1:00 | **Open the overview** | "138 of 219 are quantum-vulnerable; 52 will be exposed before they can be migrated." Foundations milestone 98 days away, CBOM at 91.7% of CERT-In's elements | "This is the answer for the CISO and the assessor on one screen. Every number says where it came from." |
| 1:30 | **Inventory** → Evidence filter → open a certificate seen on two planes | The asset panel: the file location, the live endpoint, and the confidence of each | "One asset, several kinds of evidence, one record." |
| 2:15 | **Risk → Policy drift** → D1 | The config allows only TLS 1.2 and 1.3; the live handshake negotiated TLS 1.0 | "Intent against reality, caught automatically." |
| 3:00 | **Risk → Quantum exposure** | P-256's CRQC band sits before RSA-3072's, each with its published qubit estimate | "The quantum clock isn't the same for every algorithm. This is 2026 research." Move the doubling-time slider to show the what-if, then reset it. |
| 4:00 | **Plan → Actions** → NIST / CNSA 2.0 | Key exchange: X25519MLKEM768 against ML-KEM-1024; the latency measured on this laptop; "upgrade OpenSSL to 3.5" as a prerequisite; 142 changes, 609 person-days at the declared rate | "The cheapest fix is often a version bump. Here is the measured cost, and the budget." |
| 5:00 | **Plan → Suppliers** | Luna Network HSM 7 has no PQC firmware, so three assets wait on the vendor. The contract clause is ready to copy | "The blocker is often the vendor. This drafts the clause for procurement." |
| 5:45 | **Evidence → Integrity** → Verify now, then **CERT-In conformance** | Signature verified with ML-DSA-65, the CBOM hash matches, the audit chain is intact; Table 9 element by element | "The evidence protects itself with the algorithm it recommends, and it shows exactly which CERT-In fields the sources did not record." |
| 6:30 | Press `/` and ask "migrate 200 assets" | The read-only assistant refuses. In approval mode the same request stops at the 25-asset cap | "AI with guardrails, off by default. Every step is in the audit chain with a name on it." |

## If something goes wrong
- **The model is slow or down.** The assistant's router answers the scripted questions without the model. Say so:
  "Known questions do not need the model."
- **A scan fails partway.** The Scan screen lists the failing collector and its reason. Say that this is the point:
  a failure is shown, never folded into a total.
- **The projector is dim.** Open Display and choose Dark, or text size A+. Both are tested for contrast.
