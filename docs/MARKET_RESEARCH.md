# Market research: cryptographic discovery and PQC readiness

Researched September 2026. Every claim below has a source at the end. Vendor capabilities come from the vendors'
own public pages, not from hands-on testing, so they describe what each vendor *says* its product does. Where we
found no public statement, we say that. We don't say a capability is absent.

## 1. Why buyers need this now

India's rules are now specific, and they name the product category.

- **DST task force report, "Implementation of Quantum Safe Ecosystem in India" (4 Feb 2026).**
  - *Milestones.* CII in defence, power and telecom must build foundations by 31 Dec 2027, migrate high-priority
    systems by 31 Dec 2028 and reach full PQC adoption by 31 Dec 2029. Other enterprises follow 2028, 2030 and 2033 [1].
  - *Inventory comes first.* Milestone 1 says: "Complete discovery and inventory of cryptographic artefacts" [1].
  - *Procurement.* Organisations should start asking vendors for CBOMs and quantum-resiliency roadmaps from FY 2026–27.
    From FY 2027–28, vendor CBOM submission becomes mandatory [1].
  - *The Indian product list.* The report says the national list of cryptography-dependent products should add
    "automated cryptographic discovery and inventory solutions" [1].
  - *Indigenous preference.* Under Preferential Market Access, public and private procurement should prefer
    indigenously developed solutions [1].
  - *Certification.* A national PQC testing and certification programme is proposed by December 2026 [1].
    Verification of software and cryptographic components will use the SBOM, CBOM and QBOM frameworks notified
    by CERT-In [1].
- **European Union (June 2025).** Member States start national transitions, including cryptographic inventories,
  by the end of 2026. High-risk and critical-infrastructure use cases move by the end of 2030, and as much as is
  feasible by 2035 [2].
- **United Kingdom, NCSC (March 2025).** Discovery and assessment by 2028, high-priority migration by 2031, full
  transition by 2035 [1, 3].
- **United States.** NIST IR 8547 (initial public draft, Nov 2024) proposes deprecating 112-bit RSA and ECC after
  2030 and disallowing RSA and ECC entirely after 2035 [4]. Until the final version is published, these are proposed
  dates.

**What this means for the product.** The first deliverable every regulator asks for is an inventory. In India
it has to be a machine-readable CBOM that a vendor or operator can submit. Both the DST report and the CERT-In
frameworks it cites name that format.

## 2. Market size (analyst estimates; directional only)

| Source | Estimate |
|---|---|
| MarketsandMarkets (2025) | USD 0.42 bn (2025) to USD 2.84 bn (2030), 46.2% CAGR [5] |
| Mordor Intelligence | USD 0.88 bn (2025) to USD 4.60 bn (2030), 39.2% CAGR [6] |
| Grand View Research | USD 1.6 bn (2025) to USD 20.5 bn (2033), 37.8% CAGR from 2026 [7] |

The 2025 base figures differ by roughly 4x, because each firm draws the market's boundary differently. Treat them
as evidence of fast growth, not as a size to plan revenue against. None of them splits out discovery and
inventory as its own segment.

## 3. Who else does this

| Product | Discovery surfaces (as publicly described) | Notes |
|---|---|---|
| **IBM** Guardium Quantum Safe / Guardium Cryptography Manager / Quantum Safe Explorer | Application code scanning with CBOM output. Ingests network scanners, Kubernetes, Vault certificates, Qualys/Nessus and external CBOMs [8, 9] | Enterprise platform, part of the Guardium family |
| **SandboxAQ** AQtive Guard | Passive network analyser (TLS), runtime tracer for crypto calls (e.g. JVM), filesystem and container-image scanner, correlated into one inventory [10, 11] | Absorbed Cryptosense. Policy checks against FIPS 140, PCI DSS and PQC [10] |
| **Keyfactor** AgileSec Analytics + CipherInsights | Devices, source code, binaries, file systems, applications, cloud workloads. CipherInsights adds passive network monitoring [12] | Came from the May 2025 acquisitions of InfoSec Global and CipherInsights. Bundled with PKI and certificate lifecycle management |
| **QNu Labs** QShield 2.0 (India) | Automated cryptographic asset discovery and key lifecycle management. Built for air-gapped and sovereign deployments [13] | Launched September 2026. Indian vendor, relevant to Preferential Market Access |
| **CBOMkit** (PQCA; open source, originally IBM) | Source code through the Sonar cryptography plugin (Java, Python, Go), producing a CycloneDX CBOM [14, 15] | Open source. Code only |
| **cdxgen** (OWASP; open source) | SBOM generator that can also emit a CBOM for Java and Python projects [16] | Open source. Dependency-centred |


## 4. Where V.E.R.A. fits

What an Indian CII operator needs, per [1], compared with what V.E.R.A. does today (see `README.md` for measured numbers):

| Need (source) | V.E.R.A. |
|---|---|
| Discovery and inventory across the estate [1] | 11 collectors on 4 evidence planes: source (7 languages), dependencies, binaries, containers, configs, keystores, secrets, vault/HSM/KMS metadata, TLS, SSH, recorded captures |
| CBOM in a standard, submittable format [1] | CycloneDX 1.7 (1.6 kept), validated offline against the official schema, deterministic output, signed manifest |
| Indigenous, deployable air-gapped [1] | Runs offline by default (`VERA_OFFLINE=1` socket guard), with a local model for the agent; no cloud dependency |
| Prioritisation against national deadlines [1] | Per-asset slack against the DST milestones, Mosca X/Y/Z with a per-primitive quantum-resource shift from cited estimates |
| Vendor accountability in procurement [1] | A who-can-fix register (self-managed, vendor-firmware-gated, provider-gated, third-party) and draft procurement clauses for legal review |
| Auditability [1] | Hash-chained audit log covering scans, exports, settings and every agent action; tamper detection is tested |

**Our differentiators, stated narrowly.** Among the public materials we reviewed, we found none that combined all
five of the following:

1. declared, built, held and observed evidence reconciled with explicit drift rules;
2. a signed evidence manifest;
3. a vendor-gated register tied to procurement;
4. per-asset slack against the Indian milestones;
5. a governed agent that is local by default, with a measured tool-selection accuracy (`bench/agent_results.json`).

That is a claim about what we found, not proof that these features are missing elsewhere.

**Where incumbents are ahead.** They offer runtime instrumentation of live applications (SandboxAQ's tracer),
integrated certificate lifecycle management and PKI (Keyfactor), large-scale enterprise integrations (IBM), and
commercial support. V.E.R.A. reads code, artefacts, configurations, metadata and recorded or probed handshakes. It
does not instrument running processes.

## 5. Risks to the case

- **Bundling.** Incumbents sell discovery as an entry point to PKI or data-security platforms, and may give it away.
- **Trust in findings.** A false positive in a CII audit costs credibility. That's why held-out precision and recall
  are published (WP12), not asserted.
- **Format churn.** CycloneDX moved from 1.6 to 1.7 within a year. V.E.R.A. emits both and validates both against the
  vendored official schemas.
- **Certification.** The proposed national PQC testing and certification programme [1] may add evaluation
  requirements that apply to tools as well as products.

## Sources

1. DST, *Implementation of Quantum Safe Ecosystem in India: Report of the Task Force* (4 Feb 2026). Milestones on
   report pp. 13 and 18. Procurement and CBOM on pp. 13, 19 and annexure C. Product list on pp. 11 and 20.
   https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20(v1).pdf
2. European Commission, *EU reinforces its cybersecurity with post-quantum cryptography* (23 Jun 2025).
   https://digital-strategy.ec.europa.eu/en/news/eu-reinforces-its-cybersecurity-post-quantum-cryptography
3. NCSC (UK), *Timelines for migration to post-quantum cryptography* (Mar 2025), as summarised in [1], §4.
4. NIST IR 8547 ipd, *Transition to Post-Quantum Cryptography Standards* (Nov 2024).
   https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
5. MarketsandMarkets, *Post-quantum Cryptography Market* press release.
   https://www.marketsandmarkets.com/PressReleases/post-quantum-cryptography.asp
6. Mordor Intelligence, *Post-Quantum Cryptography Market*.
   https://www.mordorintelligence.com/industry-reports/post-quantum-cryptography-market
7. Grand View Research, *Post-Quantum Cryptography Market Size Report, 2026–2033*.
   https://www.grandviewresearch.com/industry-analysis/post-quantum-cryptography-market-report
8. IBM, *Quantum-safe Discovery and Assessment* (Partner Plus directory). https://www.ibm.com/partnerplus/directory/solution/0820
9. IBM, *Guardium Cryptography Manager*. https://www.ibm.com/products/guardium-cryptography-manager
10. SandboxAQ, *Security Suite: Discover*. https://www.sandboxaq.com/solutions/security/discover
11. AQtive Guard User Guide. https://docs.aqtiveguard.com/
12. Keyfactor, *Keyfactor Acquires InfoSec Global and CipherInsights* (May 2025).
    https://www.keyfactor.com/press-releases/keyfactor-acquires-infosec-global-and-cipherinsights/
13. The Quantum Insider, *QNu Labs Launches QShield 2.0* (21 Sep 2026).
    https://thequantuminsider.com/2026/09/21/qnu-labs-qshield-2-cryptographic-assessment-assurance/
14. PQCA, *PQCA announces CBOMkit* (2025).
    https://pqca.org/blog/2025/pqca-announces-cbomkit-advanced-tools-for-generating-and-analyzing-cryptographic-bills-of-materials/
15. PQCA, sonar-cryptography. https://github.com/PQCA/sonar-cryptography
16. OWASP cdxgen. https://github.com/cdxgen/cdxgen
