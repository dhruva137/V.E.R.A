# SIH26164 (NTRO): PS coverage, clause by clause

Every row names where it is implemented, what tests it, and what was measured, with the result file and the
commit that produced it. "Declared" means the value comes from a source system or an input the operator states
(for example a day rate), not from a measurement.

## (i) Identify and catalogue all cryptographic artefacts

| Artefact | Implementation | Tests | Evidence (measured unless marked) |
|---|---|---|---|
| Algorithms | `collectors/source_scanner.py` (tree-sitter, 7 languages), `config_scanner.py`, `binary_scanner.py` | `test_source_scanner`, `test_config_scanner`, `test_binary_scanner` | Detection corpus, first run before any tuning on the held-out split: precision 0.889, recall 0.889, F1 0.889 (`bench/results.json`, commit ce55ccc) |
| Algorithms in stripped binaries | learned rung, `engine/binary_ml/detector.py` (688 KB model, conformal q-value per function) | `test_binary_ml_detector`, `test_binary_ml_conformal`, `test_binary_ml_theory` | End to end on the **shipped** model: shipped model through the product scan path: 14/16 stripped static crypto programs found, 0/14 false alarms, 2 found only by the learned rung, 0.36 s median (`research/results/e2e_product.json`, commit 1e8639e) |
| Keys | `collectors/vault_collector.py` (PKCS#11, KMIP 2.1, keystores), `keystore_scanner.py`, `secret_scanner.py` (fingerprints only) | `test_vault_collector` (incl. `test_no_pem_body_survives_into_any_finding`) | No key material is read or stored; guarantee in `engine/intake/scrub.py` |
| Certificates | `keystore_scanner.py`, live TLS, embedded certificates in binaries, container trust stores | `test_container_scanner`, `test_drift_and_resolution` | Trust store found in both real images (`research/results/container_e2e.json`) |
| Protocols | live TLS (`tls_scanner.py`), live SSH KEXINIT (`ssh_scanner.py`), nginx/Apache/HAProxy/OpenSSH/strongSwan/swanctl configs | `test_ssh_scanner`, `test_config_scanner` | IKE and SSH methods named, versions stated or marked unknown |
| Libraries, with versions | `dependency_scanner.py` (9 ecosystems), binary linkage, container package DBs; one asset per library per image (`engine/core/resolution.py`) | `test_dependency_scanner`, `test_versionless_library_takes_the_one_known_version_in_its_image` | Real images: `OpenSSL 3.3.7` (alpine:3.20) and `OpenSSL 3.3.3` (nginx:1.27-alpine), read from `lib/apk/db/installed`. Before the fix each image also listed a second `OpenSSL unknown` (`container_before_fix.json`) |
| Hardware modules | PKCS#11 token and mechanism list; a token without PQC mechanisms marks its keys change-blocked | `test_hsm_without_pqc_mechanisms_marks_assets_change_blocked` | Demo vault in native response shapes (synthetic, declared) |
| Cloud services | AWS KMS DescribeKey, Azure Key Vault keys, GCP CryptoKeyVersion; Terraform KMS/ACM; cloud certificate services (AWS ACM DescribeCertificate, Azure Key Vault certificates, GCP Certificate Manager; `test_cloud_certificate_services_parse_from_their_own_api_shapes`) | `test_vault_collector`, `test_terraform_kms_acm_tls_and_policies` | Parses each provider's own API response shape; not exercised against a live cloud account (the tool is offline by design) |
| Internal vs external | plane and exposure tagging (observed address preferred over declared) | `test_exposure_prefers_the_observed_address` | |

## (ii) Quantum risk assessment

| Clause | Implementation | Tests | Evidence |
|---|---|---|---|
| Systems prone to quantum attack | two axes, harvest-now-decrypt-later and trust-now-forge-later, per primitive (`engine/qirs.py`, `threat_model.py`) | `test_risk_model`, `test_qirs_profile` | Each primitive's break horizon cites its published qubit estimate (`engine/kb/quantum_resources.yaml`) |
| Risks to sensitive data | data classification sets X (shelf life) per asset | `test_mosca` | Classes and defaults in `engine/kb/data_classes.yaml` (declared) |

## (iii) Classify by type, lifetime, criticality; Mosca

| Clause | Implementation | Tests | Evidence |
|---|---|---|---|
| Type, lifetime, criticality | asset class, certificate lifetime, criticality tags, persona | `test_inventory_view` | Inventory facets in the GUI |
| Mosca X + Y vs Z | per asset and per primitive, Y on India's statutory schedule (`engine/mosca.py`, `engine/regulatory.py`) | `test_mosca` (10 tests incl. monotonicity) | DST, *Implementation of Quantum Safe Ecosystem in India* (Feb 2026): CII 2027/2028/2029, enterprises 2028/2030/2033; slack reported in months |

## (iv) Recommend PQC / hybrid alternatives by risk profile, latency, cost

| Clause | Implementation | Tests | Evidence |
|---|---|---|---|
| Alternatives | NIST FIPS 203/204/205 (+ HQC selected 2025) and CNSA 2.0 profiles, hybrid first where the peer may be classical (`engine/recommendations.py`) | `test_recommendations`, `test_profiles_and_pqc` | Every vulnerable asset gets at least one recommendation with its source clause |
| Latency | measured on the host with OpenSSL 3.5.4 (`bench/pqc_bench.py`) | `test_bench_floors` | ML-KEM-768 encapsulate 31.2 us, decapsulate 49.1 us vs X25519 derive 50.3 us; ML-DSA-65 sign 1,555 us vs RSA-2048 sign 375 us (`bench/pqc_bench.json`, 24 Sep 2026) |
| Size on the wire | FIPS 203/204 parameter sizes | | ML-KEM-768 public key 1,184 B, ciphertext 1,088 B; ML-DSA-65 public key 1,952 B, signature 3,309 B (from the standards) |
| Cost | declared person-days x declared day rate, plus who can fix it (team, HSM vendor, cloud provider) (`engine/cost_model.py`) | `test_overview_cost` | Declared, not measured; shown as such in the GUI |

## Deliverables

| Deliverable | Implementation | Evidence |
|---|---|---|
| Scan source repositories | Git repo or folder | Corpus above |
| Scan binaries | ELF / PE / Mach-O / JAR; x86-64, AArch64, ARM32 | shipped model through the product scan path: 14/16 stripped static crypto programs found, 0/14 false alarms, 2 found only by the learned rung, 0.36 s median (`research/results/e2e_product.json`, commit 1e8639e) |
| Scan libraries | dependency scanner + linkage | versions above |
| Scan container images | OCI / docker-save, layer-aware | Two real Docker Hub images (digest-verified, `research/e2e/fetch_image.py`) scanned through the product API: alpine:3.20 8 assets, nginx:1.27-alpine 38 assets, both CBOMs valid against the CycloneDX 1.7 schema with 0 violations (`research/results/container_e2e.json`) |
| Report with versions / modes, standard formats | CycloneDX 1.7 (and 1.6) CBOM, SARIF 2.1.0, signed evidence manifest, PDF | nginx: AES modes present on 20 of 20 block-cipher components (0 of 6 before the fix); named `AES-128-GCM`, `AES-256-CBC`, etc. CERT-In Table 9 conformance 96.2% of required elements on the nginx CBOM (85.4% before modes and their OIDs were recorded; `container_e2e.json`, commit 1e8639e) |
| CERT-In CBOM / QBOM | element-by-element conformance to CERT-In Technical Guidelines v2.0 (9 Jul 2025), Table 9 (`engine/certin.py`) | `test_certin_cbom` |
| Interactive GUI | React, 7 screens (Overview, Scan, Inventory, Risk, Plan, Evidence incl. Detector, Settings), EN/HI, WCAG AA (axe-core) | `docs/screens/` |

## What is not covered (stated plainly)

- Cloud accounts are read from exported API responses, not by calling the cloud (offline by design).
- Mode is recorded when the evidence names it (a symbol such as `EVP_aes_256_gcm`, a JCA transformation, a cipher
  suite). A binary that implements AES without naming the mode gets no mode rather than a guess.
- Cost is declared, not measured.
- The learned binary rung's guarantee assumes calibration and deployment code are exchangeable. We measured a
  violation: non-crypto helpers inside Argon2 and libsodium exceed the calibration 95th percentile 17-22% of the
  time (5% expected) (`research/SELF_AUDIT.md`, 0.2b).
