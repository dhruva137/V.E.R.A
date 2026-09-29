# Demo estate: Tejomaya Bank (synthetic)

One fictional bank, every surface SIH26164 names, and drift planted on purpose.

| Folder | Surface | Plane |
|---|---|---|
| `repos/` | Source in Java, Go, C, Python, TypeScript, C#, Rust + manifests and lockfiles | built |
| `images/` | Two OCI images: base + app layers, a whiteout, a baked-in key marker, a real JAR | built |
| `configs/` | nginx, HAProxy, openssl.cnf, java.security, sshd_config, strongSwan; Terraform in `repos/customer-portal/infra` | declared |
| `captures/` | Recorded TLS and SSH observations of the bank's endpoints | observed |
| `keymanager/` + `../vault/` | KMIP, PKCS#11, cloud KMS, keystores, certificates (metadata only) | held |
| `estate.yaml` | The bank's register: systems, hosts, exposure, criticality, data classes | declared |

Run it: `POST /api/scan/full {"estate": "demo/estate/estate.yaml"}` or press **Scan demo estate** on the Discovery screen.

What the scan finds (pinned by `backend/tests/test_demo_estate.py`): all eight drift rules, D1 to D8. For example: the gateway negotiates TLS 1.0 and 3DES that its nginx config forbids; the ledger ships an OpenSSL 1.1.1w binary against a 3.0.8 manifest; a retired KMIP key still serves; an expired certificate is still served; the bastion's sshd_config lists ML-KEM but the daemon does not offer it; an "internal" ledger answers on a public address.

Nothing here is real. Hosts use `.example` / `.internal` names and RFC 5737 addresses. Binaries are byte blobs with scanner markers, not executables. Key files hold a PEM marker only. Regenerate with `python demo/estate/make_estate.py`; output is byte-identical between runs.
