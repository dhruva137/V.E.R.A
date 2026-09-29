# Vendored schemas (offline validation)

Validation must work on an air-gapped host, so the official schemas live here.
`engine/schema_validation.py` resolves the files against each other locally;
nothing is fetched at runtime.

| Source | Files | Licence |
|---|---|---|
| CycloneDX specification, as shipped in the `cyclonedx-python-lib` 11.12.0 wheel on PyPI (`cyclonedx/schema/_res/`) | `bom-1.7`, `bom-1.6`, `cryptography-defs`, `jsf-0.82`, `spdx` (`.SNAPSHOT.schema.json`, names kept because the schemas `$ref` each other by them) | Apache-2.0 (CycloneDX) |
| OASIS SARIF 2.1.0 schema, errata 01 (`$id` https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json), from the OASIS `sarif-spec` repository | `sarif-schema-2.1.0.json` | OASIS IPR policy (specification schema) |

Known limitation: the CycloneDX 1.7 JSON schema and XSD disagree on
`protocolProperties` (CycloneDX specification issue #1030). V.E.R.A. emits and
validates JSON only and makes no claim of XML validity.

## SHA-256 of each vendored file

| File | SHA-256 |
|---|---|
| `bom-1.6.SNAPSHOT.schema.json` | 83821ba49aa366ad1f1d16c34837d05edd010f036f652e310db1c77d57b37c58 |
| `bom-1.7.SNAPSHOT.schema.json` | dd7942f6a2e93bc3305da220e61a7931cc536fd10ee5fa063809055c6c1c2ffb |
| `cryptography-defs.SNAPSHOT.schema.json` | 027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44 |
| `jsf-0.82.SNAPSHOT.schema.json` | 8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae |
| `sarif-schema-2.1.0.json` | c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e |
| `spdx.SNAPSHOT.schema.json` | ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3 |
