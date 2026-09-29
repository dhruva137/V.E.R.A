# Stripped binaries for the live detector demo

Four programs from the measured end-to-end set (`research/e2e/`, built by `research/e2e/build_cli.py`): statically
linked and stripped, so no symbols, no imports and no library names. Ground truth comes from the unstripped twin of
the same link and is in `manifest.json`.

- `siphash_x86_64`, `siphash_aarch64`: SipHash-2-4. No signature layer recognises it; the certified learned rung
  finds it (research/results/e2e_product.json).
- `lz4_x86_64`, `xxhash_x86_64`: no cryptography. The detector should report nothing.

`GET /api/detector/live` scans them with the shipped model and calibration and changes nothing in the estate.
