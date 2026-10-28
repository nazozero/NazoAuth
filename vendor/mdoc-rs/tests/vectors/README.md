# Test vectors

## `iso_18013_5_annex_d_mdl.hex`

The ISO/IEC 18013-5 **Annex D** example mDL `DeviceResponse`, as a hex string.

- **Source:** the `ISSUED_MDOC` constant in `pyMDOC-CBOR`
  (`pymdoccbor/tests/test_01_mdoc_parser.py`), which embeds the canonical
  Annex-D credential.
- **Issuer:** leaf "utopia ds" signed by the "utopia iaca" root (the root is
  **not** in the `x5chain`, so full chain anchoring cannot be exercised from this
  vector alone).
- **Device auth:** a real `deviceMac` (COSE_Mac0) block.
- **Validity:** `validFrom` 2020-10-01 … `validUntil` 2021-10-01 (expired), so a
  full `is_valid` verdict at today's date will fail on MSO validity even with the
  right anchors.

Used by `tests/interop_test.rs` to validate, against a genuine conformant issuer:
parsing, Tag-24-wrapped `valueDigests` matching (audit MEDIUM-1), full-date
(Tag 1004) / tdate (Tag 0) parsing, and issuer COSE_Sign1 signature verification.
