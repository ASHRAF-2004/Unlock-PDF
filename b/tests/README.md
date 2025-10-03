# Encryption Test Assets

This directory contains small helper assets that make it easy to manually verify the `pdf_password_retriever`
executable against several PDF encryption handlers supported by the project.

## Contents

- `pdfs/` – encrypted variants of a single-page sample PDF generated with [FPDF](https://pyfpdf.github.io/fpdf2/).
  Each file uses `Secret1` as the user password and `OwnerSecret` as the owner password.
  - `PDF_ENCRYPT_RC4_40.pdf` – legacy RC4 security handler with a 40-bit key.
  - `PDF_ENCRYPT_RC4_128.pdf` – legacy RC4 handler upgraded to a 128-bit key.
  - `PDF_ENCRYPT_AES_128.pdf` – AES-128 encryption (Revision 4 / AESV2 crypt filter).
  - `PDF_ENCRYPT_AES_256_CBC.pdf` – AES-256 encryption (Revision 6 / AESV3 crypt filter).
- `wordlists/` – lightweight wordlist used for smoke tests (`Secret1` is included among a few decoy entries).

## Regenerating the PDFs

The encrypted files can be reproduced with [qpdf](https://qpdf.sourceforge.io/) using the commands below. Start by
regenerating `sample_plain.pdf`, the unencrypted base document produced by the FPDF script in the repository root.
Install the Python dependency once (FPDF v2) and then run the helper:

```bash
python -m pip install --user fpdf2
python scripts/create_sample_plain_pdf.py
```

Then run the following commands to create the encrypted variants:

```bash
# RC4 (40-bit)
qpdf --allow-weak-crypto --encrypt Secret1 OwnerSecret 40 -- sample_plain.pdf tests/pdfs/PDF_ENCRYPT_RC4_40.pdf

# RC4 (128-bit)
qpdf --allow-weak-crypto --encrypt Secret1 OwnerSecret 128 --use-aes=n -- sample_plain.pdf tests/pdfs/PDF_ENCRYPT_RC4_128.pdf

# AES-128
qpdf --encrypt Secret1 OwnerSecret 128 --use-aes=y -- sample_plain.pdf tests/pdfs/PDF_ENCRYPT_AES_128.pdf

# AES-256 (CBC/AESV3)
qpdf --encrypt Secret1 OwnerSecret 256 -- sample_plain.pdf tests/pdfs/PDF_ENCRYPT_AES_256_CBC.pdf
```

> **Note:** qpdf 11.9.0 cannot generate PDF 2.0 AES-GCM, RMS/LiveCycle, or vendor-specific custom security handlers.
> Those formats are therefore not included in this quick regression set.
