"""Generate the unencrypted sample PDF used in manual encryption tests."""
from pathlib import Path

from fpdf import FPDF


def main() -> None:
    output = Path(__file__).resolve().parent.parent / "sample_plain.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, "Sample PDF for encryption tests.")
    pdf.output(str(output))
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
