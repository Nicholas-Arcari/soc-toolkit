import fitz  # PyMuPDF

from core.ioc.text_extractor import extract_from_text


def extract_from_pdf(content: bytes) -> list[dict]:
    """Extract IOCs from a PDF file (e.g., threat intelligence reports)."""
    text = _pdf_to_text(content)
    return extract_from_text(text)


def _pdf_to_text(content: bytes) -> str:
    """Extract text from PDF bytes."""
    doc = fitz.open(stream=content, filetype="pdf")
    pages = []

    for page in doc:
        pages.append(page.get_text())

    doc.close()
    return "\n\n".join(pages)
