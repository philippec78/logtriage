"""Extraction PDF isolée : aucune commande ni ressource distante issue du PDF."""
import io
import json
import sys


def main():
    # Bornes du sous-processus, indépendantes de la connexion IMAP et de SQLite.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        if sys.platform == "linux":
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    except (ImportError, ValueError, OSError):
        pass
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(sys.stdin.buffer.read()))
        if reader.is_encrypted:
            raise ValueError("PDF chiffré")
        max_pages, max_chars = int(sys.argv[1]), int(sys.argv[2])
        texts, total = [], 0
        incomplete = len(reader.pages) > max_pages
        for page in reader.pages[:max_pages]:
            text = page.extract_text() or ""
            remaining = max_chars - total
            texts.append(text[:remaining])
            total += len(text[:remaining])
            if len(text) > remaining or total >= max_chars:
                incomplete = True
                break
        text = "\n".join(texts)
        print(json.dumps({"text": text, "pages": len(reader.pages),
                          "incomplete": incomplete or not text.strip()}))
    except Exception:
        # Ni contenu du document, ni exceptions potentiellement sensibles dans les logs.
        print(json.dumps({"text": "", "incomplete": True, "error": "pdf_illisible"}))


if __name__ == "__main__":
    main()
