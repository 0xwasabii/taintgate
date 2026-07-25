import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_PATH = re.compile(r"(?<![\w:/.])/(?:[\w.-]+/)*[\w.-]+")
_IBAN = re.compile(r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}\b")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
_ID = re.compile(r"\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{6,}\b")
_HOST = re.compile(r"https?://([^/\s:\"'<>]+)")


def extract_entities(text: str, cap: int = 500) -> set[str]:
    """Emails, URLs, hosts, domains, IBANs, mixed letter/digit identifiers and absolute paths, lowercased, at most cap."""
    found: list[str] = []
    for m in _URL.finditer(text):
        found.append(m.group(0).rstrip(".,;"))
    for m in _HOST.finditer(text):
        found.append(m.group(1))
    found += _EMAIL.findall(text)
    found += _IBAN.findall(text) + _DOMAIN.findall(text) + _ID.findall(text)
    found += _PATH.findall(text)
    out: set[str] = set()
    for e in found:
        out.add(e.lower())
        if len(out) >= cap:
            break
    return out
