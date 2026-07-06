import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_PATH = re.compile(r"(?<![\w:/.])/(?:[\w.-]+/)*[\w.-]+")
_HOST = re.compile(r"https?://([^/\s:\"'<>]+)")


def extract_entities(text: str, cap: int = 500) -> set[str]:
    """Emails, URLs, hostnames and absolute paths in text, lowercased, at most cap."""
    found: list[str] = []
    for m in _URL.finditer(text):
        found.append(m.group(0).rstrip(".,;"))
    for m in _HOST.finditer(text):
        found.append(m.group(1))
    found += _EMAIL.findall(text)
    found += _PATH.findall(text)
    out: set[str] = set()
    for e in found:
        out.add(e.lower())
        if len(out) >= cap:
            break
    return out
