from taintgate.entities import extract_entities


def test_extracts_email_url_host_path():
    out = extract_entities("mail bob@Evil.com or see https://evil.com/x and /etc/passwd")
    assert {"bob@evil.com", "https://evil.com/x", "evil.com", "/etc/passwd"} <= out


def test_cap_respected():
    text = " ".join(f"u{i}@x.com" for i in range(2000))
    assert len(extract_entities(text)) == 500
