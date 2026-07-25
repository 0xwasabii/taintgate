from taintgate.entities import extract_entities


def test_extracts_email_url_host_path():
    out = extract_entities("mail bob@Evil.com or see https://evil.com/x and /etc/passwd")
    assert {"bob@evil.com", "https://evil.com/x", "evil.com", "/etc/passwd"} <= out


def test_cap_respected():
    text = " ".join(f"u{i}@x.com" for i in range(2000))
    assert len(extract_entities(text)) == 500


def test_extracts_ibans_domains_and_identifiers():
    out = extract_entities("Send to US133000000121212121212, see www.Evil-Site.com and ref AB12cd34ef")
    assert "us133000000121212121212" in out
    assert "www.evil-site.com" in out
    assert "ab12cd34ef" in out


def test_plain_words_are_not_entities():
    assert extract_entities("Please pay the monthly rent and groceries") == set()
