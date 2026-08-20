import pytest

from validation import InvalidTarget, normalize_target


@pytest.mark.parametrize(
    "raw,expected_type,expected",
    [
        ("8.8.8.8", "ip", "8.8.8.8"),
        ("  8.8.8.8  ", "ip", "8.8.8.8"),
        ("185.220.101.42", "ip", "185.220.101.42"),
        ("2606:4700:4700::1111", "ip", "2606:4700:4700::1111"),
        ("[2606:4700:4700::1111]:443", "ip", "2606:4700:4700::1111"),
        ("example.com", "domain", "example.com"),
        ("EXAMPLE.COM", "domain", "example.com"),
        ("example.com.", "domain", "example.com"),
        ("https://example.com/path?q=1", "domain", "example.com"),
        ("http://sub.example.co.uk", "domain", "sub.example.co.uk"),
        ("example.com:8080", "domain", "example.com"),
    ],
)
def test_accepts_valid_targets(raw, expected_type, expected):
    target_type, normalized = normalize_target(raw)
    assert (target_type, normalized) == (expected_type, expected)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        # 這四個都是線上真實出現過的輸入,每一筆都完整燒掉一次 LLM 呼叫。
        "185",
        "185.",
        "123.456.123.456",
        "localhost:8000",
        "not a domain",
        "-bad.example.com",
        "com",
    ],
)
def test_rejects_invalid_targets(raw):
    with pytest.raises(InvalidTarget):
        normalize_target(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1",       # loopback
        "192.168.1.1",     # 私有網段
        "10.0.0.1",        # 私有網段
        "172.16.0.1",      # 私有網段
        "169.254.1.1",     # link-local
        "0.0.0.0",         # unspecified
        "224.0.0.1",       # multicast
        "::1",             # IPv6 loopback
    ],
)
def test_rejects_non_routable_addresses(raw):
    """查這些位址沒有情資意義,還可能洩漏內網結構。"""
    with pytest.raises(InvalidTarget):
        normalize_target(raw)


def test_rejects_overlong_target():
    with pytest.raises(InvalidTarget):
        normalize_target("a" * 300 + ".com")
