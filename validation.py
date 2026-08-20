"""目標(IP / domain)的正規化與驗證。

原本的版本把任何字串都直接送進 Agent,線上資料裡 10 筆分析有 4 筆是
`185`、`185.`、`localhost:8000`、`123.456.123.456` 這類無效輸入 —— 每一筆
都完整燒掉一次 LLM 呼叫。驗證放在 API 層,不合法的輸入在進 Agent 之前就擋掉。
"""

import ipaddress
import re

# 單一 label:英數與連字號,不可用連字號開頭或結尾,最長 63 字元。
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")

# 至少要有一個字母,擋掉 `1.2.3.4.5` 這種看起來像 IP 的假網域。
_HAS_ALPHA_RE = re.compile(r"[a-z]")

MAX_TARGET_LENGTH = 253


class InvalidTarget(ValueError):
    """輸入無法被解析成可查詢的 IP 或 domain。"""


def normalize_target(raw: str) -> tuple[str, str]:
    """回傳 ``(target_type, normalized_target)``。

    ``target_type`` 為 ``"ip"`` 或 ``"domain"``。無法解析時丟出 ``InvalidTarget``。
    """
    if not isinstance(raw, str):
        raise InvalidTarget("target 必須是字串")

    target = raw.strip()
    if not target:
        raise InvalidTarget("target 不可為空")

    # 容錯:使用者常直接貼上完整網址。
    target = re.sub(r"^[a-z][a-z0-9+.-]*://", "", target, flags=re.IGNORECASE)
    target = target.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    target = target.strip().rstrip(".")

    if not target:
        raise InvalidTarget("target 不可為空")
    if len(target) > MAX_TARGET_LENGTH:
        raise InvalidTarget(f"target 長度不可超過 {MAX_TARGET_LENGTH} 字元")

    # IPv6 常見寫法 [::1]:8000
    if target.startswith("["):
        closing = target.find("]")
        if closing == -1:
            raise InvalidTarget("IPv6 位址的中括號未閉合")
        target = target[1:closing]
    elif target.count(":") == 1:
        # host:port,但 IPv6 會有多個冒號,不能一律切。
        host, _, port = target.partition(":")
        if port.isdigit():
            target = host

    ip = _try_parse_ip(target)
    if ip is not None:
        _reject_non_routable(ip)
        return "ip", str(ip)

    domain = target.lower()
    domain = _to_ascii_domain(domain)

    if not _DOMAIN_RE.match(domain):
        raise InvalidTarget(f"'{raw.strip()}' 不是合法的 IP 位址或 domain 名稱")
    if not _HAS_ALPHA_RE.search(domain):
        raise InvalidTarget(f"'{raw.strip()}' 不是合法的 IP 位址或 domain 名稱")

    return "domain", domain


def _try_parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _reject_non_routable(ip) -> None:
    """擋掉查了也沒有情資意義、還可能洩漏內網資訊的位址。"""
    if ip.is_loopback:
        raise InvalidTarget(f"{ip} 是 loopback 位址,不提供威脅情資查詢")
    if ip.is_private:
        raise InvalidTarget(f"{ip} 是私有網段位址,不提供威脅情資查詢")
    if ip.is_link_local:
        raise InvalidTarget(f"{ip} 是 link-local 位址,不提供威脅情資查詢")
    if ip.is_multicast:
        raise InvalidTarget(f"{ip} 是多播位址,不提供威脅情資查詢")
    if ip.is_reserved or ip.is_unspecified:
        raise InvalidTarget(f"{ip} 是保留位址,不提供威脅情資查詢")


def _to_ascii_domain(domain: str) -> str:
    """把 IDN 轉成 punycode;轉不了就原樣回傳,交給後面的正規表示式判定。"""
    if domain.isascii():
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise InvalidTarget("無法解析的國際化網域名稱") from None
