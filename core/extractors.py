import re
import logging
from typing import Dict, List
from collections import OrderedDict

logger = logging.getLogger("midins.extractors")

_PRIVATE_V4_PREFIXES = (
    "10.", "127.", "0.", "169.254.", "255.255.255.255",
)
_PRIVATE_V4_RANGES = [
    (172, 16, 31),
]

_RX_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_RX_URL = re.compile(
    r"\b(?:https?|mailto)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE
)
_RX_FQDN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|co|gov|edu|mil|info|biz|xyz|me|tech|cloud|"
    r"ai|sh|to|ru|cn|de|uk|fr|jp|br|in|us|eu|onion|ly|tv|site|store|host)\b",
    re.IGNORECASE,
)
_RX_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"
)

_RX_AWS_AKID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_RX_AWS_SECRET = re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{0,4}([A-Za-z0-9/+=]{40})")
_RX_GOOGLE_API = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_RX_GOOGLE_OAUTH = re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b")
_RX_SLACK = re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,72}\b")
_RX_GITHUB = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")
_RX_STRIPE = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b")
_RX_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
_RX_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r"[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
)
_RX_GENERIC_BEARER = re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})")

_SECRET_RULES = [
    ("AWS_ACCESS_KEY", _RX_AWS_AKID),
    ("AWS_SECRET_KEY", _RX_AWS_SECRET),
    ("GOOGLE_API_KEY", _RX_GOOGLE_API),
    ("GOOGLE_OAUTH_TOKEN", _RX_GOOGLE_OAUTH),
    ("SLACK_TOKEN", _RX_SLACK),
    ("GITHUB_TOKEN", _RX_GITHUB),
    ("STRIPE_KEY", _RX_STRIPE),
    ("JWT", _RX_JWT),
    ("PRIVATE_KEY_BLOCK", _RX_PRIVATE_KEY),
    ("BEARER_TOKEN", _RX_GENERIC_BEARER),
]


def _is_private_ipv4(addr: str) -> bool:
    if addr.startswith(_PRIVATE_V4_PREFIXES):
        return True
    octets = addr.split(".")
    try:
        first, second = int(octets[0]), int(octets[1])
    except ValueError:
        return False
    if first == 192 and second == 168:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    return False


def _dedupe(items: List[str]) -> List[str]:
    return list(OrderedDict.fromkeys(items))


class ArtifactHarvester:
    def harvest(self, payload: str) -> Dict:
        if not isinstance(payload, str) or not payload:
            return self._empty()

        ipv4_matches = _RX_IPV4.findall(payload)
        public_ipv4 = [ip for ip in ipv4_matches if not _is_private_ipv4(ip)]
        private_ipv4 = [ip for ip in ipv4_matches if _is_private_ipv4(ip)]

        urls = _RX_URL.findall(payload)
        domains_raw = _RX_FQDN.findall(payload)
        emails = _RX_EMAIL.findall(payload)

        secrets: List[Dict[str, str]] = []
        seen_secret_values = set()
        for label, pattern in _SECRET_RULES:
            for match in pattern.finditer(payload):
                token = match.group(0)
                if token in seen_secret_values:
                    continue
                seen_secret_values.add(token)
                secrets.append({
                    "type": label,
                    "value": token if len(token) <= 240 else token[:240] + "…",
                    "offset": match.start(),
                })

        return {
            "ipv4_public": _dedupe(public_ipv4),
            "ipv4_private": _dedupe(private_ipv4),
            "urls": _dedupe(urls),
            "domains": _dedupe(domains_raw),
            "emails": _dedupe(emails),
            "secrets": secrets,
            "counts": {
                "ipv4_public": len(_dedupe(public_ipv4)),
                "ipv4_private": len(_dedupe(private_ipv4)),
                "urls": len(_dedupe(urls)),
                "domains": len(_dedupe(domains_raw)),
                "emails": len(_dedupe(emails)),
                "secrets": len(secrets),
            },
        }

    def _empty(self) -> Dict:
        return {
            "ipv4_public": [], "ipv4_private": [], "urls": [],
            "domains": [], "emails": [], "secrets": [],
            "counts": {
                "ipv4_public": 0, "ipv4_private": 0, "urls": 0,
                "domains": 0, "emails": 0, "secrets": 0,
            },
        }
