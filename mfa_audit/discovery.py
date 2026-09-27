"""Discovery Module: identifies authentication endpoints and MFA indicators."""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urljoin, urlparse

import requests

from .models import Endpoint

COMMON_AUTH_PATHS = [
    "/login", "/signin", "/auth", "/sso", "/oauth2/authorize",
    "/mfa", "/2fa", "/verify", "/challenge", "/authenticate",
    "/.well-known/openid-configuration",
]

MFA_INDICATORS = {
    "totp": [r"totp", r"authenticator", r"6[-\s]?digit", r"one[-\s]?time code"],
    "sms": [r"sms", r"text message", r"mobile number"],
    "push": [r"push notification", r"approve.*sign[-\s]?in", r"authenticator app"],
    "fido2": [r"fido2", r"webauthn", r"security key", r"passkey"],
    "email_otp": [r"email.*code", r"verification code.*email"],
}

DEFAULT_HEADERS = {
    "User-Agent": "MFA-Audit-Tool/1.0 (+authorized-security-assessment)"
}


class DiscoveryModule:
    """Discovers authentication endpoints and MFA indicators on a target."""

    def __init__(self, target: str, timeout: int = 10, verify_tls: bool = True):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def run(self) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        # Always include the base URL
        endpoints.append(self._probe(self.target))
        for path in COMMON_AUTH_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            ep = self._probe(url)
            if ep.status_code and ep.status_code < 500:
                endpoints.append(ep)
        # De-duplicate by URL
        seen = set()
        unique = []
        for ep in endpoints:
            if ep.url not in seen:
                seen.add(ep.url)
                unique.append(ep)
        return unique

    def _probe(self, url: str) -> Endpoint:
        ep = Endpoint(url=url)
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True
            )
            ep.status_code = resp.status_code
            ep.method = "GET"
            ep.auth_type = self._infer_auth_type(resp)
            ep.mfa_indicators = self._detect_mfa(resp.text)
        except requests.RequestException:
            ep.status_code = None
        return ep

    @staticmethod
    def _infer_auth_type(resp: requests.Response) -> str:
        www = resp.headers.get("WWW-Authenticate", "").lower()
        if "basic" in www:
            return "basic"
        if "bearer" in www:
            return "bearer"
        if "negotiate" in www:
            return "negotiate"
        if "saml" in resp.text.lower()[:5000]:
            return "saml"
        if "oauth" in resp.text.lower()[:5000]:
            return "oauth"
        return "form"

    @staticmethod
    def _detect_mfa(text: str) -> List[str]:
        found = []
        low = text.lower()
        for method, patterns in MFA_INDICATORS.items():
            if any(re.search(p, low) for p in patterns):
                found.append(method)
        return found

    @staticmethod
    def host_of(url: str) -> str:
        return urlparse(url).netloc