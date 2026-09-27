"""Assessment / Attack Engine: safe, non-destructive MFA security checks.

All checks are passive or lightly-active, authorized-only probes. No
exploitation, no credential attacks, no social engineering.
"""
from __future__ import annotations
import math
import re
import time
from collections import Counter
from typing import List, Optional
from urllib.parse import urljoin

import requests

from .models import Endpoint, Finding, Severity


class AssessmentEngine:
    def __init__(self, target: str, timeout: int = 10, verify_tls: bool = True):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "MFA-Audit-Tool/1.0 (+authorized-security-assessment)"
        })

    # ---------- public entry point ----------
    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        primary = self._pick_primary(endpoints)

        findings += self.check_https_enforcement(primary)
        findings += self.check_hsts(primary)
        findings += self.check_security_headers(primary)
        findings += self.check_cookie_flags(primary)
        findings += self.check_session_token_entropy(primary)
        findings += self.check_rate_limiting(primary)
        findings += self.check_legacy_auth(primary)
        findings += self.check_fallback_methods(primary)
        findings += self.check_phishing_resistance(primary)
        findings += self.check_tls_version(primary)
        return findings

    # ---------- helpers ----------
    def _pick_primary(self, endpoints: List[Endpoint]) -> Endpoint:
        for ep in endpoints:
            if ep.url.rstrip("/") == self.target:
                return ep
        return endpoints[0] if endpoints else Endpoint(url=self.target)

    def _pick_auth_url(self, ep: Endpoint) -> str:
        """Try known auth paths and return the first that responds."""
        candidates = ["/login", "/signin", "/auth", "/mfa", "/2fa"]
        for path in candidates:
            url = urljoin(self.target + "/", path.lstrip("/"))
            r = self._get(url, allow_redirects=False)
            if r is not None and r.status_code < 500:
                return url
        return self.target

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=self.verify_tls, **kw
            )
        except requests.RequestException:
            return None

    # ---------- checks ----------
    def check_https_enforcement(self, ep: Endpoint) -> List[Finding]:
        if not self.target.startswith("https://"):
            return []
        http_url = "http://" + self.target[len("https://"):]
        r = self._get(http_url, allow_redirects=False)
        if r is None:
            return []
        if r.status_code in (301, 302, 307, 308) and r.headers.get(
            "Location", ""
        ).startswith("https://"):
            return []
        return [Finding(
            check_id="CFG-001",
            title="HTTPS not strictly enforced",
            severity=Severity.HIGH,
            description=(
                "The target does not redirect plain HTTP traffic to HTTPS. "
                "This permits credential and MFA token interception via "
                "Adversary-in-the-Middle (AiTM) attacks."
            ),
            evidence=f"HTTP {http_url} returned status {r.status_code}",
            remediation=(
                "Enforce HSTS and 301-redirect all HTTP requests to HTTPS at "
                "the edge/load balancer. Disable plaintext listeners."
            ),
            nist_ref="NIST SP 800-63B §5.1.1",
            owasp_ref="OWASP A02:2021 Cryptographic Failures",
        )]

    def check_hsts(self, ep: Endpoint) -> List[Finding]:
        if not self.target.startswith("https://"):
            return []
        r = self._get(self.target)
        if r is None:
            return []
        hsts = r.headers.get("Strict-Transport-Security", "")
        if "max-age" in hsts.lower():
            return []
        return [Finding(
            check_id="CFG-002",
            title="Missing or weak HSTS header",
            severity=Severity.MEDIUM,
            description=(
                "Strict-Transport-Security is missing or lacks max-age, "
                "increasing SSL-strip and downgrade risk to authentication flows."
            ),
            evidence=f"Strict-Transport-Security: {hsts or '<absent>'}",
            remediation=(
                "Set 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload' on all HTTPS responses."
            ),
            nist_ref="NIST SP 800-63B §5.1.1",
            owasp_ref="OWASP A02:2021",
        )]

    def check_security_headers(self, ep: Endpoint) -> List[Finding]:
        r = self._get(self.target)
        if r is None:
            return []
        required = {
            "Content-Security-Policy": "CSP reduces injection & clickjacking risks",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "X-Frame-Options": "Prevents clickjacking of auth UI",
            "Referrer-Policy": "Limits referrer leakage of auth URLs",
        }
        missing = [h for h in required if h not in r.headers]
        if not missing:
            return []
        return [Finding(
            check_id="CFG-003",
            title="Missing browser security headers",
            severity=Severity.LOW,
            description=(
                "Authentication pages lack hardening headers, weakening "
                "defense-in-depth against token theft and UI-redress attacks."
            ),
            evidence="Missing: " + ", ".join(missing),
            remediation="Add the missing headers at the web server or edge.",
            owasp_ref="OWASP A05:2021 Security Misconfiguration",
        )]

    def check_cookie_flags(self, ep: Endpoint) -> List[Finding]:
        r = self._get(self.target)
        if r is None:
            return []
        findings = []
        for cookie in r.cookies:
            rest = cookie._rest or {}
            secure = bool(rest.get("Secure")) or cookie.secure
            httponly = bool(rest.get("HttpOnly")) or cookie.has_nonstandard_attr("HttpOnly")
            samesite = rest.get("SameSite") or cookie.get_nonstandard_attr("SameSite")
            problems = []
            if not secure:
                problems.append("Secure")
            if not httponly:
                problems.append("HttpOnly")
            if not samesite:
                problems.append("SameSite")
            if problems:
                findings.append(Finding(
                    check_id="SES-001",
                    title=f"Session cookie '{cookie.name}' missing flags",
                    severity=Severity.HIGH if "HttpOnly" in problems or "Secure" in problems
                             else Severity.MEDIUM,
                    description=(
                        "Session cookies lacking Secure/HttpOnly/SameSite "
                        "increase risk of session hijacking and post-MFA token theft."
                    ),
                    evidence=f"Cookie={cookie.name}; missing={','.join(problems)}",
                    remediation=(
                        "Set Secure; HttpOnly; SameSite=Lax (or Strict) on all "
                        "authentication session cookies."
                    ),
                    nist_ref="NIST SP 800-63B §7.1",
                    owasp_ref="OWASP A07:2021 Identification & Authentication Failures",
                ))
        return findings

    def check_session_token_entropy(self, ep: Endpoint) -> List[Finding]:
        r = self._get(self.target)
        if r is None or not r.cookies:
            return []
        findings = []
        for cookie in r.cookies:
            tok = cookie.value
            if not tok:
                continue
            # Short tokens are themselves a risk — flag directly
            if len(tok) < 16:
                findings.append(Finding(
                    check_id="SES-002",
                    title=f"Short session token '{cookie.name}'",
                    severity=Severity.HIGH,
                    description=(
                        "Session token is under 16 characters, far below the "
                        "128-bit NIST minimum. Such tokens are predictable and "
                        "trivially brute-forceable."
                    ),
                    evidence=f"Token length = {len(tok)} characters",
                    remediation=(
                        "Generate session identifiers with a CSPRNG providing at "
                        "least 128 bits of entropy (e.g., secrets.token_urlsafe(32))."
                    ),
                    nist_ref="NIST SP 800-63B §7.1",
                    owasp_ref="OWASP A07:2021",
                    cwe_ref="CWE-330",
                ))
                continue
            entropy = _shannon_entropy(tok)
            total_bits = entropy * len(tok)
            if total_bits < 128:
                findings.append(Finding(
                    check_id="SES-002",
                    title=f"Low-entropy session token '{cookie.name}'",
                    severity=Severity.HIGH,
                    description=(
                        "Session token entropy is below 128 bits, which "
                        "facilitates prediction and post-MFA session hijacking."
                    ),
                    evidence=f"Estimated entropy ≈ {total_bits:.0f} bits",
                    remediation=(
                        "Generate session identifiers using a CSPRNG with ≥128 "
                        "bits of entropy (e.g., secrets.token_urlsafe(32))."
                    ),
                    nist_ref="NIST SP 800-63B §7.1",
                    owasp_ref="OWASP A07:2021",
                    cwe_ref="CWE-330",
                ))
        return findings

    def check_rate_limiting(self, ep: Endpoint) -> List[Finding]:
        """Send a small, safe burst to the auth endpoint to detect throttling."""
        url = self._pick_auth_url(ep)
        burst = 12
        statuses = []
        start = time.time()
        for _ in range(burst):
            try:
                r = self.session.get(url, timeout=self.timeout,
                                     verify=self.verify_tls, allow_redirects=False)
                statuses.append(r.status_code)
            except requests.RequestException:
                statuses.append(0)
        elapsed = time.time() - start
        throttled = any(s in (429, 503) for s in statuses)
        slow = elapsed > 6.0
        if throttled or slow:
            return []
        return [Finding(
            check_id="ATT-001",
            title="No observable rate limiting on authentication endpoint",
            severity=Severity.HIGH,
            description=(
                "The authentication endpoint did not throttle a burst of "
                "requests, making the system susceptible to MFA fatigue "
                "(prompt bombing) and OTP brute-force attacks."
            ),
            evidence=(
                f"{burst} rapid requests to {url}; statuses={dict(Counter(statuses))}; "
                f"elapsed={elapsed:.2f}s"
            ),
            remediation=(
                "Implement per-account and per-IP rate limits on all MFA "
                "challenge endpoints (e.g., 3–5 attempts/min), enable number "
                "matching, and lock the account after repeated denials."
            ),
            nist_ref="NIST SP 800-63B §5.2.2",
            owasp_ref="OWASP A07:2021",
            cwe_ref="CWE-307",
        )]

    def check_legacy_auth(self, ep: Endpoint) -> List[Finding]:
        findings = []
        r = self._get(self.target)
        if r is None:
            return findings
        www = r.headers.get("WWW-Authenticate", "").lower()
        if "basic" in www or "ntlm" in www or "negotiate" in www:
            findings.append(Finding(
                check_id="CFG-004",
                title="Legacy authentication protocol exposed",
                severity=Severity.HIGH,
                description=(
                    "The endpoint advertises legacy authentication (Basic/NTLM/"
                    "Negotiate). These protocols cannot enforce MFA and are a "
                    "common MFA bypass vector in enterprise environments."
                ),
                evidence=f"WWW-Authenticate: {r.headers.get('WWW-Authenticate')}",
                remediation=(
                    "Disable Basic/NTLM/Negotiate at the edge, block legacy "
                    "auth protocols (IMAP/POP/SMTP) in the identity provider, "
                    "and require modern OAuth2/OIDC flows."
                ),
                nist_ref="NIST SP 800-63B §5.1.2",
                owasp_ref="OWASP A07:2021",
            ))
        return findings

    def check_fallback_methods(self, ep: Endpoint) -> List[Finding]:
        r = self._get(self._pick_auth_url(ep))
        if r is None:
            return []
        text = r.text.lower()
        weak_hits = []
        if re.search(r"\b(sms|text message)\b", text):
            weak_hits.append("SMS")
        if re.search(r"\bvoice call\b", text):
            weak_hits.append("voice")
        if re.search(r"\bemail (a )?code\b", text):
            weak_hits.append("email OTP")
        if not weak_hits:
            return []
        return [Finding(
            check_id="ATT-002",
            title="Weak fallback MFA method offered",
            severity=Severity.MEDIUM,
            description=(
                "The authentication flow advertises weak fallback factors "
                f"({', '.join(weak_hits)}). These can be downgraded to by an "
                "attacker to bypass stronger factors such as FIDO2/WebAuthn."
            ),
            evidence=f"Fallback indicators found: {', '.join(weak_hits)}",
            remediation=(
                "Prefer phishing-resistant factors (FIDO2/WebAuthn). If SMS/"
                "voice must remain, restrict to recovery only and apply "
                "additional verification and monitoring."
            ),
            nist_ref="NIST SP 800-63B §5.1.3 / §5.2.10",
            owasp_ref="OWASP A07:2021",
        )]

    def check_phishing_resistance(self, ep: Endpoint) -> List[Finding]:
        r = self._get(self.target)
        if r is None:
            return []
        text = r.text.lower()
        has_fido = any(k in text for k in ("webauthn", "fido2", "passkey", "security key"))
        if has_fido:
            return []
        return [Finding(
            check_id="ATT-003",
            title="No phishing-resistant MFA factor detected",
            severity=Severity.MEDIUM,
            description=(
                "The target does not advertise FIDO2/WebAuthn support. Users "
                "rely on OTP or push, which are vulnerable to AiTM phishing "
                "and real-time relay attacks."
            ),
            evidence="No WebAuthn/FIDO2/passkey indicators in login page",
            remediation=(
                "Roll out FIDO2 security keys or platform passkeys and "
                "require them for privileged accounts (NIST AAL3)."
            ),
            nist_ref="NIST SP 800-63B §5.1.7",
            owasp_ref="OWASP A07:2021",
        )]

    def check_tls_version(self, ep: Endpoint) -> List[Finding]:
        if not self.target.startswith("https://"):
            return []
        ver = None
        try:
            import ssl, socket
            from urllib.parse import urlparse
            host = urlparse(self.target).hostname
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()
            if ver in ("TLSv1.2", "TLSv1.3"):
                return []
        except Exception:
            return []
        return [Finding(
            check_id="CFG-005",
            title="Weak TLS configuration",
            severity=Severity.MEDIUM,
            description="TLS version negotiation indicates outdated protocol support.",
            evidence=f"Negotiated: {ver or 'unknown'}",
            remediation="Require TLS 1.2+ and disable TLS 1.0/1.1 and weak ciphers.",
            nist_ref="NIST SP 800-63B §5.1.1",
        )]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())