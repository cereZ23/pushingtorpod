"""Classify a finding as an actionable *exposure* or best-practice *hygiene*.

The findings board is dominated by hygiene items (missing security headers, weak
ciphers, SPF/DKIM/DMARC, DNSSEC…) that generate volume but rarely represent a
direct breach path, burying the real exposures (CVEs, exposed services/panels,
default logins, takeovers, cleartext credentials). Separating the two lets the UI
default to exposures and collapse hygiene into a count/score.

Read-time only — there is no stored column. The classifier is keyword-based on the
finding name/template and **biases toward 'exposure'**: a finding is only demoted to
'hygiene' on a clear best-practice signal, so we never hide a real exposure.
"""

from __future__ import annotations

# Substrings (lowercased) that mark a best-practice / hardening finding.
HYGIENE_KEYWORDS = (
    # Security headers
    "hsts",
    "strict-transport",
    "content-security-policy",
    "content security policy",
    "x-frame",
    "clickjack",
    "x-content-type",
    "referrer-policy",
    "permissions-policy",
    "security header",
    # TLS / cipher configuration
    "weak cipher",
    "cipher suite",
    "tls version",
    "tls-version",
    "deprecated tls",
    "deprecated-tls",
    "sslv2",
    "sslv3",
    "tls 1.0",
    "tls 1.1",
    "3des",
    "rc4",
    # Certificate hygiene
    "self-signed",
    "self signed",
    "certificate expired",
    "certificate expiring",
    "expiring soon",
    "weak signature",
    "certificate mismatch",
    # Cookies
    "samesite",
    "httponly",
    "secure flag",
    "cookie without",
    "cookie missing",
    # Email auth / DNS hardening
    "spf",
    "dkim",
    "dmarc",
    "dnssec",
    "caa record",
    "caa dns",
    # Certificate transparency
    "signed certificate timestamp",
)

EXPOSURE = "exposure"
HYGIENE = "hygiene"


def finding_tier(name: str | None = None, template_id: str | None = None, source: str | None = None) -> str:
    """Return 'exposure' (actionable) or 'hygiene' (best-practice) for a finding.

    Defaults to 'exposure' — only clear header/TLS/email/DNS best-practice signals
    demote to 'hygiene', so a real exposure is never hidden by misclassification.
    """
    text = f"{name or ''} {template_id or ''}".lower()
    if any(k in text for k in HYGIENE_KEYWORDS):
        return HYGIENE
    return EXPOSURE
