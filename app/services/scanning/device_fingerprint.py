"""Identify a network appliance from its TLS certificate subject.

Many appliances present a factory certificate whose subject CN encodes the device
identity. Fortinet is the clean case: ``CN=FG100D3G15815658`` is the unit serial —
6-char model code + 10-char unit id — so the product line and model decode straight
from the certificate we already collect with tlsx. This is exactly how Shodan
fingerprints them, no login and no protocol-specific probe needed (that caveat only
applies to non-TLS management protocols like fgfm on 541).

Extensible: add vendors to IDENTIFIERS. Biased toward precision — return None unless
the pattern is unambiguous, so we never mislabel a normal web certificate.
"""

from __future__ import annotations

import re

# Fortinet product lines keyed by serial prefix (longest first when matching).
_FORTINET_LINES = {
    "FGT": "FortiGate",
    "FG": "FortiGate",
    "FWF": "FortiWiFi",
    "FW": "FortiWiFi",
    "FMG": "FortiManager",
    "FAZ": "FortiAnalyzer",
    "FL": "FortiAnalyzer",
    "FML": "FortiMail",
    "FE": "FortiMail",
    "FAC": "FortiAuthenticator",
    "FWB": "FortiWeb",
    "FV": "FortiWeb",
    "FS": "FortiSwitch",
    "FAP": "FortiAP",
    "FAD": "FortiADC",
    "FAI": "FortiADC",
    "FSA": "FortiSandbox",
}

# Fortinet serial: leading letters + alphanumerics ending in a run of digits, 12-20 chars.
_FORTINET_SERIAL_RE = re.compile(r"^F[A-Z]{1,3}[A-Z0-9]{4,}\d{4,}$")


def _identify_fortinet(cn: str) -> dict | None:
    s = cn.strip().upper()
    if not _FORTINET_SERIAL_RE.match(s) or len(s) < 12:
        return None
    model_code = s[:6] if len(s) >= 16 else s
    unit_id = s[6:] if len(s) >= 16 else ""
    for prefix in sorted(_FORTINET_LINES, key=len, reverse=True):
        if s.startswith(prefix):
            model_num = model_code[len(prefix) :]
            device = _FORTINET_LINES[prefix]
            return {
                "vendor": "Fortinet",
                "device": device,
                "model": f"{device}-{model_num}" if model_num else device,
                "serial": s,
                "unit_id": unit_id,
            }
    return None


# Each identifier takes the cert subject CN and returns a device dict or None.
IDENTIFIERS = (_identify_fortinet,)


def identify_device(subject_cn: str | None) -> dict | None:
    """Return {vendor, device, model, serial, ...} if the cert CN identifies an
    appliance, else None. Precise by design — a normal web CN returns None."""
    if not subject_cn:
        return None
    for fn in IDENTIFIERS:
        hit = fn(subject_cn)
        if hit:
            return hit
    return None
