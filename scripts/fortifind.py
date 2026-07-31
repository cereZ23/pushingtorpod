#!/usr/bin/env python3
"""fortifind — identify a Fortinet appliance (device + model + serial) from its TLS cert.

Fortinet appliances present a factory self-signed certificate whose subject CN *is*
the device serial number (e.g. ``CN=FG100D3G15815658``). Fortinet serials are 16
chars: a 6-char model code + a 10-char unit id. The leading letters name the product
line and the model code decodes the model — this is exactly how Shodan fingerprints
them, straight from the certificate, no login needed.

Usage:
    fortifind.py <host> [port ...]        # grab the cert on each port (default: 443 10443 8443 541 10400)
    fortifind.py --decode <SERIAL>        # just decode a serial you already have

Needs only `openssl` (present on macOS/Linux).
"""

from __future__ import annotations

import re
import subprocess
import sys

DEFAULT_PORTS = [443, 10443, 8443, 541, 10400]

# Longest prefixes first so FGT matches before FG, FWF before FW, etc.
DEVICE_PREFIX = {
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
    "FCH": "FortiCache",
    "FSA": "FortiSandbox",
}

# Fortinet serial: leading letters + alphanumerics ending in a run of digits.
SERIAL_RE = re.compile(r"^[A-Z]{2,4}[A-Z0-9]{4,}\d{4,}$")


def decode_serial(cn: str) -> dict | None:
    """Decode a Fortinet serial (device / model / unit id) or None if it isn't one."""
    s = (cn or "").strip().upper()
    if not (s.startswith("F") and SERIAL_RE.match(s)):
        return None
    model_code = s[:6] if len(s) >= 16 else s
    unit_id = s[6:] if len(s) >= 16 else ""
    for prefix in sorted(DEVICE_PREFIX, key=len, reverse=True):
        if s.startswith(prefix):
            model_num = model_code[len(prefix):]
            return {
                "serial": s,
                "device": DEVICE_PREFIX[prefix],
                "model": f"{DEVICE_PREFIX[prefix]}-{model_num}" if model_num else DEVICE_PREFIX[prefix],
                "model_code": model_code,
                "unit_id": unit_id,
            }
    return {"serial": s, "device": "Fortinet (unknown line)", "model": model_code, "model_code": model_code, "unit_id": unit_id}


def _openssl_subject(host: str, port: int, timeout: int = 8) -> tuple[str, str] | None:
    """Return (subject, issuer) of the leaf cert via openssl s_client, or None."""
    try:
        s = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input=b"", capture_output=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    out = s.stdout.decode(errors="replace")
    start, end = out.find("-----BEGIN CERTIFICATE-----"), out.find("-----END CERTIFICATE-----")
    if start == -1 or end == -1:
        return None
    pem = out[start : end + len("-----END CERTIFICATE-----")]
    x = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer"],
        input=pem.encode(), capture_output=True,
    ).stdout.decode(errors="replace")
    subject = issuer = ""
    for line in x.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer="):].strip()
    return subject, issuer


def _cn(dn: str) -> str:
    m = re.search(r"CN\s*=\s*([^,/]+)", dn)
    return m.group(1).strip() if m else ""


def scan_host(host: str, ports: list[int]) -> None:
    print(f"# fortifind {host}\n")
    found = False
    for port in ports:
        res = _openssl_subject(host, port)
        if not res:
            print(f"  {port:>6}  (no TLS / no response)")
            continue
        subject, issuer = res
        cn = _cn(subject)
        info = decode_serial(cn)
        if info:
            found = True
            print(f"  {port:>6}  \033[1;32mFORTINET\033[0m  {info['model']}")
            print(f"          serial : {info['serial']}")
            print(f"          issuer : {issuer}")
        else:
            print(f"  {port:>6}  CN={cn or '(none)'}  [not a Fortinet serial]")
    if not found:
        print("\n  No Fortinet factory cert found on the scanned ports.")
        print("  Try the appliance's management/SSL-VPN port explicitly, e.g.:")
        print(f"    {sys.argv[0]} {host} 10443 4443 8443")


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--decode":
        if len(args) < 2:
            print("usage: fortifind.py --decode <SERIAL>")
            return 2
        info = decode_serial(args[1])
        if not info:
            print(f"{args[1]!r} does not look like a Fortinet serial.")
            return 1
        print(f"device : {info['device']}")
        print(f"model  : {info['model']}")
        print(f"serial : {info['serial']}")
        print(f"unit id: {info['unit_id']}")
        return 0
    host, ports = args[0], [int(p) for p in args[1:]] or DEFAULT_PORTS
    scan_host(host, ports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
