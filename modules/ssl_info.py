"""
ssl_info.py
-----------
Retrieves and parses the SSL/TLS certificate presented by the target host
on port 443, including subject, issuer, validity window, SANs, and the
negotiated TLS protocol version.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Dict


def get_certificate_info(hostname: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"Certificate verification failed: {exc}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return {"error": f"Could not establish TLS connection: {exc}"}

    def _name_dict(tup):
        return {k: v for entry in tup for k, v in entry}

    subject = _name_dict(cert.get("subject", ()))
    issuer = _name_dict(cert.get("issuer", ()))
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_remaining = None
    try:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry - datetime.datetime.utcnow()).days
    except (TypeError, ValueError):
        pass

    return {
        "subject_common_name": subject.get("commonName"),
        "issuer": issuer.get("commonName") or issuer.get("organizationName"),
        "issued": not_before,
        "expires": not_after,
        "days_until_expiry": days_remaining,
        "subject_alt_names": san,
        "tls_protocol": protocol,
        "cipher_suite": cipher[0] if cipher else None,
        "serial_number": cert.get("serialNumber"),
    }
