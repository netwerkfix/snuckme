"""Python 3 backend for snuck.me.

The original project used Express and an AWS Lambda endpoint.  This port keeps
the certificate lookup on the same origin and exposes a small JSON API.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
from datetime import timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from fastapi import FastAPI, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0
STATIC_FILES = {
    "captcha.svg",
    "favicon.jpg",
    "favicon.png",
    "favicon.svg",
    "http.png",
    "http.svg",
    "marydale.ttf",
    "password.svg",
    "seatop.png",
    "seatop.svg",
    "title.png",
    "title.svg",
    "tutorial.png",
    "tutorial.svg",
}


class CertificateRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


app = FastAPI(
    title="snuck.me",
    description="Retrieve a website's TLS certificate from the server side.",
    version="0.2.0",
)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_target(value: str) -> tuple[str, int]:
    """Return an IDNA hostname and TCP port from a hostname or HTTPS URL."""

    raw = value.strip()
    if not raw:
        raise ValueError("Enter a hostname or HTTPS URL.")

    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.scheme and parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS targets are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in the target URL.")
    if not parsed.hostname:
        raise ValueError("The target hostname is invalid.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or DEFAULT_PORT
    except (UnicodeError, ValueError) as exc:
        raise ValueError("The target hostname or port is invalid.") from exc

    if len(hostname) > 253 or any(not label for label in hostname.split(".")):
        raise ValueError("The target hostname is invalid.")
    return hostname, port


def resolve_target(hostname: str, port: int) -> list[str]:
    """Resolve a target and reject local/private destinations by default."""

    try:
        records = socket.getaddrinfo(
            hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve {hostname}.") from exc

    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ValueError(f"Unable to resolve {hostname}.")

    if not _env_flag("SNUCKME_ALLOW_PRIVATE_TARGETS"):
        blocked = [address for address in addresses if not ipaddress.ip_address(address).is_global]
        if blocked:
            raise ValueError("Private, loopback, link-local, and reserved targets are blocked.")
    return addresses


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    oid_names = {
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COMMON_NAME: "CN",
        NameOID.EMAIL_ADDRESS: "emailAddress",
    }
    result: dict[str, str] = {}
    for attribute in name:
        result[oid_names.get(attribute.oid, attribute.oid.dotted_string)] = attribute.value
    return result


def _format_time(value: Any) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%b %d %H:%M:%S %Y GMT")


def certificate_to_dict(certificate_der: bytes) -> dict[str, Any]:
    certificate = x509.load_der_x509_certificate(certificate_der)

    alternative_names: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        alternative_names.extend(f"DNS:{name}" for name in extension.value.get_values_for_type(x509.DNSName))
        alternative_names.extend(
            f"IP Address:{address}"
            for address in extension.value.get_values_for_type(x509.IPAddress)
        )
    except x509.ExtensionNotFound:
        pass

    info_access: dict[str, list[str]] = {
        "CA Issuers - URI": [],
        "OCSP - URI": [],
    }
    try:
        extension = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for description in extension.value:
            if not isinstance(description.access_location, x509.UniformResourceIdentifier):
                continue
            if description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                info_access["CA Issuers - URI"].append(description.access_location.value)
            elif description.access_method == AuthorityInformationAccessOID.OCSP:
                info_access["OCSP - URI"].append(description.access_location.value)
    except x509.ExtensionNotFound:
        pass

    sha1 = hashlib.sha1(certificate_der).hexdigest().upper()
    fingerprint = ":".join(sha1[index : index + 2] for index in range(0, len(sha1), 2))
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    return {
        "subject": _name_to_dict(certificate.subject),
        "issuer": _name_to_dict(certificate.issuer),
        "subjectaltname": ", ".join(alternative_names),
        "fingerprint": fingerprint,
        "infoAccess": info_access,
        "valid_from": _format_time(not_before),
        "valid_to": _format_time(not_after),
        "serialNumber": format(certificate.serial_number, "X"),
        "raw": pem,
    }


def get_certificate(value: str) -> dict[str, Any]:
    hostname, port = parse_target(value)
    addresses = resolve_target(hostname, port)
    timeout = float(os.getenv("SNUCKME_TLS_TIMEOUT", str(DEFAULT_TIMEOUT)))
    timeout = max(0.5, min(timeout, 20.0))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    last_error: OSError | ssl.SSLError | None = None
    for address in addresses:
        try:
            with socket.create_connection((address, port), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                    certificate_der = tls_socket.getpeercert(binary_form=True)
                    if not certificate_der:
                        raise ssl.SSLError("The peer did not provide a certificate.")
                    result = certificate_to_dict(certificate_der)
                    result.update(
                        success=True,
                        message=f"Found certificate for {hostname}:{port}",
                        hostname=hostname,
                        port=port,
                    )
                    return result
        except (OSError, ssl.SSLError) as exc:
            last_error = exc

    raise ConnectionError(f"Unable to retrieve the certificate for {hostname}:{port}.") from last_error


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/certificate")
def certificate_lookup(request: CertificateRequest) -> JSONResponse:
    try:
        return JSONResponse(get_certificate(request.url))
    except ValueError as exc:
        return JSONResponse({"success": False, "message": str(exc)}, status_code=400)
    except (ConnectionError, OSError, ssl.SSLError, x509.UnsupportedAlgorithm):
        return JSONResponse(
            {"success": False, "message": f"Unable to find certificate for {request.url}"},
            status_code=502,
        )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")


@app.get("/client.js", include_in_schema=False)
def client_script() -> FileResponse:
    return FileResponse(BASE_DIR / "client.js", media_type="application/javascript")


@app.get("/{filename}", include_in_schema=False)
def static_file(filename: str) -> Response:
    if filename not in STATIC_FILES:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return FileResponse(BASE_DIR / filename)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
