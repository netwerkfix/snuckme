from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from fastapi.testclient import TestClient

import app as snuckme


client = TestClient(snuckme.app)


def make_certificate() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "snuck.me test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.IPAddress(ipaddress.ip_address("203.0.113.10"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("https://ocsp.example.com"),
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", ("example.com", 443)),
        ("https://example.com/path", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("https://münich.example", ("xn--mnich-kva.example", 443)),
    ],
)
def test_parse_target(value: str, expected: tuple[str, int]) -> None:
    assert snuckme.parse_target(value) == expected


@pytest.mark.parametrize("value", ["", "http://example.com", "https://user:pass@example.com", "bad..host"])
def test_parse_target_rejects_bad_input(value: str) -> None:
    with pytest.raises(ValueError):
        snuckme.parse_target(value)


def test_resolve_target_blocks_private_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SNUCKME_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setattr(
        snuckme.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="Private"):
        snuckme.resolve_target("localhost", 443)


def test_resolve_target_can_allow_private_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SNUCKME_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setattr(
        snuckme.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    assert snuckme.resolve_target("localhost", 443) == ["127.0.0.1"]


def test_certificate_mapping() -> None:
    result = snuckme.certificate_to_dict(make_certificate())
    assert result["subject"]["CN"] == "example.com"
    assert result["issuer"]["C"] == "BE"
    assert "DNS:example.com" in result["subjectaltname"]
    assert result["infoAccess"]["OCSP - URI"] == ["https://ocsp.example.com"]
    assert result["serialNumber"] == "3039"
    assert result["raw"].startswith("-----BEGIN CERTIFICATE-----")


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_frontend_uses_python_api_client() -> None:
    page = client.get("/")
    script = client.get("/client.js")
    assert page.status_code == 200
    assert '<script src="/client.js"></script>' in page.text
    assert "execute-api.us-east-1.amazonaws.com" not in page.text
    assert script.status_code == 200
    assert 'fetch("/api/certificate"' in script.text


def test_certificate_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        snuckme,
        "get_certificate",
        lambda value: {"success": True, "message": value, "subject": {"CN": "example.com"}},
    )
    response = client.post("/api/certificate", json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json()["subject"]["CN"] == "example.com"


def test_certificate_api_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_value: str) -> dict[str, object]:
        raise ValueError("blocked")

    monkeypatch.setattr(snuckme, "get_certificate", fail)
    response = client.post("/api/certificate", json={"url": "localhost"})
    assert response.status_code == 400
    assert response.json() == {"success": False, "message": "blocked"}
