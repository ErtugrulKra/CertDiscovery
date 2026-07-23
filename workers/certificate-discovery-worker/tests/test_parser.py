from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

from worker.discovery import parse_certificate
from worker.models import WorkerJob


def test_parse_self_signed_certificate() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("unit.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    parsed = parse_certificate(cert.public_bytes(serialization.Encoding.DER))

    assert parsed.commonName == "unit.test"
    assert parsed.isSelfSigned is True
    assert parsed.publicKeyAlgorithm == "RSA"
    assert parsed.subjectAlternativeNames[0].name == "unit.test"
    assert len(parsed.chainEntries) == 1
    assert parsed.chainEntries[0].position == 0
    assert parsed.chainEntries[0].fingerprintSha256 == parsed.fingerprintSha256


def test_worker_job_accepts_numeric_protocol_from_legacy_api_payload() -> None:
    job = WorkerJob.model_validate(
        {
            "jobId": "job-1",
            "assets": [
                {
                    "id": "asset-1",
                    "name": "Legacy",
                    "host": "example.com",
                    "port": 443,
                    "protocol": 0,
                    "sniHost": None,
                    "timeoutSeconds": 10,
                }
            ],
        }
    )

    assert job.assets[0].protocol == "HTTPS"
