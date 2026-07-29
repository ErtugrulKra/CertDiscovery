import asyncio
import hashlib
import socket
import ssl
import time
from datetime import UTC, datetime

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .models import (
    ScanErrorType,
    ScanResultStatus,
    SubjectAlternativeName,
    WorkerAsset,
    WorkerCertificate,
    WorkerCertificateChainEntry,
    WorkerScanResult,
)

SUPPORTED_PROTOCOLS = {"HTTPS", "TLS", "SMTPS", "IMAPS", "POP3S", "LDAPS", "SMTP", "IMAP", "POP3", "LDAP"}
STARTTLS_PROTOCOLS = {"SMTP", "IMAP", "POP3", "LDAP"}


async def scan_asset(job_id: str, asset: WorkerAsset) -> WorkerScanResult:
    started = datetime.now(UTC)
    start_counter = time.perf_counter()
    resolved_ip: str | None = None
    try:
        if asset.protocol.upper() not in SUPPORTED_PROTOCOLS:
            raise UnsupportedProtocolError(f"Unsupported protocol: {asset.protocol}")

        resolved_ip = await resolve_host(asset.host)
        server_hostname = asset.sniHost or asset.host

        tls_result = await connect_tls_with_chain(
            asset.host, asset.port, server_hostname, asset.timeoutSeconds, asset.protocol.upper()
        )
        if not tls_result.certificate_der:
            raise CertificateParseError("Peer did not provide a certificate.")
        certificate = parse_certificate(tls_result.certificate_der, tls_result.chain_der)
        completed = datetime.now(UTC)
        return WorkerScanResult(
            scanJobId=job_id,
            assetId=asset.id,
            status=ScanResultStatus.success,
            startedAtUtc=started,
            completedAtUtc=completed,
            durationMilliseconds=int((time.perf_counter() - start_counter) * 1000),
            resolvedIpAddress=resolved_ip,
            tlsProtocol=tls_result.tls_protocol,
            cipherSuite=tls_result.cipher_suite,
            certificate=certificate,
        )
    except Exception as exc:
        completed = datetime.now(UTC)
        error_type = map_error(exc)
        return WorkerScanResult(
            scanJobId=job_id,
            assetId=asset.id,
            status=ScanResultStatus.failed,
            startedAtUtc=started,
            completedAtUtc=completed,
            durationMilliseconds=int((time.perf_counter() - start_counter) * 1000),
            resolvedIpAddress=resolved_ip,
            errorType=error_type,
            errorMessage=str(exc),
            rawDiagnosticData=type(exc).__name__,
        )


async def resolve_host(host: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DnsResolutionError(str(exc)) from exc
    return results[0][4][0]


class TlsConnectionResult:
    def __init__(self, certificate_der: bytes, chain_der: list[bytes], tls_protocol: str | None, cipher_suite: str | None) -> None:
        self.certificate_der = certificate_der
        self.chain_der = chain_der
        self.tls_protocol = tls_protocol
        self.cipher_suite = cipher_suite


async def connect_tls_with_chain(
    host: str,
    port: int,
    server_hostname: str | None,
    timeout_seconds: int,
    protocol: str = "TLS",
) -> TlsConnectionResult:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _connect_tls_with_chain_blocking, host, port, server_hostname, timeout_seconds, protocol
    )


def _connect_tls_with_chain_blocking(
    host: str,
    port: int,
    server_hostname: str | None,
    timeout_seconds: int,
    protocol: str = "TLS",
) -> TlsConnectionResult:
    sock: socket.socket | None = None
    connection: SSL.Connection | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_seconds)
        if protocol.upper() in STARTTLS_PROTOCOLS:
            negotiate_starttls(sock, protocol.upper(), server_hostname or host)
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        connection = SSL.Connection(context, sock)
        if server_hostname:
            connection.set_tlsext_host_name(server_hostname.encode("idna"))
        connection.set_connect_state()
        connection.setblocking(True)
        connection.do_handshake()
        peer = connection.get_peer_certificate()
        if peer is None:
            raise CertificateParseError("Peer did not provide a certificate.")
        chain = connection.get_peer_cert_chain() or [peer]
        chain_der = [crypto.dump_certificate(crypto.FILETYPE_ASN1, item) for item in chain]
        return TlsConnectionResult(
            certificate_der=crypto.dump_certificate(crypto.FILETYPE_ASN1, peer),
            chain_der=chain_der,
            tls_protocol=connection.get_protocol_version_name(),
            cipher_suite=connection.get_cipher_name(),
        )
    finally:
        if connection is not None:
            try:
                connection.shutdown()
            except Exception:
                pass
            try:
                connection.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def negotiate_starttls(sock: socket.socket, protocol: str, client_name: str) -> None:
    """Upgrade a plaintext application connection before the TLS handshake."""
    reader = sock.makefile("rb")
    try:
        if protocol == "SMTP":
            _expect_line(reader, (b"220",), "SMTP greeting")
            sock.sendall(f"EHLO {client_name}\r\n".encode("idna"))
            _read_smtp_response(reader, b"250", "SMTP EHLO")
            sock.sendall(b"STARTTLS\r\n")
            _expect_line(reader, (b"220",), "SMTP STARTTLS")
        elif protocol == "IMAP":
            _expect_line(reader, (b"* OK",), "IMAP greeting")
            sock.sendall(b"A001 STARTTLS\r\n")
            _expect_line(reader, (b"A001 OK",), "IMAP STARTTLS")
        elif protocol == "POP3":
            _expect_line(reader, (b"+OK",), "POP3 greeting")
            sock.sendall(b"STLS\r\n")
            _expect_line(reader, (b"+OK",), "POP3 STLS")
        elif protocol == "LDAP":
            # LDAPMessage(messageID=1, extendedReq(1.3.6.1.4.1.1466.20037))
            sock.sendall(bytes.fromhex("301d02010177188016312e332e362e312e342e312e313436362e3230303337"))
            response = sock.recv(4096)
            if b"\x0a\x01\x00" not in response:
                raise StartTlsNegotiationError("LDAP StartTLS request was rejected.")
        else:
            raise UnsupportedProtocolError(f"Unsupported STARTTLS protocol: {protocol}")
    finally:
        reader.close()


def _expect_line(reader: object, prefixes: tuple[bytes, ...], stage: str) -> bytes:
    line = reader.readline(65536)
    if not line or not any(line.upper().startswith(prefix) for prefix in prefixes):
        detail = line.decode("utf-8", errors="replace").strip()
        raise StartTlsNegotiationError(f"{stage} failed: {detail or 'connection closed'}")
    return line


def _read_smtp_response(reader: object, expected_code: bytes, stage: str) -> None:
    line = _expect_line(reader, (expected_code,), stage)
    while len(line) >= 4 and line[3:4] == b"-":
        line = _expect_line(reader, (expected_code,), stage)


def parse_certificate(cert_bytes: bytes, chain_der: list[bytes] | None = None) -> WorkerCertificate:
    try:
        certificate = x509.load_der_x509_certificate(cert_bytes)
        public_key = certificate.public_key()
        public_key_size = getattr(public_key, "key_size", None)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key_algorithm = "RSA"
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key_algorithm = "DSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key_algorithm = "EC"
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key_algorithm = "EdDSA"
        else:
            public_key_algorithm = type(public_key).__name__

        common_name = first_name_value(certificate.subject, NameOID.COMMON_NAME)
        sans = extract_sans(certificate)
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        return WorkerCertificate(
            fingerprintSha256=hashlib.sha256(cert_bytes).hexdigest().upper(),
            serialNumber=format(certificate.serial_number, "x").upper(),
            subject=certificate.subject.rfc4514_string(),
            commonName=common_name,
            issuer=certificate.issuer.rfc4514_string(),
            notBeforeUtc=certificate.not_valid_before_utc,
            notAfterUtc=certificate.not_valid_after_utc,
            signatureAlgorithm=certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else None,
            publicKeyAlgorithm=public_key_algorithm,
            publicKeySize=public_key_size,
            version=certificate.version.value,
            isSelfSigned=certificate.issuer == certificate.subject,
            pemEncodedCertificate=pem,
            subjectAlternativeNames=sans,
            chainEntries=parse_certificate_chain(chain_der or [cert_bytes]),
        )
    except Exception as exc:
        raise CertificateParseError(str(exc)) from exc


def parse_certificate_chain(chain_der: list[bytes]) -> list[WorkerCertificateChainEntry]:
    return [parse_certificate_chain_entry(cert_bytes, index) for index, cert_bytes in enumerate(chain_der)]


def parse_certificate_chain_entry(cert_bytes: bytes, position: int) -> WorkerCertificateChainEntry:
    certificate = x509.load_der_x509_certificate(cert_bytes)
    public_key = certificate.public_key()
    public_key_size = getattr(public_key, "key_size", None)
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key_algorithm = "EdDSA"
    else:
        public_key_algorithm = type(public_key).__name__

    return WorkerCertificateChainEntry(
        position=position,
        fingerprintSha256=hashlib.sha256(cert_bytes).hexdigest().upper(),
        serialNumber=format(certificate.serial_number, "x").upper(),
        subject=certificate.subject.rfc4514_string(),
        commonName=first_name_value(certificate.subject, NameOID.COMMON_NAME),
        issuer=certificate.issuer.rfc4514_string(),
        notBeforeUtc=certificate.not_valid_before_utc,
        notAfterUtc=certificate.not_valid_after_utc,
        signatureAlgorithm=certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else None,
        publicKeyAlgorithm=public_key_algorithm,
        publicKeySize=public_key_size,
        version=certificate.version.value,
        isSelfSigned=certificate.issuer == certificate.subject,
        pemEncodedCertificate=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def first_name_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def extract_sans(certificate: x509.Certificate) -> list[SubjectAlternativeName]:
    try:
        extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    values: list[SubjectAlternativeName] = []
    for dns in extension.get_values_for_type(x509.DNSName):
        values.append(SubjectAlternativeName(name=dns, type="DNS"))
    for ip in extension.get_values_for_type(x509.IPAddress):
        values.append(SubjectAlternativeName(name=str(ip), type="IP"))
    for email in extension.get_values_for_type(x509.RFC822Name):
        values.append(SubjectAlternativeName(name=email, type="Email"))
    for uri in extension.get_values_for_type(x509.UniformResourceIdentifier):
        values.append(SubjectAlternativeName(name=uri, type="URI"))
    return values


def map_error(exc: Exception) -> ScanErrorType:
    if isinstance(exc, UnsupportedProtocolError):
        return ScanErrorType.unsupported_protocol
    if isinstance(exc, DnsResolutionError):
        return ScanErrorType.dns_resolution_failed
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return ScanErrorType.connection_timeout
    if isinstance(exc, ConnectionRefusedError):
        return ScanErrorType.connection_refused
    if isinstance(exc, (ssl.SSLError, SSL.Error)):
        return ScanErrorType.tls_handshake_failed
    if isinstance(exc, StartTlsNegotiationError):
        return ScanErrorType.tls_handshake_failed
    if isinstance(exc, CertificateParseError):
        return ScanErrorType.certificate_parse_failed
    return ScanErrorType.internal_error


class DnsResolutionError(Exception):
    pass


class CertificateParseError(Exception):
    pass


class UnsupportedProtocolError(Exception):
    pass


class StartTlsNegotiationError(Exception):
    pass
