import asyncio
import ipaddress
import socket
import time
from datetime import UTC, datetime

from .discovery import CertificateParseError, connect_tls_with_chain, map_error, parse_certificate
from .models import ScanErrorType, ScanResultStatus, WorkerDiscoveryResult

PORT_PROTOCOLS = {
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    636: "LDAPS",
}


def expand_targets(cidr: str, ports: list[int]) -> list[tuple[str, int]]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    if network.prefixlen == 32:
        hosts = [str(network.network_address)]
    return [(host, port) for host in hosts for port in ports]


async def scan_endpoint(job_id: str, ip_address: str, port: int, timeout_seconds: int) -> WorkerDiscoveryResult:
    started = datetime.now(UTC)
    start_counter = time.perf_counter()
    protocol = PORT_PROTOCOLS.get(port, "TLS")
    reverse_dns: str | None = None
    try:
        reverse_dns = await reverse_lookup(ip_address)
        tls_result = await connect_tls_with_chain(ip_address, port, reverse_dns, timeout_seconds)
        if not tls_result.certificate_der:
            raise CertificateParseError("Peer did not provide a certificate.")
        certificate = parse_certificate(tls_result.certificate_der, tls_result.chain_der)
        completed = datetime.now(UTC)
        return WorkerDiscoveryResult(
            discoveryJobId=job_id,
            ipAddress=ip_address,
            port=port,
            protocolGuess=protocol,
            status=ScanResultStatus.success,
            startedAtUtc=started,
            completedAtUtc=completed,
            durationMilliseconds=int((time.perf_counter() - start_counter) * 1000),
            tlsProtocol=tls_result.tls_protocol,
            cipherSuite=tls_result.cipher_suite,
            certificate=certificate,
            reverseDnsName=reverse_dns,
        )
    except Exception as exc:
        completed = datetime.now(UTC)
        return WorkerDiscoveryResult(
            discoveryJobId=job_id,
            ipAddress=ip_address,
            port=port,
            protocolGuess=protocol,
            status=ScanResultStatus.failed,
            startedAtUtc=started,
            completedAtUtc=completed,
            durationMilliseconds=int((time.perf_counter() - start_counter) * 1000),
            reverseDnsName=reverse_dns,
            errorType=map_error(exc),
            errorMessage=str(exc),
            rawDiagnosticData=type(exc).__name__,
        )


async def reverse_lookup(ip_address: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip_address)
        return host
    except Exception:
        return None
