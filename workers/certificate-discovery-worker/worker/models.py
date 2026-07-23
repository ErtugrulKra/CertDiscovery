from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


PROTOCOL_BY_VALUE = {
    0: "HTTPS",
    1: "TLS",
    2: "SMTPS",
    3: "IMAPS",
    4: "POP3S",
    5: "LDAPS",
}


class ScanResultStatus(str, Enum):
    success = "Success"
    failed = "Failed"


class ScanErrorType(str, Enum):
    none = "None"
    dns_resolution_failed = "DnsResolutionFailed"
    connection_timeout = "ConnectionTimeout"
    connection_refused = "ConnectionRefused"
    tls_handshake_failed = "TlsHandshakeFailed"
    certificate_parse_failed = "CertificateParseFailed"
    unsupported_protocol = "UnsupportedProtocol"
    internal_error = "InternalError"


class WorkerAsset(BaseModel):
    id: str
    name: str
    host: str
    port: int
    protocol: str
    sniHost: str | None = None
    timeoutSeconds: int

    @field_validator("protocol", mode="before")
    @classmethod
    def normalize_protocol(cls, value: object) -> str:
        if isinstance(value, int):
            return PROTOCOL_BY_VALUE.get(value, str(value))
        return str(value)


class WorkerJob(BaseModel):
    jobId: str
    assets: list[WorkerAsset]


class WorkerDiscoveryJob(BaseModel):
    jobId: str
    cidr: str
    ports: list[int]
    timeoutSeconds: int
    maxConcurrency: int


class SubjectAlternativeName(BaseModel):
    name: str
    type: str


class WorkerCertificate(BaseModel):
    fingerprintSha256: str
    serialNumber: str | None
    subject: str
    commonName: str | None
    issuer: str
    notBeforeUtc: datetime
    notAfterUtc: datetime
    signatureAlgorithm: str | None
    publicKeyAlgorithm: str | None
    publicKeySize: int | None
    version: int | None
    isSelfSigned: bool
    pemEncodedCertificate: str
    subjectAlternativeNames: list[SubjectAlternativeName]
    chainEntries: list["WorkerCertificateChainEntry"] = Field(default_factory=list)


class WorkerCertificateChainEntry(BaseModel):
    position: int
    fingerprintSha256: str
    serialNumber: str | None
    subject: str
    commonName: str | None
    issuer: str
    notBeforeUtc: datetime
    notAfterUtc: datetime
    signatureAlgorithm: str | None
    publicKeyAlgorithm: str | None
    publicKeySize: int | None
    version: int | None
    isSelfSigned: bool
    pemEncodedCertificate: str


class WorkerScanResult(BaseModel):
    scanJobId: str
    assetId: str
    status: ScanResultStatus
    startedAtUtc: datetime
    completedAtUtc: datetime
    durationMilliseconds: int
    resolvedIpAddress: str | None = None
    tlsProtocol: str | None = None
    cipherSuite: str | None = None
    certificate: WorkerCertificate | None = None
    errorType: ScanErrorType = ScanErrorType.none
    errorMessage: str | None = None
    rawDiagnosticData: str | None = None

    def to_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class WorkerDiscoveryResult(BaseModel):
    discoveryJobId: str
    ipAddress: str
    port: int
    protocolGuess: str
    status: ScanResultStatus
    startedAtUtc: datetime
    completedAtUtc: datetime
    durationMilliseconds: int
    tlsProtocol: str | None = None
    cipherSuite: str | None = None
    certificate: WorkerCertificate | None = None
    reverseDnsName: str | None = None
    errorType: ScanErrorType = ScanErrorType.none
    errorMessage: str | None = None
    rawDiagnosticData: str | None = None

    def to_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)
