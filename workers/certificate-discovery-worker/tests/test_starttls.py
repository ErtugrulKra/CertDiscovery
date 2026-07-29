import io

import pytest

from worker.discovery import StartTlsNegotiationError, negotiate_starttls


class FakeSocket:
    def __init__(self, transcript: bytes, recv_data: bytes = b"") -> None:
        self.reader = io.BytesIO(transcript)
        self.recv_data = recv_data
        self.sent = bytearray()

    def makefile(self, _mode: str) -> io.BytesIO:
        return self.reader

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, _size: int) -> bytes:
        return self.recv_data


@pytest.mark.parametrize(
    ("protocol", "transcript", "expected"),
    [
        ("SMTP", b"220 mail.test ESMTP\r\n250-mail.test\r\n250 STARTTLS\r\n220 Ready\r\n", b"EHLO mail.test\r\nSTARTTLS\r\n"),
        ("IMAP", b"* OK ready\r\nA001 OK Begin TLS\r\n", b"A001 STARTTLS\r\n"),
        ("POP3", b"+OK ready\r\n+OK Begin TLS\r\n", b"STLS\r\n"),
    ],
)
def test_negotiate_line_based_starttls(protocol: str, transcript: bytes, expected: bytes) -> None:
    sock = FakeSocket(transcript)

    negotiate_starttls(sock, protocol, "mail.test")

    assert bytes(sock.sent) == expected


def test_negotiate_ldap_starttls() -> None:
    sock = FakeSocket(b"", bytes.fromhex("300c02010178070a010004000400"))

    negotiate_starttls(sock, "LDAP", "ldap.test")

    assert bytes(sock.sent).startswith(bytes.fromhex("301d0201017718"))


def test_rejected_starttls_is_reported() -> None:
    sock = FakeSocket(b"220 ready\r\n500 unavailable\r\n")

    with pytest.raises(StartTlsNegotiationError):
        negotiate_starttls(sock, "SMTP", "mail.test")
