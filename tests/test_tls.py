import hashlib
import unittest
from unittest import mock

from tlsinfo import inspect_tls_certificate


class _FakeWrappedSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getpeercert(self, binary_form=False):
        if binary_form:
            return b"certificate-bytes"
        return {
            "subject": ((('commonName', 'example.test'),),),
            "issuer": ((('commonName', 'Example CA'),),),
            "subjectAltName": (("DNS", "example.test"),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 00:00:00 2026 GMT",
        }


class _FakeTcpSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeContext:
    def __init__(self):
        self.check_hostname = True
        self.verify_mode = None

    def wrap_socket(self, sock, server_hostname=None):
        return _FakeWrappedSocket()


class TlsTests(unittest.TestCase):
    @mock.patch("tlsinfo.ssl.create_default_context", return_value=_FakeContext())
    @mock.patch("tlsinfo.socket.create_connection", return_value=_FakeTcpSocket())
    def test_inspect_tls_certificate(self, _create_connection, _create_default_context) -> None:
        result = inspect_tls_certificate("203.0.113.10", port=443, timeout=1.0, insecure=False)
        self.assertEqual(result["subject"]["commonName"], "example.test")
        self.assertEqual(result["issuer"]["commonName"], "Example CA")
        self.assertEqual(result["sha256"], hashlib.sha256(b"certificate-bytes").hexdigest())


if __name__ == "__main__":
    unittest.main()
