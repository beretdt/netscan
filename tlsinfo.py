from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime
from typing import Any

from plugins import PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord, PortRecord


DEFAULT_TLS_TIMEOUT = 3.0


class TLSInspectionError(PluginError):
    """Falha ao coletar informações TLS."""



def inspect_tls_certificate(
    target: str,
    *,
    port: int,
    timeout: float = DEFAULT_TLS_TIMEOUT,
    insecure: bool = False,
) -> dict[str, Any]:
    if not 0.1 <= timeout <= 120.0:
        raise TLSInspectionError("Timeout TLS deve ficar entre 0.1 e 120 segundos.")
    if not 1 <= port <= 65535:
        raise TLSInspectionError("Porta TLS deve ficar entre 1 e 65535.")
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    server_hostname = None if insecure else target
    try:
        with socket.create_connection((target, port), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=server_hostname) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)
                certificate = tls_socket.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise TLSInspectionError(
            f"A validação TLS falhou para {target}:{port}: {exc}. Use --insecure explicitamente se precisar apenas inspecionar."
        ) from exc
    except ssl.SSLError as exc:
        raise TLSInspectionError(f"Falha TLS em {target}:{port}: {exc}.") from exc
    except OSError as exc:
        raise TLSInspectionError(f"Falha de conexão TLS em {target}:{port}: {exc}.") from exc

    result = {
        "subject": _flatten_name(certificate.get("subject") or ()),
        "issuer": _flatten_name(certificate.get("issuer") or ()),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind in {"DNS", "IP Address"}],
        "not_before": _parse_ssl_time(certificate.get("notBefore")),
        "not_after": _parse_ssl_time(certificate.get("notAfter")),
        "sha256": hashlib.sha256(der_certificate).hexdigest(),
        "validated": not insecure,
    }
    if parsed := _parse_with_cryptography(der_certificate):
        result.update(parsed)
    return result


@register_plugin(
    name="tls",
    description="Coleta issuer, subject, SANs, validade e SHA-256 de portas TLS/HTTPS.",
    profiles=("enrich", "web", "audit"),
    depends_on=("nmap-service",),
    traffic="tcp-tls",
    opt_in=True,
)
def tls_plugin(context: ScanContext) -> PluginResult:
    findings: list[FindingRecord] = []
    for host in context.iter_hosts():
        for port in host.ports:
            if not _looks_like_tls_service(port):
                continue
            tls_info = inspect_tls_certificate(
                host.address,
                port=port.port,
                timeout=float(context.options.get("tls_timeout") or context.timeout),
                insecure=bool(context.options.get("tls_insecure")),
            )
            port.tls = tls_info
            expires = tls_info.get("not_after")
            findings.append(
                FindingRecord(
                    host=host.address,
                    title=f"Certificado TLS coletado em {port.port}/{port.protocol}",
                    plugin="tls",
                    severity="info",
                    description=f"Issuer: {tls_info.get('issuer', {}).get('commonName', 'desconhecido')}",
                    category="tls",
                    port=port.port,
                    protocol=port.protocol,
                    evidence={"sha256": tls_info["sha256"], "not_after": expires},
                )
            )
    return PluginResult(findings=findings)



def _looks_like_tls_service(port: PortRecord) -> bool:
    if port.protocol.lower() not in {"", "tcp"}:
        return False
    service = (port.service or "").lower()
    extra = (port.extra or "").lower()
    return service.startswith("https") or service in {"ssl", "tls"} or "ssl" in extra or port.port in {443, 465, 587, 636, 853, 8443}



def _flatten_name(parts: Any) -> dict[str, str]:
    flattened: dict[str, str] = {}
    for group in parts:
        for key, value in group:
            flattened[key] = value
    return flattened



def _parse_ssl_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").isoformat()
    except ValueError:
        return value



def _parse_with_cryptography(der_certificate: bytes) -> dict[str, Any] | None:
    try:
        from cryptography import x509  # type: ignore[import-untyped]
        from cryptography.hazmat.primitives import hashes  # type: ignore[import-untyped]
    except ImportError:
        return None

    certificate = x509.load_der_x509_certificate(der_certificate)
    sans: list[str] = []
    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(value.value) for value in san_extension.value]
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject": _x509_name_to_dict(certificate.subject),
        "issuer": _x509_name_to_dict(certificate.issuer),
        "subject_alt_names": sans,
        "signature_hash": certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else None,
        "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
    }



def _x509_name_to_dict(name: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for attribute in name:
        key = attribute.oid._name or attribute.oid.dotted_string
        result[key] = attribute.value
    return result
