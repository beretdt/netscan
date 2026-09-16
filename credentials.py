from __future__ import annotations

import base64
import ftplib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from plugins import PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord


DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("root", "root"),
    ("support", "support"),
]


class DefaultCredentialError(PluginError):
    """Falha operacional no módulo de credenciais padrão."""



def load_credentials_file(path: str | Path | None) -> list[tuple[str, str]]:
    if path is None:
        return list(DEFAULT_CREDENTIALS)
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DefaultCredentialError(f"Arquivo de credenciais inválido: {path}.") from exc
    if not isinstance(payload, list):
        raise DefaultCredentialError("O arquivo de credenciais deve conter uma lista JSON.")
    credentials: list[tuple[str, str]] = []
    for item in payload:
        try:
            if isinstance(item, dict):
                credentials.append((str(item["username"]), str(item["password"])))
            else:
                username, password = item
                credentials.append((str(username), str(password)))
        except (KeyError, TypeError, ValueError) as exc:
            raise DefaultCredentialError(
                "Cada credencial deve ser um objeto username/password ou um par [username, password]."
            ) from exc
    if not credentials:
        raise DefaultCredentialError("A lista de credenciais não pode ser vazia.")
    return credentials


@register_plugin(
    name="default-creds",
    description="Testa pequena lista opt-in de credenciais padrão em HTTP Basic e FTP.",
    profiles=("audit",),
    depends_on=("nmap-service",),
    traffic="authenticated-probe",
    opt_in=True,
)
def default_credentials_plugin(context: ScanContext) -> PluginResult:
    findings: list[FindingRecord] = []
    credentials = context.options.get("default_credentials") or list(DEFAULT_CREDENTIALS)
    max_attempts = int(context.options.get("default_creds_max_attempts") or len(credentials))
    rate_limit = float(context.options.get("default_creds_rate_limit") or 0.25)
    timeout = float(context.options.get("default_creds_timeout") or context.timeout)
    insecure = bool(context.options.get("default_creds_insecure"))
    if max_attempts < 1:
        raise DefaultCredentialError("default_creds_max_attempts deve ser maior que zero.")
    if rate_limit < 0:
        raise DefaultCredentialError("default_creds_rate_limit não pode ser negativo.")
    if timeout <= 0:
        raise DefaultCredentialError("default_creds_timeout deve ser maior que zero.")
    for host in context.iter_hosts():
        for port in host.ports:
            if port.state != "open":
                continue
            service = (port.service or "").lower()
            candidates = list(credentials)[:max_attempts]
            if service.startswith("http") or port.port in {80, 443, 8080, 8443}:
                findings.extend(_check_http_basic(host.address, port.port, service, candidates, timeout, rate_limit, insecure))
            elif service == "ftp" or port.port == 21:
                findings.extend(_check_ftp(host.address, port.port, candidates, timeout, rate_limit))
    return PluginResult(findings=findings, metadata={"attempted_protocols": ["http-basic", "ftp"]})



def _check_http_basic(
    host: str,
    port: int,
    service: str,
    credentials: Iterable[tuple[str, str]],
    timeout: float,
    rate_limit: float,
    insecure: bool,
) -> list[FindingRecord]:
    scheme = "https" if "https" in service or port in {443, 8443} else "http"
    url = f"{scheme}://{host}:{port}/"
    request = urllib.request.Request(url, method="GET")
    try:
        context = None
        if scheme == "https" and insecure:
            import ssl

            context = ssl._create_unverified_context()  # noqa: SLF001
        with urllib.request.urlopen(request, timeout=timeout, context=context):
            return []
    except urllib.error.HTTPError as exc:
        challenge = exc.headers.get("WWW-Authenticate", "")
        if exc.code != 401 or "basic" not in challenge.lower():
            return []
    except OSError:
        return []

    findings: list[FindingRecord] = []
    for username, password in credentials:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        auth_request = urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {token}"},
            method="GET",
        )
        try:
            context = None
            if scheme == "https" and insecure:
                import ssl

                context = ssl._create_unverified_context()  # noqa: SLF001
            with urllib.request.urlopen(auth_request, timeout=timeout, context=context) as response:
                if response.status < 400:
                    findings.append(
                        FindingRecord(
                            host=host,
                            title=f"Credencial padrão aceita em {scheme.upper()} Basic",
                            plugin="default-creds",
                            severity="high",
                            description=f"{username}:{password} autenticou em {url}.",
                            category="default-credentials",
                            port=port,
                            protocol="tcp",
                            evidence={"username": username, "url": url},
                        )
                    )
                    break
        except urllib.error.HTTPError:
            pass
        except OSError:
            break
        finally:
            time.sleep(rate_limit)
    return findings



def _check_ftp(
    host: str,
    port: int,
    credentials: Iterable[tuple[str, str]],
    timeout: float,
    rate_limit: float,
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for username, password in credentials:
        ftp = ftplib.FTP()
        try:
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)
            findings.append(
                FindingRecord(
                    host=host,
                    title="Credencial padrão aceita em FTP",
                    plugin="default-creds",
                    severity="high",
                    description=f"{username}:{password} autenticou em ftp://{host}:{port}/.",
                    category="default-credentials",
                    port=port,
                    protocol="tcp",
                    evidence={"username": username},
                )
            )
            break
        except (ftplib.Error, OSError):
            pass
        finally:
            try:
                ftp.close()
            except (AttributeError, OSError):
                pass
            time.sleep(rate_limit)
    return findings
