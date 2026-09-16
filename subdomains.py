from __future__ import annotations

import ipaddress
import json
import subprocess
from shutil import which
from typing import Any

from plugins import PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord, HostRecord


class SubfinderError(PluginError):
    """Falha ao executar subfinder."""



def enumerate_subdomains(
    domain: str,
    *,
    timeout: float,
    binary: str = "subfinder",
    runner: Any = subprocess.run,
) -> list[str]:
    if timeout <= 0:
        raise SubfinderError("Timeout do subfinder deve ser maior que zero.")
    normalized_domain = validate_domain(domain)
    executable = which(binary)
    if executable is None:
        raise SubfinderError("Binário 'subfinder' ausente no PATH.")
    command = [executable, "-d", normalized_domain, "-silent", "-json"]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SubfinderError(f"subfinder excedeu o timeout ao enumerar {normalized_domain}.") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "erro desconhecido").strip()
        raise SubfinderError(f"subfinder falhou: {detail[:400]}")
    results: list[str] = []
    for line_number, line in enumerate(completed.stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SubfinderError(f"subfinder retornou JSONL inválido na linha {line_number}.") from exc
        if not isinstance(payload, dict):
            raise SubfinderError(f"subfinder retornou um registro não-objeto na linha {line_number}.")
        host = payload.get("host") or payload.get("subdomain") or payload.get("input")
        if host and host not in results:
            results.append(host)
    return results


def validate_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253 or "://" in candidate or "/" in candidate:
        raise SubfinderError(f"Domínio inválido: {value!r}.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise SubfinderError("Enumeração de subdomínios exige um domínio, não um endereço IP.")
    labels = candidate.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in labels
    ):
        raise SubfinderError(f"Domínio inválido: {value!r}.")
    return candidate


@register_plugin(
    name="subdomains",
    description="Enumera subdomínios com subfinder somente quando solicitado.",
    profiles=("web",),
    traffic="dns-enumeration",
    opt_in=True,
    requirements=("subfinder",),
)
def subdomains_plugin(context: ScanContext) -> PluginResult:
    if context.scope:
        context.scope.assert_allowed(context.target, label="domain")
    domains = enumerate_subdomains(
        context.target,
        timeout=float(context.options.get("subdomains_timeout") or context.timeout),
        binary=str(context.options.get("subdomains_binary") or "subfinder"),
    )
    hosts = [
        HostRecord(address=domain, hostnames=[domain], source="subfinder")
        for domain in domains
    ]
    findings = [
        FindingRecord(
            host=domain,
            title="Subdomínio encontrado",
            plugin="subdomains",
            severity="info",
            description=f"Subfinder encontrou {domain}.",
            category="subdomain-enumeration",
        )
        for domain in domains
    ]
    return PluginResult(
        hosts=hosts,
        findings=findings,
        metadata={"domain": context.target, "count": len(domains)},
    )
