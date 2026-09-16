from __future__ import annotations

import json
import subprocess
from shutil import which
from typing import Any
from urllib.parse import urlparse

from plugins import MissingDependencyError, PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord


class NucleiError(PluginError):
    """Falha ao executar Nuclei."""



def run_nuclei(
    urls: list[str],
    *,
    timeout: float,
    rate_limit: int,
    templates: str | None = None,
    binary: str = "nuclei",
    runner: Any = subprocess.run,
) -> list[dict[str, Any]]:
    if timeout <= 0:
        raise NucleiError("Timeout do Nuclei deve ser maior que zero.")
    if rate_limit < 1:
        raise NucleiError("Rate limit do Nuclei deve ser maior que zero.")
    executable = which(binary)
    if executable is None:
        raise MissingDependencyError("Binário 'nuclei' ausente no PATH.")
    results: list[dict[str, Any]] = []
    for url in urls:
        command = [
            executable,
            "-u",
            url,
            "-silent",
            "-jsonl",
            "-rl",
            str(rate_limit),
        ]
        if templates:
            command.extend(["-t", templates])
        try:
            completed = runner(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NucleiError(f"Nuclei excedeu o timeout em {url}.") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "erro desconhecido").strip()
            raise NucleiError(f"Nuclei falhou em {url}: {detail[:400]}")
        results.extend(parse_nuclei_jsonl(completed.stdout))
    return results



def parse_nuclei_jsonl(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise NucleiError(f"Nuclei retornou JSONL inválido na linha {line_number}.") from exc
        if not isinstance(payload, dict):
            raise NucleiError(f"Nuclei retornou um registro não-objeto na linha {line_number}.")
        findings.append(payload)
    return findings


@register_plugin(
    name="nuclei",
    description="Executa templates Nuclei em URLs HTTP/HTTPS descobertas.",
    profiles=("web", "audit"),
    depends_on=("nmap-service",),
    traffic="http-template-scan",
    opt_in=True,
    requirements=("nuclei",),
)
def nuclei_plugin(context: ScanContext) -> PluginResult:
    urls = _http_urls_from_context(context)
    rows = run_nuclei(
        urls,
        timeout=float(context.options.get("nuclei_timeout") or 120.0),
        rate_limit=int(context.options.get("nuclei_rate_limit") or 25),
        templates=context.options.get("nuclei_templates"),
    )
    findings = [
        FindingRecord(
            host=urlparse(item.get("host") or item.get("matched-at") or "").hostname or context.target,
            title=item.get("info", {}).get("name") or item.get("template-id") or "Nuclei finding",
            plugin="nuclei",
            severity=str(item.get("info", {}).get("severity") or "info").lower(),
            description=item.get("matcher-name") or item.get("template-id") or "Achado do Nuclei.",
            category="vulnerability",
            references=list(item.get("info", {}).get("reference") or []),
            evidence=item,
        )
        for item in rows
    ]
    return PluginResult(findings=findings, metadata={"urls": urls, "count": len(findings)})



def _http_urls_from_context(context: ScanContext) -> list[str]:
    urls: list[str] = []
    for host in context.iter_hosts():
        for port in host.ports:
            service = (port.service or "").lower()
            if service.startswith("http") or port.port in {80, 443, 8080, 8443}:
                scheme = "https" if "https" in service or port.port in {443, 8443} else "http"
                urls.append(f"{scheme}://{host.address}:{port.port}")
    deduped: list[str] = []
    for url in urls:
        if url not in deduped:
            deduped.append(url)
    if not deduped:
        raise NucleiError("Nenhuma URL HTTP/HTTPS descoberta para enviar ao Nuclei.")
    return deduped
