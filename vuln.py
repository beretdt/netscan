from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from external import (
    DEFAULT_TOP_PORTS,
    NmapError,
    validate_ports,
    validate_target,
    validate_timeout,
    validate_top_ports,
)
from plugins import PluginResult, ScanContext, register_plugin
from schema import FindingRecord


DEFAULT_VULN_TIMEOUT = 900.0
DEFAULT_SCRIPT_TIMEOUT = 120.0
MIN_SCRIPT_TIMEOUT = 5.0
MAX_SCRIPT_TIMEOUT = 600.0
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)



def _severity(output: str) -> str:
    normalized = output.upper()
    if "NOT VULNERABLE" in normalized:
        return "OK"
    if "LIKELY VULNERABLE" in normalized:
        return "MEDIA"
    if "STATE: VULNERABLE" in normalized or normalized.lstrip().startswith("VULNERABLE"):
        return "ALTA"
    return "INFO"



def _cves(output: str) -> list[str]:
    return sorted({match.upper() for match in CVE_PATTERN.findall(output)})



def _validate_script_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise NmapError(f"Timeout dos scripts inválido: {value!r}.") from exc

    if not (MIN_SCRIPT_TIMEOUT <= timeout <= MAX_SCRIPT_TIMEOUT):
        raise NmapError(
            f"Timeout dos scripts deve ficar entre {MIN_SCRIPT_TIMEOUT:g} e "
            f"{MAX_SCRIPT_TIMEOUT:g} segundos."
        )

    return timeout



def run_vulnerability_scan(
    target: Any,
    *,
    ports: Any | None = None,
    top_ports: Any = DEFAULT_TOP_PORTS,
    timeout: Any = DEFAULT_VULN_TIMEOUT,
    script_timeout: Any = DEFAULT_SCRIPT_TIMEOUT,
    os_detect: bool = False,
) -> dict[str, Any]:
    """Executa os scripts NSE da categoria vuln em um único endereço IP."""
    from shutil import which

    normalized_target = validate_target(target)
    validated_timeout = validate_timeout(timeout)
    validated_script_timeout = _validate_script_timeout(script_timeout)
    binary = which("nmap")
    if binary is None:
        raise NmapError(
            "Nmap não foi encontrado no PATH. Instale-o em https://nmap.org/download.html "
            "e abra um novo terminal."
        )

    command = [
        binary,
        "-Pn",
        "-n",
        "-sV",
        "--script",
        "vuln",
        "--script-timeout",
        f"{validated_script_timeout:g}s",
        "--host-timeout",
        f"{validated_timeout:g}s",
        "-T3",
        "-oX",
        "-",
    ]
    if ports is not None:
        command.extend(["-p", validate_ports(ports)])
    else:
        command.extend(["--top-ports", str(validate_top_ports(top_ports))])
    if os_detect:
        command.append("-O")
    command.append(normalized_target)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=validated_timeout + validated_script_timeout + 60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(
            f"Scan de vulnerabilidades excedeu o timeout para {normalized_target}."
        ) from exc
    except OSError as exc:
        raise NmapError(f"Não foi possível iniciar o Nmap: {exc}.") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()
        suffix = f": {detail[:400]}" if detail else "."
        raise NmapError(f"Nmap terminou com código {completed.returncode}{suffix}")

    try:
        return parse_vulnerability_xml(completed.stdout, normalized_target)
    except ET.ParseError as exc:
        raise NmapError(f"Nmap retornou XML inválido: {exc}.") from exc



def _parse_script(script: ET.Element, *, port: dict[str, Any] | None) -> dict[str, Any]:
    output = script.get("output", "").strip()
    return {
        "port": port["port"] if port else None,
        "protocol": port["protocol"] if port else None,
        "service": port["service"] if port else "host",
        "script": script.get("id", "unknown"),
        "severity": _severity(output),
        "cves": _cves(output),
        "output": output,
    }



def parse_vulnerability_xml(xml_text: str, target: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    result: dict[str, Any] = {
        "target": target,
        "host_state": "unknown",
        "hostname": None,
        "os": None,
        "ports": [],
        "findings": [],
    }

    host = root.find("host")
    if host is None:
        return result

    status = host.find("status")
    result["host_state"] = status.get("state") if status is not None else "unknown"
    hostname = host.find("hostnames/hostname")
    result["hostname"] = hostname.get("name") if hostname is not None else None
    os_match = host.find("os/osmatch")
    result["os"] = os_match.get("name") if os_match is not None else None

    for port_element in host.findall("ports/port"):
        state = port_element.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port_element.find("service")
        port_id = port_element.get("portid")
        if port_id is None:
            continue

        port = {
            "port": int(port_id),
            "protocol": port_element.get("protocol", ""),
            "service": service.get("name", "") if service is not None else "",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "") if service is not None else "",
            "scripts": [],
        }
        for script in port_element.findall("script"):
            finding = _parse_script(script, port=port)
            port["scripts"].append(
                {
                    "script": finding["script"],
                    "severity": finding["severity"],
                    "cves": finding["cves"],
                }
            )
            result["findings"].append(finding)

        result["ports"].append(port)

    for script in host.findall("hostscript/script"):
        result["findings"].append(_parse_script(script, port=None))

    result["ports"].sort(key=lambda item: (item["port"], item["protocol"]))
    return result


@register_plugin(
    name="nmap-vuln",
    description="Executa scripts NSE da categoria vuln do Nmap.",
    profiles=("audit",),
    depends_on=("nmap-service",),
    traffic="nmap-nse",
    opt_in=True,
    requirements=("nmap",),
)
def nmap_vuln_plugin(context: ScanContext) -> PluginResult:
    result = run_vulnerability_scan(
        context.target,
        ports=context.options.get("ports"),
        top_ports=context.options.get("top_ports", DEFAULT_TOP_PORTS),
        timeout=context.options.get("vuln_timeout", DEFAULT_VULN_TIMEOUT),
        script_timeout=context.options.get("script_timeout", DEFAULT_SCRIPT_TIMEOUT),
        os_detect=bool(context.options.get("os_detect")),
    )
    findings = [
        FindingRecord(
            host=context.target,
            title=f"Nmap NSE {item['script']}",
            plugin="nmap-vuln",
            severity=str(item["severity"]).lower(),
            description=item["output"],
            category="vulnerability",
            port=item["port"],
            protocol=item["protocol"],
            cves=list(item["cves"]),
            evidence={"service": item["service"]},
        )
        for item in result.get("findings", [])
        if item.get("severity") != "OK"
    ]
    return PluginResult(findings=findings, metadata={"raw": result})
