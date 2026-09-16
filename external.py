from __future__ import annotations

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET
from shutil import which
from typing import Any

from plugins import PluginResult, ScanContext, register_plugin
from schema import HostRecord, PortRecord


DEFAULT_EXTERNAL_TIMEOUT = 300.0
DEFAULT_TOP_PORTS = 100
MIN_EXTERNAL_TIMEOUT = 5.0
MAX_EXTERNAL_TIMEOUT = 3600.0


class NmapError(RuntimeError):
    """Erro operacional ao executar ou interpretar o Nmap."""



def validate_target(value: Any) -> str:
    raw_value = str(value).strip() if value is not None else ""
    if not raw_value:
        raise NmapError("Informe um endereço IPv4 ou IPv6 para o scan externo.")

    try:
        address = ipaddress.ip_address(raw_value)
    except ValueError as exc:
        raise NmapError(
            "O alvo externo deve ser um endereço IP, não um hostname ou CIDR."
        ) from exc

    return str(address)



def validate_ports(value: Any) -> str:
    raw_value = str(value).strip() if value is not None else ""
    if not raw_value or not re.fullmatch(r"[0-9,-]+", raw_value):
        raise NmapError(
            "Portas inválidas. Use formatos como 22,80,443 ou 1-1024."
        )

    normalized_parts: list[str] = []
    for part in raw_value.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or any(not bound for bound in bounds):
            raise NmapError(f"Faixa de portas inválida: {part!r}.")

        try:
            start = int(bounds[0])
            end = int(bounds[-1])
        except ValueError as exc:
            raise NmapError(f"Porta inválida: {part!r}.") from exc

        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise NmapError(f"Porta fora do intervalo permitido: {part!r}.")

        normalized_parts.append(str(start) if len(bounds) == 1 else f"{start}-{end}")

    return ",".join(normalized_parts)



def validate_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise NmapError(f"Timeout externo inválido: {value!r}.") from exc

    if not (MIN_EXTERNAL_TIMEOUT <= timeout <= MAX_EXTERNAL_TIMEOUT):
        raise NmapError(
            f"Timeout externo deve ficar entre {MIN_EXTERNAL_TIMEOUT:g} e "
            f"{MAX_EXTERNAL_TIMEOUT:g} segundos."
        )

    return timeout



def validate_top_ports(value: Any) -> int:
    try:
        top_ports = int(value)
    except (TypeError, ValueError) as exc:
        raise NmapError(f"Quantidade de portas inválida: {value!r}.") from exc

    if not 1 <= top_ports <= 1000:
        raise NmapError("A quantidade de portas deve ficar entre 1 e 1000.")

    return top_ports



def run_nmap(
    target: Any,
    *,
    ports: Any | None = None,
    top_ports: Any = DEFAULT_TOP_PORTS,
    timeout: Any = DEFAULT_EXTERNAL_TIMEOUT,
    os_detect: bool = False,
) -> dict[str, Any]:
    normalized_target = validate_target(target)
    validated_timeout = validate_timeout(timeout)
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
        "-sT",
        "-sV",
        "--open",
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
            timeout=validated_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(
            f"Nmap excedeu o timeout de {validated_timeout:g} segundos para {normalized_target}."
        ) from exc
    except OSError as exc:
        raise NmapError(f"Não foi possível iniciar o Nmap: {exc}.") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()
        suffix = f": {detail[:400]}" if detail else "."
        raise NmapError(f"Nmap terminou com código {completed.returncode}{suffix}")

    try:
        return parse_nmap_xml(completed.stdout, normalized_target)
    except ET.ParseError as exc:
        raise NmapError(f"Nmap retornou XML inválido: {exc}.") from exc



def parse_nmap_xml(xml_text: str, target: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        addresses = {
            address.get("addrtype"): address.get("addr")
            for address in host.findall("address")
            if address.get("addrtype") and address.get("addr")
        }
        hostnames = [
            hostname.get("name")
            for hostname in host.findall("hostnames/hostname")
            if hostname.get("name")
        ]

        parsed_ports: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            port_id = port.get("portid")
            if port_id is None:
                continue

            parsed_ports.append(
                {
                    "port": int(port_id),
                    "protocol": port.get("protocol", ""),
                    "state": state.get("state") if state is not None else "unknown",
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "extra": service.get("extrainfo", "") if service is not None else "",
                    "tunnel": service.get("tunnel", "") if service is not None else "",
                }
            )

        os_matches = [
            {
                "name": match.get("name", ""),
                "accuracy": match.get("accuracy", ""),
            }
            for match in host.findall("os/osmatch")
            if match.get("name")
        ]

        hosts.append(
            {
                "ip": addresses.get("ipv4") or addresses.get("ipv6") or target,
                "state": status.get("state") if status is not None else "unknown",
                "hostnames": hostnames,
                "mac": addresses.get("mac"),
                "vendor": next(
                    (
                        address.get("vendor")
                        for address in host.findall("address")
                        if address.get("addrtype") == "mac" and address.get("vendor")
                    ),
                    None,
                ),
                "ports": sorted(parsed_ports, key=lambda item: (item["port"], item["protocol"])),
                "os": os_matches[:3],
            }
        )

    return {
        "target": target,
        "nmap_version": root.get("version"),
        "hosts": hosts,
    }



def nmap_hosts_to_records(result: dict[str, Any]) -> list[HostRecord]:
    records: list[HostRecord] = []
    for item in result.get("hosts", []):
        ports = [
            PortRecord(
                port=port["port"],
                protocol=port.get("protocol") or "tcp",
                state=port.get("state") or "unknown",
                service=port.get("service") or "",
                product=port.get("product") or "",
                version=port.get("version") or "",
                extra=port.get("extra") or "",
                metadata={"tunnel": port.get("tunnel") or ""},
            )
            for port in item.get("ports", [])
        ]
        records.append(
            HostRecord(
                address=item["ip"],
                state=item.get("state") or "unknown",
                hostnames=[name for name in item.get("hostnames", []) if name],
                mac=item.get("mac"),
                vendor=item.get("vendor"),
                source="nmap",
                ports=ports,
                metadata={"os": item.get("os", [])},
            )
        )
    return records


@register_plugin(
    name="nmap-service",
    description="Descoberta ativa de portas e banners via Nmap XML.",
    profiles=("basic", "enrich", "web", "audit"),
    traffic="tcp-connect",
    requirements=("nmap",),
)
def nmap_service_plugin(context: ScanContext) -> PluginResult:
    result = run_nmap(
        context.target,
        ports=context.options.get("ports"),
        top_ports=context.options.get("top_ports", DEFAULT_TOP_PORTS),
        timeout=context.options.get("external_timeout", context.timeout),
        os_detect=bool(context.options.get("os_detect")),
    )
    metadata = {"nmap_version": result.get("nmap_version")}
    return PluginResult(hosts=nmap_hosts_to_records(result), metadata=metadata)
