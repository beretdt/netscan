from __future__ import annotations

import ipaddress
import random
import socket
import struct
import subprocess
import time
from typing import Any, Iterable

from plugins import MissingDependencyError, PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord, HostRecord, PortRecord


DEFAULT_PASSIVE_TIMEOUT = 2.0


class PassiveDiscoveryError(PluginError):
    """Falha ao executar descoberta passiva."""


def _parse_arp_table_lines(lines: Iterable[str], source: str) -> list[HostRecord]:
    hosts: list[HostRecord] = []
    seen: set[tuple[str, str | None]] = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_candidate = parts[0]
        mac_candidate = parts[3]
        if (
            not _looks_like_ip(ip_candidate)
            or not _looks_like_mac(mac_candidate)
            or not _is_unicast_mac(mac_candidate)
        ):
            continue
        key = (ip_candidate, mac_candidate.upper())
        if key in seen:
            continue
        seen.add(key)
        hosts.append(
            HostRecord(
                address=ip_candidate,
                mac=_normalize_mac_soft(mac_candidate),
                source=source,
            )
        )
    return hosts


def read_proc_net_arp(path: str = "/proc/net/arp") -> list[HostRecord]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()[1:]
    except FileNotFoundError as exc:
        raise MissingDependencyError(f"Arquivo {path} não está disponível nesta plataforma.") from exc
    return _parse_arp_table_lines(lines, "proc-net-arp")


def read_ip_neigh(command_runner: Any = subprocess.run) -> list[HostRecord]:
    try:
        completed = command_runner(
            ["ip", "neigh"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise MissingDependencyError("Comando 'ip neigh' não encontrado no PATH.") from exc
    if completed.returncode != 0:
        raise PassiveDiscoveryError((completed.stderr or completed.stdout or "Falha ao ler ip neigh.").strip())
    hosts: list[HostRecord] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        ip_candidate = parts[0]
        if "lladdr" not in parts:
            continue
        mac_candidate = parts[parts.index("lladdr") + 1]
        if (
            not _looks_like_ip(ip_candidate)
            or not _looks_like_mac(mac_candidate)
            or not _is_unicast_mac(mac_candidate)
        ):
            continue
        hosts.append(
            HostRecord(
                address=ip_candidate,
                mac=_normalize_mac_soft(mac_candidate),
                source="ip-neigh",
                metadata={"state": parts[-1].lower()},
            )
        )
    return _deduplicate_hosts(hosts)


def read_arp_a(command_runner: Any = subprocess.run) -> list[HostRecord]:
    try:
        completed = command_runner(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise MissingDependencyError("Comando 'arp -a' não encontrado no PATH.") from exc
    if completed.returncode != 0:
        raise PassiveDiscoveryError((completed.stderr or completed.stdout or "Falha ao ler arp -a.").strip())
    hosts: list[HostRecord] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        ip_candidate, mac_candidate = parts[0], parts[1]
        if (
            not _looks_like_ip(ip_candidate)
            or not _looks_like_mac(mac_candidate)
            or not _is_unicast_mac(mac_candidate)
        ):
            continue
        hosts.append(
            HostRecord(
                address=ip_candidate,
                mac=_normalize_mac_soft(mac_candidate),
                source="arp-a",
                metadata={"type": parts[2].lower()},
            )
        )
    return _deduplicate_hosts(hosts)


def build_dns_query(name: str, qtype: int, qclass: int = 1, *, query_id: int | None = None) -> bytes:
    transaction_id = 0 if query_id is None else query_id & 0xFFFF
    header = struct.pack("!HHHHHH", transaction_id, 0, 1, 0, 0, 0)
    question = _encode_dns_name(name) + struct.pack("!HH", qtype, qclass)
    return header + question


def parse_dns_message(packet: bytes) -> dict[str, Any]:
    if len(packet) < 12:
        raise PassiveDiscoveryError("Pacote DNS/LLMNR/mDNS muito curto.")
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    questions: list[dict[str, Any]] = []
    answers: list[dict[str, Any]] = []
    for _ in range(qdcount):
        name, offset = _decode_dns_name(packet, offset)
        if offset + 4 > len(packet):
            raise PassiveDiscoveryError("Pergunta DNS truncada.")
        qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    total_rrs = ancount + nscount + arcount
    for _ in range(total_rrs):
        name, offset = _decode_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise PassiveDiscoveryError("Registro DNS truncado.")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(packet):
            raise PassiveDiscoveryError("Dados do registro DNS truncados.")
        rdata = packet[offset : offset + rdlength]
        answer = {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "data": _decode_rdata(packet, rtype, rdata, offset),
        }
        offset += rdlength
        answers.append(answer)
    return {
        "id": transaction_id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
    }


def query_mdns(timeout: float = DEFAULT_PASSIVE_TIMEOUT) -> PluginResult:
    query = build_dns_query("_services._dns-sd._udp.local", 12, query_id=0)
    responses = _udp_exchange(
        query,
        ("224.0.0.251", 5353),
        timeout,
        multicast=True,
        multicast_group="224.0.0.251",
        bind_port=5353,
    )
    hosts: list[HostRecord] = []
    findings: list[FindingRecord] = []
    for data, (source_ip, _) in responses:
        parsed = parse_dns_message(data)
        hostnames: set[str] = set()
        ports: list[PortRecord] = []
        for answer in parsed["answers"]:
            if answer["type"] in {1, 28} and answer["data"]:
                hostnames.add(_strip_local_domain(answer["name"]))
            elif answer["type"] == 33 and isinstance(answer["data"], dict):
                service_name = _service_from_dns_name(answer["name"])
                ports.append(
                    PortRecord(
                        port=int(answer["data"]["port"]),
                        protocol="tcp",
                        state="open",
                        service=service_name,
                        metadata={"target": answer["data"]["target"]},
                    )
                )
                findings.append(
                    FindingRecord(
                        host=source_ip,
                        title=f"Serviço mDNS {service_name}",
                        plugin="mdns",
                        severity="info",
                        description=f"Anúncio mDNS para {answer['name']} via {answer['data']['target']}.",
                        category="service-discovery",
                        port=int(answer["data"]["port"]),
                        protocol="tcp",
                        evidence={"record": answer},
                    )
                )
            elif answer["type"] == 12 and isinstance(answer["data"], str):
                hostnames.add(_strip_local_domain(answer["data"]))
        hosts.append(
            HostRecord(
                address=source_ip,
                hostnames=sorted(item for item in hostnames if item),
                source="mdns",
                ports=ports,
            )
        )
    return PluginResult(hosts=_deduplicate_hosts(hosts), findings=findings)


def query_ssdp(timeout: float = DEFAULT_PASSIVE_TIMEOUT) -> PluginResult:
    payload = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("utf-8")
    responses = _udp_exchange(payload, ("239.255.255.250", 1900), timeout, multicast=True)
    hosts: list[HostRecord] = []
    findings: list[FindingRecord] = []
    for data, (source_ip, _) in responses:
        text = data.decode("utf-8", errors="replace")
        headers: dict[str, str] = {}
        for line in text.splitlines()[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        service = headers.get("st") or headers.get("server") or "ssdp"
        hosts.append(HostRecord(address=source_ip, source="ssdp", metadata=headers))
        findings.append(
            FindingRecord(
                host=source_ip,
                title=f"Anúncio SSDP {service}",
                plugin="ssdp",
                severity="info",
                description=headers.get("location", "Resposta SSDP sem LOCATION."),
                category="service-discovery",
                references=[headers["location"]] if headers.get("location") else [],
                evidence=headers,
            )
        )
    return PluginResult(hosts=_deduplicate_hosts(hosts), findings=findings)


def query_llmnr(timeout: float = DEFAULT_PASSIVE_TIMEOUT, query_name: str = "wpad") -> PluginResult:
    query = build_dns_query(query_name, 1, query_id=random.randint(1, 65535))
    responses = _udp_exchange(query, ("224.0.0.252", 5355), timeout, multicast=True)
    hosts: list[HostRecord] = []
    findings: list[FindingRecord] = []
    for data, (source_ip, _) in responses:
        parsed = parse_dns_message(data)
        resolved = [answer["data"] for answer in parsed["answers"] if answer["type"] == 1 and isinstance(answer["data"], str)]
        if not resolved:
            continue
        host_ip = resolved[0]
        hosts.append(
            HostRecord(
                address=host_ip,
                hostnames=[query_name],
                source="llmnr",
                metadata={"responder": source_ip},
            )
        )
        findings.append(
            FindingRecord(
                host=host_ip,
                title=f"Resposta LLMNR para {query_name}",
                plugin="llmnr",
                severity="info",
                description=f"{source_ip} respondeu à consulta multicast LLMNR.",
                category="name-resolution",
                evidence={"query_name": query_name, "response": parsed},
            )
        )
    return PluginResult(hosts=_deduplicate_hosts(hosts), findings=findings, metadata={"query_name": query_name})


def query_nbns(timeout: float = DEFAULT_PASSIVE_TIMEOUT) -> PluginResult:
    transaction_id = random.randint(1, 65535)
    question = _encode_netbios_name("*") + struct.pack("!HH", 0x0021, 0x0001)
    packet = struct.pack("!HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0) + question
    responses = _udp_exchange(packet, ("255.255.255.255", 137), timeout, broadcast=True)
    hosts: list[HostRecord] = []
    findings: list[FindingRecord] = []
    for data, (source_ip, _) in responses:
        response = parse_nbns_node_status(data)
        hostnames = [name for name in response["names"] if name]
        hosts.append(
            HostRecord(
                address=source_ip,
                hostnames=hostnames[:3],
                mac=response.get("mac"),
                source="nbns",
                metadata={"names": hostnames},
            )
        )
        findings.append(
            FindingRecord(
                host=source_ip,
                title="Resposta NBNS node status",
                plugin="nbns",
                severity="info",
                description=", ".join(hostnames) or "Host respondeu ao NBNS sem nomes úteis.",
                category="name-resolution",
                evidence=response,
            )
        )
    return PluginResult(hosts=_deduplicate_hosts(hosts), findings=findings)


def parse_nbns_node_status(packet: bytes) -> dict[str, Any]:
    if len(packet) < 57:
        raise PassiveDiscoveryError("Resposta NBNS muito curta.")
    qdcount = struct.unpack("!H", packet[4:6])[0]
    ancount = struct.unpack("!H", packet[6:8])[0]
    if ancount < 1:
        raise PassiveDiscoveryError("Resposta NBNS sem answers.")
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_dns_name(packet, offset)
        if offset + 4 > len(packet):
            raise PassiveDiscoveryError("Pergunta NBNS truncada.")
        offset += 4
    _, offset = _decode_dns_name(packet, offset)
    if offset + 10 > len(packet):
        raise PassiveDiscoveryError("Registro NBNS truncado.")
    _, _, _, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
    offset += 10
    if offset + rdlength > len(packet) or rdlength < 1:
        raise PassiveDiscoveryError("Dados NBNS truncados.")
    rdata = packet[offset : offset + rdlength]
    name_count = rdata[0]
    names: list[str] = []
    cursor = 1
    for _ in range(name_count):
        if cursor + 18 > len(rdata):
            raise PassiveDiscoveryError("Tabela de nomes NBNS truncada.")
        raw_name = rdata[cursor : cursor + 15].decode("ascii", errors="ignore").strip()
        cursor += 18
        if raw_name and raw_name != "*":
            names.append(raw_name)
    mac = None
    if cursor + 6 <= len(rdata):
        mac = ":".join(f"{byte:02X}" for byte in rdata[cursor : cursor + 6])
    return {"names": names, "mac": mac}


def query_snmp(context: ScanContext) -> PluginResult:
    try:
        from pysnmp.hlapi import (  # type: ignore[import-untyped]
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )
    except ImportError as exc:
        raise MissingDependencyError("pysnmp não está instalado; use o extra [snmp].") from exc

    targets = list(context.options.get("snmp_targets") or [host.address for host in context.iter_hosts()])
    if not targets:
        raise PassiveDiscoveryError("Nenhum alvo SNMP informado nem descoberto por plugins anteriores.")
    communities_value = context.options.get("snmp_communities")
    if communities_value:
        communities = [str(item).strip() for item in communities_value if str(item).strip()]
    else:
        communities = [
            item.strip()
            for item in str(context.options.get("snmp_community") or "public").split(",")
            if item.strip()
        ]
    if not communities:
        raise PassiveDiscoveryError("Informe ao menos uma community SNMP.")
    timeout = float(context.options.get("snmp_timeout") or context.timeout)
    if not 0.1 <= timeout <= 120.0:
        raise PassiveDiscoveryError("Timeout SNMP deve ficar entre 0.1 e 120 segundos.")
    hosts: list[HostRecord] = []
    findings: list[FindingRecord] = []
    for target in targets:
        if context.scope:
            context.scope.assert_allowed(target, label="SNMP target")
        for community in communities:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((target, 161), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )
            error_indication, error_status, _, var_binds = next(iterator)
            if error_indication or error_status:
                continue
            values = {str(name): str(value) for name, value in var_binds}
            sys_name = values.get("SNMPv2-MIB::sysName.0") or values.get("1.3.6.1.2.1.1.5.0")
            sys_descr = values.get("SNMPv2-MIB::sysDescr.0") or values.get("1.3.6.1.2.1.1.1.0")
            hosts.append(
                HostRecord(
                    address=target,
                    hostnames=[sys_name] if sys_name else [],
                    source="snmp",
                    metadata={"sysDescr": sys_descr, "community": community},
                )
            )
            findings.append(
                FindingRecord(
                    host=target,
                    title="Resposta SNMP sysDescr",
                    plugin="snmp",
                    severity="info",
                    description=sys_descr or "SNMP respondeu sem sysDescr.",
                    category="inventory",
                    evidence={"community": community, **values},
                )
            )
            break
    return PluginResult(hosts=hosts, findings=findings, metadata={"communities": communities})


@register_plugin(
    name="proc-arp",
    description="Lê /proc/net/arp sem gerar tráfego.",
    profiles=("cache", "lan"),
    requirements=("/proc/net/arp",),
    traffic="cache-read",
    soft_fail=True,
)
def proc_arp_plugin(context: ScanContext) -> PluginResult:
    return PluginResult(hosts=read_proc_net_arp())


@register_plugin(
    name="ip-neigh",
    description="Lê o cache do comando ip neigh sem gerar tráfego.",
    profiles=("cache", "lan"),
    requirements=("ip",),
    traffic="cache-read",
    soft_fail=True,
)
def ip_neigh_plugin(context: ScanContext) -> PluginResult:
    return PluginResult(hosts=read_ip_neigh())


@register_plugin(
    name="arp-a",
    description="Lê o cache do comando arp -a sem gerar tráfego.",
    profiles=("cache", "lan"),
    requirements=("arp",),
    traffic="cache-read",
    soft_fail=True,
)
def arp_a_plugin(context: ScanContext) -> PluginResult:
    return PluginResult(hosts=read_arp_a())


@register_plugin(
    name="mdns",
    description="Envia consulta UDP multicast mDNS/Bonjour.",
    profiles=("lan",),
    traffic="udp-query",
)
def mdns_plugin(context: ScanContext) -> PluginResult:
    return query_mdns(float(context.options.get("udp_timeout") or context.timeout))


@register_plugin(
    name="ssdp",
    description="Envia consulta UDP multicast SSDP/UPnP.",
    profiles=("lan",),
    traffic="udp-query",
)
def ssdp_plugin(context: ScanContext) -> PluginResult:
    return query_ssdp(float(context.options.get("udp_timeout") or context.timeout))


@register_plugin(
    name="llmnr",
    description="Envia consulta UDP multicast LLMNR para um nome explícito.",
    profiles=("lan",),
    traffic="udp-query",
)
def llmnr_plugin(context: ScanContext) -> PluginResult:
    return query_llmnr(
        float(context.options.get("udp_timeout") or context.timeout),
        str(context.options.get("llmnr_name") or "wpad"),
    )


@register_plugin(
    name="nbns",
    description="Envia consulta UDP NBNS node status broadcast.",
    profiles=("lan",),
    traffic="udp-query",
)
def nbns_plugin(context: ScanContext) -> PluginResult:
    return query_nbns(float(context.options.get("udp_timeout") or context.timeout))


@register_plugin(
    name="snmp",
    description="Consulta SNMP sysName/sysDescr em alvos explícitos ou descobertos.",
    profiles=("lan",),
    traffic="udp-query",
    opt_in=True,
    requirements=("pysnmp",),
)
def snmp_plugin(context: ScanContext) -> PluginResult:
    return query_snmp(context)


def _udp_exchange(
    payload: bytes,
    destination: tuple[str, int],
    timeout: float,
    *,
    multicast: bool = False,
    broadcast: bool = False,
    multicast_group: str | None = None,
    bind_port: int | None = None,
) -> list[tuple[bytes, tuple[str, int]]]:
    if not 0.1 <= timeout <= 120.0:
        raise PassiveDiscoveryError("Timeout UDP deve ficar entre 0.1 e 120 segundos.")
    responses: list[tuple[bytes, tuple[str, int]]] = []
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_port is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", bind_port))
        sock.settimeout(timeout)
        if multicast:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if multicast_group:
                membership = socket.inet_aton(multicast_group) + socket.inet_aton("0.0.0.0")
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(payload, destination)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                responses.append(sock.recvfrom(65535))
            except socket.timeout:
                break
    except OSError as exc:
        raise PassiveDiscoveryError(f"Falha de socket UDP para {destination[0]}:{destination[1]}: {exc}") from exc
    finally:
        sock.close()
    return responses


def _encode_dns_name(name: str) -> bytes:
    result = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")
        result.append(len(encoded))
        result.extend(encoded)
    result.append(0)
    return bytes(result)


def _decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    return _decode_dns_name_safe(packet, offset, set())


def _decode_dns_name_safe(
    packet: bytes,
    offset: int,
    visited: set[int],
) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise PassiveDiscoveryError("Nome DNS truncado.")
        if offset in visited:
            raise PassiveDiscoveryError("Ponteiro DNS circular.")
        visited.add(offset)
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise PassiveDiscoveryError("Ponteiro DNS truncado.")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            referenced, _ = _decode_dns_name_safe(packet, pointer, visited)
            labels.append(referenced)
            offset += 2
            break
        if length & 0xC0:
            raise PassiveDiscoveryError("Tipo de rótulo DNS inválido.")
        offset += 1
        if offset + length > len(packet):
            raise PassiveDiscoveryError("Rótulo DNS truncado.")
        labels.append(packet[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(item for item in labels if item), offset


def _decode_rdata(packet: bytes, rtype: int, rdata: bytes, offset: int) -> Any:
    if rtype == 1 and len(rdata) == 4:
        return str(ipaddress.ip_address(rdata))
    if rtype == 28 and len(rdata) == 16:
        return str(ipaddress.ip_address(rdata))
    if rtype == 12:
        name, _ = _decode_dns_name(packet, offset)
        return name
    if rtype == 16:
        values: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            length = rdata[cursor]
            cursor += 1
            if cursor + length > len(rdata):
                raise PassiveDiscoveryError("Registro TXT DNS truncado.")
            values.append(rdata[cursor : cursor + length].decode("utf-8", errors="replace"))
            cursor += length
        return values
    if rtype == 33 and len(rdata) >= 7:
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = _decode_dns_name(packet, offset + 6)
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    return rdata.hex()


def _service_from_dns_name(name: str) -> str:
    labels = [label for label in name.split(".") if label.startswith("_")]
    if len(labels) >= 2:
        return f"{labels[0][1:]}/{labels[1][1:]}"
    if labels:
        return labels[0][1:]
    return name


def _strip_local_domain(value: str) -> str:
    return value.removesuffix(".local").removesuffix(".")


def _encode_netbios_name(name: str) -> bytes:
    padded = (name[:15].ljust(15) + "\x00").encode("ascii", errors="ignore")
    encoded = bytearray([32])
    for byte in padded:
        encoded.append(((byte >> 4) & 0x0F) + 0x41)
        encoded.append((byte & 0x0F) + 0x41)
    encoded.append(0)
    return bytes(encoded)


def _deduplicate_hosts(hosts: list[HostRecord]) -> list[HostRecord]:
    merged: dict[str, HostRecord] = {}
    for host in hosts:
        existing = merged.get(host.address)
        if existing is None:
            merged[host.address] = host
        else:
            existing.merge_from(host)
    return [merged[key] for key in sorted(merged)]


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _looks_like_mac(value: str) -> bool:
    compact = "".join(char for char in value if char.isalnum())
    return len(compact) == 12


def _is_unicast_mac(value: str) -> bool:
    compact = "".join(char for char in value if char.isalnum())
    if len(compact) != 12:
        return False
    first_octet = int(compact[:2], 16)
    return first_octet != 0 and not (first_octet & 1)


def _normalize_mac_soft(value: str) -> str:
    compact = "".join(char for char in value if char.isalnum()).upper()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))
