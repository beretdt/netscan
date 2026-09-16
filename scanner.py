from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
from typing import Any, Callable, Iterable, Mapping

from plugins import PluginResult, ScanContext, register_plugin
from schema import HostRecord

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 2.0
MIN_TIMEOUT = 0.2
MAX_TIMEOUT = 30.0


class ConfigurationError(ValueError):
    """Erro de configuração ou validação de entrada."""


class NetworkScanError(RuntimeError):
    """Erro operacional durante a descoberta de rede."""


ScapyRunner = Callable[[str, float], Iterable[Mapping[str, Any]]]


def get_local_ip() -> str:
    """Retorna o IP da interface usada para alcançar a rede externa."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    except OSError as exc:
        raise ConfigurationError(
            "Não foi possível detectar o IP local; informe NETMAPPER_CIDR manualmente."
        ) from exc
    finally:
        sock.close()

    try:
        address = ipaddress.ip_address(local_ip)
    except ValueError as exc:
        raise ConfigurationError(f"IP local inválido detectado: {local_ip!r}.") from exc

    if address.is_loopback:
        raise ConfigurationError(
            "A interface local resolveu para loopback; informe NETMAPPER_CIDR manualmente."
        )

    return str(address)


def detect_local_cidr(prefix: int = 24) -> str:
    """Deriva um CIDR da interface local, usando /24 por padrão."""
    if not 1 <= prefix <= 32:
        raise ConfigurationError("O prefixo da rede deve ficar entre 1 e 32.")

    return str(ipaddress.ip_network(f"{get_local_ip()}/{prefix}", strict=False))


def validate_cidr(value: Any) -> ipaddress.IPv4Network:
    if value is None:
        raise ConfigurationError("CIDR não informado.")

    raw_value = str(value).strip()
    if not raw_value:
        raise ConfigurationError("CIDR vazio.")

    try:
        network = ipaddress.ip_network(raw_value, strict=False)
    except ValueError as exc:
        raise ConfigurationError(f"CIDR inválido: {raw_value!r}.") from exc

    if network.version != 4:
        raise ConfigurationError("Apenas redes IPv4 são suportadas.")

    return network


def normalize_cidr(value: Any) -> str:
    return str(validate_cidr(value))


def validate_timeout(value: Any) -> float:
    if value is None:
        raise ConfigurationError("Timeout não informado.")

    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"Timeout inválido: {value!r}.") from exc

    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        raise ConfigurationError(
            f"Timeout deve ficar entre {MIN_TIMEOUT} e {MAX_TIMEOUT} segundos."
        )

    return timeout


def normalize_mac(value: Any) -> str:
    if value is None:
        raise NetworkScanError("Endereço MAC ausente na resposta do scanner.")

    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(compact) != 12:
        raise NetworkScanError(f"Endereço MAC inválido: {value!r}.")

    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


def discover_hosts(
    cidr: Any,
    timeout: Any = DEFAULT_TIMEOUT,
    runner: ScapyRunner | None = None,
) -> list[dict[str, str]]:
    network = validate_cidr(cidr)
    normalized_cidr = str(network)
    validated_timeout = validate_timeout(timeout)

    raw_results = (
        runner(normalized_cidr, validated_timeout)
        if runner
        else _scapy_discover(normalized_cidr, validated_timeout)
    )

    devices: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for item in raw_results:
        ip_address = _normalize_host_ip(item.get("ip"), network)
        mac_address = normalize_mac(item.get("mac"))
        key = (ip_address, mac_address)

        if key in seen:
            continue

        seen.add(key)
        devices.append({"ip": ip_address, "mac": mac_address})

    devices.sort(key=lambda device: tuple(int(part) for part in device["ip"].split(".")))
    return devices


def _normalize_host_ip(value: Any, network: ipaddress.IPv4Network) -> str:
    if value is None:
        raise NetworkScanError("Endereço IP ausente na resposta do scanner.")

    try:
        ip_address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise NetworkScanError(
            f"Endereço IP inválido retornado pelo scanner: {value!r}."
        ) from exc

    if ip_address.version != 4:
        raise NetworkScanError("A descoberta ARP suporta apenas respostas IPv4.")

    if ip_address not in network:
        raise NetworkScanError(
            f"O scanner retornou um IP fora da rede solicitada ({network}): {ip_address}."
        )

    return str(ip_address)


def _scapy_discover(cidr: str, timeout: float) -> list[dict[str, str]]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]
        from scapy.error import Scapy_Exception  # type: ignore[import-untyped]
    except ImportError as exc:
        raise NetworkScanError(
            "Scapy não está disponível. Instale as dependências em requirements.txt."
        ) from exc

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)

    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except PermissionError as exc:
        permission_hint = (
            "Execute com sudo ou conceda as capacidades de captura necessárias."
            if platform.system() != "Windows"
            else "Execute com privilégios adequados e instale o Npcap/WinPcap."
        )
        raise NetworkScanError(
            f"Permissão insuficiente para abrir raw socket. {permission_hint}"
        ) from exc
    except OSError as exc:
        raise NetworkScanError(
            "Falha ao executar a descoberta ARP. Verifique permissões e suporte a captura de pacotes."
        ) from exc
    except RuntimeError as exc:
        message = str(exc)
        lowered_message = message.lower()
        if "winpcap" in lowered_message or "npcap" in lowered_message or "layer 2" in lowered_message:
            if platform.system() != "Windows":
                raise NetworkScanError(
                    "O Scapy não conseguiu abrir a camada 2. Execute com sudo "
                    "ou conceda as capacidades de captura necessárias."
                ) from exc
            raise NetworkScanError(
                "O Scapy não encontrou o Npcap/WinPcap para usar sockets de camada 2. "
                "Instale o Npcap no Windows e marque o modo compatível com a API do WinPcap."
            ) from exc
        raise NetworkScanError(f"Falha do Scapy durante a descoberta ARP: {message}.") from exc
    except Scapy_Exception as exc:
        raise NetworkScanError(f"Falha do Scapy durante a descoberta ARP: {exc}.") from exc

    results: list[dict[str, str]] = []
    for _, response in answered:
        results.append({"ip": response.psrc, "mac": response.hwsrc})

    logger.info("Descoberta ARP concluída para %s com %s dispositivos.", cidr, len(results))
    return results


@register_plugin(
    name="arp-active",
    description="Varredura ARP ativa com Scapy no segmento local.",
    profiles=("local",),
    traffic="arp-broadcast",
    opt_in=True,
    requirements=("scapy", "Npcap/WinPcap"),
)
def arp_active_plugin(context: ScanContext) -> PluginResult:
    cidr = context.options.get("cidr") or context.target
    timeout = context.options.get("arp_timeout") or context.timeout
    hosts = [
        HostRecord(address=item["ip"], mac=item["mac"], source="arp-active")
        for item in discover_hosts(cidr, timeout=timeout)
    ]
    return PluginResult(hosts=hosts)
