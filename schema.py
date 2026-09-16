from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


JsonDict = dict[str, Any]


@dataclass
class PortRecord:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    tls: JsonDict | None = None
    metadata: JsonDict = field(default_factory=dict)

    def key(self) -> tuple[int, str]:
        return self.port, self.protocol

    def merge_from(self, other: "PortRecord") -> None:
        for field_name in ("state", "service", "product", "version", "extra"):
            current = getattr(self, field_name)
            incoming = getattr(other, field_name)
            if (current in (None, "") or current == "unknown") and incoming not in (None, ""):
                setattr(self, field_name, incoming)
        if self.tls is None and other.tls is not None:
            self.tls = dict(other.tls)
        self.metadata = {**self.metadata, **other.metadata}

    def to_dict(self) -> JsonDict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra": self.extra,
            "tls": self.tls,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PortRecord":
        return cls(
            port=int(data.get("port", 0)),
            protocol=str(data.get("protocol", "tcp")),
            state=str(data.get("state", "open")),
            service=str(data.get("service", "")),
            product=str(data.get("product", "")),
            version=str(data.get("version", "")),
            extra=str(data.get("extra", "")),
            tls=dict(data["tls"]) if data.get("tls") else None,
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class HostRecord:
    address: str
    state: str = "up"
    hostnames: list[str] = field(default_factory=list)
    mac: str | None = None
    vendor: str | None = None
    source: str = ""
    ports: list[PortRecord] = field(default_factory=list)
    metadata: JsonDict = field(default_factory=dict)

    def merge_from(self, other: "HostRecord") -> None:
        if (self.state in ("", "unknown") or not self.state) and other.state:
            self.state = other.state
        if not self.mac and other.mac:
            self.mac = other.mac
        if not self.vendor and other.vendor:
            self.vendor = other.vendor
        if not self.source and other.source:
            self.source = other.source
        for hostname in other.hostnames:
            if hostname and hostname not in self.hostnames:
                self.hostnames.append(hostname)
        port_index = {port.key(): port for port in self.ports}
        for other_port in other.ports:
            key = other_port.key()
            if key in port_index:
                port_index[key].merge_from(other_port)
            else:
                self.ports.append(other_port)
        self.ports.sort(key=lambda item: item.key())
        self.metadata = {**self.metadata, **other.metadata}

    def to_dict(self) -> JsonDict:
        return {
            "address": self.address,
            "state": self.state,
            "hostnames": list(self.hostnames),
            "mac": self.mac,
            "vendor": self.vendor,
            "source": self.source,
            "ports": [port.to_dict() for port in self.ports],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> "HostRecord":
        return cls(
            address=str(data.get("address") or data.get("ip") or ""),
            state=str(data.get("state", "up")),
            hostnames=[str(item) for item in data.get("hostnames") or []],
            mac=data.get("mac"),
            vendor=data.get("vendor"),
            source=str(data.get("source", "")),
            ports=[PortRecord.from_dict(item) for item in data.get("ports") or []],
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class FindingRecord:
    host: str
    title: str
    plugin: str
    severity: str = "info"
    description: str = ""
    category: str = "general"
    port: int | None = None
    protocol: str | None = None
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    evidence: JsonDict = field(default_factory=dict)
    metadata: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return {
            "host": self.host,
            "title": self.title,
            "plugin": self.plugin,
            "severity": self.severity,
            "description": self.description,
            "category": self.category,
            "port": self.port,
            "protocol": self.protocol,
            "references": list(self.references),
            "cves": list(self.cves),
            "evidence": dict(self.evidence),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> "FindingRecord":
        return cls(
            host=str(data.get("host", "")),
            title=str(data.get("title", "")),
            plugin=str(data.get("plugin", "")),
            severity=str(data.get("severity", "info")),
            description=str(data.get("description", "")),
            category=str(data.get("category", "general")),
            port=data.get("port"),
            protocol=data.get("protocol"),
            references=[str(item) for item in data.get("references") or []],
            cves=[str(item) for item in data.get("cves") or []],
            evidence=dict(data.get("evidence") or {}),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class ScanResult:
    scan_type: str
    target: str
    profile: str
    command: str
    plugins: list[str]
    started_at: str = field(default_factory=lambda: utcnow())
    finished_at: str | None = None
    hosts: list[HostRecord] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    metadata: JsonDict = field(default_factory=dict)
    scan_id: int | None = None

    def add_host(self, host: HostRecord) -> None:
        existing = next((item for item in self.hosts if item.address == host.address), None)
        if existing is None:
            self.hosts.append(host)
            self.hosts.sort(key=lambda item: item.address)
            return
        existing.merge_from(host)

    def add_finding(self, finding: FindingRecord) -> None:
        self.findings.append(finding)

    def finish(self) -> None:
        self.finished_at = utcnow()

    def to_dict(self) -> JsonDict:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "profile": self.profile,
            "command": self.command,
            "plugins": list(self.plugins),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "hosts": [host.to_dict() for host in self.hosts],
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> "ScanResult":
        return cls(
            scan_id=data.get("scan_id"),
            scan_type=str(data.get("scan_type", "unknown")),
            target=str(data.get("target", "")),
            profile=str(data.get("profile", "")),
            command=str(data.get("command", "")),
            plugins=[str(item) for item in data.get("plugins") or []],
            started_at=str(data.get("started_at") or utcnow()),
            finished_at=data.get("finished_at"),
            hosts=[HostRecord.from_dict(item) for item in data.get("hosts") or []],
            findings=[FindingRecord.from_dict(item) for item in data.get("findings") or []],
            metadata=dict(data.get("metadata") or {}),
        )


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
