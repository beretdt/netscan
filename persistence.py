from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from schema import FindingRecord, HostRecord, PortRecord, ScanResult


def default_database_path() -> Path:
    return Path(__file__).resolve().parent / "netmapper.sqlite3"


class NetMapperStore:
    def __init__(self, database_path: str | Path | None = None) -> None:
        self.database_path = Path(database_path) if database_path else default_database_path()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _ensure_schema(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    command TEXT NOT NULL,
                    plugins_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    address TEXT NOT NULL,
                    state TEXT NOT NULL,
                    hostnames_json TEXT NOT NULL,
                    mac TEXT,
                    vendor TEXT,
                    source TEXT,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    extra TEXT,
                    tls_json TEXT,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    host TEXT NOT NULL,
                    title TEXT NOT NULL,
                    plugin TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    category TEXT,
                    port INTEGER,
                    protocol TEXT,
                    references_json TEXT NOT NULL,
                    cves_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
                CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    data_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_certificates_scan_id ON certificates(scan_id);
                CREATE TABLE IF NOT EXISTS screenshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    host TEXT NOT NULL,
                    url TEXT NOT NULL,
                    path TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_screenshots_scan_id ON screenshots(scan_id);
                CREATE TABLE IF NOT EXISTS cve_feeds (
                    source TEXT PRIMARY KEY,
                    fetched_at TEXT NOT NULL,
                    checksum TEXT
                );
                CREATE TABLE IF NOT EXISTS cve_records (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    severity TEXT,
                    cvss_score REAL,
                    published_at TEXT,
                    updated_at TEXT,
                    references_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cve_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
                    part TEXT,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    version_start_including TEXT,
                    version_start_excluding TEXT,
                    version_end_including TEXT,
                    version_end_excluding TEXT,
                    criteria TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cve_match_tokens (
                    match_id INTEGER NOT NULL REFERENCES cve_matches(id) ON DELETE CASCADE,
                    token TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cve_tokens_token ON cve_match_tokens(token);
                CREATE INDEX IF NOT EXISTS idx_cve_matches_cve ON cve_matches(cve_id);
                """
            )
            connection.commit()

    def save_scan(self, scan: ScanResult) -> int:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans(scan_type, target, profile, command, plugins_json, started_at, finished_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_type,
                    scan.target,
                    scan.profile,
                    scan.command,
                    json.dumps(scan.plugins, ensure_ascii=False),
                    scan.started_at,
                    scan.finished_at,
                    json.dumps(scan.metadata, ensure_ascii=False),
                ),
            )
            scan_id = int(cursor.lastrowid)
            for host in scan.hosts:
                host_id = int(
                    connection.execute(
                        """
                        INSERT INTO hosts(scan_id, address, state, hostnames_json, mac, vendor, source, metadata_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            host.address,
                            host.state,
                            json.dumps(host.hostnames, ensure_ascii=False),
                            host.mac,
                            host.vendor,
                            host.source,
                            json.dumps(host.metadata, ensure_ascii=False),
                        ),
                    ).lastrowid
                )
                for port in host.ports:
                    connection.execute(
                        """
                        INSERT INTO ports(host_id, port, protocol, state, service, product, version, extra, tls_json, metadata_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            host_id,
                            port.port,
                            port.protocol,
                            port.state,
                            port.service,
                            port.product,
                            port.version,
                            port.extra,
                            json.dumps(port.tls, ensure_ascii=False) if port.tls is not None else None,
                            json.dumps(port.metadata, ensure_ascii=False),
                        ),
                    )
                    if port.tls is not None:
                        connection.execute(
                            """
                            INSERT INTO certificates(scan_id, host, port, protocol, data_json)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                scan_id,
                                host.address,
                                port.port,
                                port.protocol,
                                json.dumps(port.tls, ensure_ascii=False),
                            ),
                        )
            for finding in scan.findings:
                connection.execute(
                    """
                    INSERT INTO findings(scan_id, host, title, plugin, severity, description, category, port, protocol,
                                         references_json, cves_json, evidence_json, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding.host,
                        finding.title,
                        finding.plugin,
                        finding.severity,
                        finding.description,
                        finding.category,
                        finding.port,
                        finding.protocol,
                        json.dumps(finding.references, ensure_ascii=False),
                        json.dumps(finding.cves, ensure_ascii=False),
                        json.dumps(finding.evidence, ensure_ascii=False),
                        json.dumps(finding.metadata, ensure_ascii=False),
                    ),
                )
            for artifact in _screenshot_artifacts(scan.metadata):
                connection.execute(
                    """
                    INSERT INTO screenshots(scan_id, host, url, path, metadata_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        artifact.get("host") or artifact.get("url") or scan.target,
                        artifact.get("url") or "",
                        artifact.get("path") or "",
                        json.dumps(artifact, ensure_ascii=False),
                    ),
                )
            connection.commit()
            scan.scan_id = scan_id
            return scan_id

    def load_scan(self, scan_id: int) -> ScanResult:
        with closing(self._connect()) as connection:
            scan_row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if scan_row is None:
                raise KeyError(f"Scan {scan_id} não encontrado.")
            host_rows = connection.execute(
                "SELECT * FROM hosts WHERE scan_id = ? ORDER BY address", (scan_id,)
            ).fetchall()
            port_rows = connection.execute(
                """
                SELECT ports.*, hosts.address AS host_address
                FROM ports JOIN hosts ON hosts.id = ports.host_id
                WHERE hosts.scan_id = ?
                ORDER BY hosts.address, ports.port, ports.protocol
                """,
                (scan_id,),
            ).fetchall()
            finding_rows = connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY host, port, plugin, title",
                (scan_id,),
            ).fetchall()
            screenshot_rows = connection.execute(
                "SELECT * FROM screenshots WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()

        ports_by_host: dict[str, list[PortRecord]] = {}
        for row in port_rows:
            ports_by_host.setdefault(row["host_address"], []).append(
                PortRecord(
                    port=int(row["port"]),
                    protocol=row["protocol"],
                    state=row["state"],
                    service=row["service"] or "",
                    product=row["product"] or "",
                    version=row["version"] or "",
                    extra=row["extra"] or "",
                    tls=json.loads(row["tls_json"]) if row["tls_json"] else None,
                    metadata=json.loads(row["metadata_json"]),
                )
            )

        hosts = [
            HostRecord(
                address=row["address"],
                state=row["state"],
                hostnames=json.loads(row["hostnames_json"]),
                mac=row["mac"],
                vendor=row["vendor"],
                source=row["source"] or "",
                ports=ports_by_host.get(row["address"], []),
                metadata=json.loads(row["metadata_json"]),
            )
            for row in host_rows
        ]
        findings = [
            FindingRecord(
                host=row["host"],
                title=row["title"],
                plugin=row["plugin"],
                severity=row["severity"],
                description=row["description"] or "",
                category=row["category"] or "general",
                port=row["port"],
                protocol=row["protocol"],
                references=json.loads(row["references_json"]),
                cves=json.loads(row["cves_json"]),
                evidence=json.loads(row["evidence_json"]),
                metadata=json.loads(row["metadata_json"]),
            )
            for row in finding_rows
        ]
        metadata = json.loads(scan_row["metadata_json"])
        if screenshot_rows:
            metadata.setdefault(
                "screenshots",
                [json.loads(row["metadata_json"]) for row in screenshot_rows],
            )
        return ScanResult(
            scan_id=int(scan_row["id"]),
            scan_type=scan_row["scan_type"],
            target=scan_row["target"],
            profile=scan_row["profile"],
            command=scan_row["command"],
            plugins=json.loads(scan_row["plugins_json"]),
            started_at=scan_row["started_at"],
            finished_at=scan_row["finished_at"],
            hosts=hosts,
            findings=findings,
            metadata=metadata,
        )

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id, scan_type, target, profile, started_at, finished_at FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_screenshot_artifacts(
        self,
        scan_id: int,
        artifacts: list[dict[str, Any]],
    ) -> None:
        """Anexa screenshots capturados posteriormente a um scan já salvo."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT metadata_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Scan {scan_id} não encontrado.")
            metadata = json.loads(row["metadata_json"])
            saved = metadata.setdefault("screenshots", [])
            if not isinstance(saved, list):
                saved = []
                metadata["screenshots"] = saved
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    continue
                saved.append(dict(artifact))
                connection.execute(
                    """
                    INSERT INTO screenshots(scan_id, host, url, path, metadata_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        artifact.get("host") or artifact.get("url") or "",
                        artifact.get("url") or "",
                        artifact.get("path") or "",
                        json.dumps(artifact, ensure_ascii=False),
                    ),
                )
            connection.execute(
                "UPDATE scans SET metadata_json = ? WHERE id = ?",
                (json.dumps(metadata, ensure_ascii=False), scan_id),
            )
            connection.commit()

    def diff_scans(self, first_id: int, second_id: int) -> dict[str, Any]:
        first = self.load_scan(first_id)
        second = self.load_scan(second_id)
        first_hosts = {host.address: host for host in first.hosts}
        second_hosts = {host.address: host for host in second.hosts}

        def port_map(scan: ScanResult) -> dict[tuple[str, int, str], PortRecord]:
            mapped: dict[tuple[str, int, str], PortRecord] = {}
            for host in scan.hosts:
                for port in host.ports:
                    mapped[(host.address, port.port, port.protocol)] = port
            return mapped

        first_ports = port_map(first)
        second_ports = port_map(second)

        def finding_key(item: FindingRecord) -> tuple[Any, ...]:
            return (
                item.host,
                item.port,
                item.protocol,
                item.plugin,
                item.title,
                item.severity,
                tuple(sorted(item.cves)),
            )

        first_findings = {finding_key(item): item for item in first.findings}
        second_findings = {finding_key(item): item for item in second.findings}
        changed_ports: list[dict[str, Any]] = []
        for key in sorted(first_ports.keys() & second_ports.keys()):
            before = first_ports[key]
            after = second_ports[key]
            if before.to_dict() != after.to_dict():
                changed_ports.append(
                    {"host": key[0], "before": before.to_dict(), "after": after.to_dict()}
                )

        return {
            "first_scan": first.to_dict(),
            "second_scan": second.to_dict(),
            "added_hosts": [
                second_hosts[key].to_dict() for key in sorted(second_hosts.keys() - first_hosts.keys())
            ],
            "removed_hosts": [
                first_hosts[key].to_dict() for key in sorted(first_hosts.keys() - second_hosts.keys())
            ],
            "added_ports": [
                second_ports[key].to_dict() | {"host": key[0]}
                for key in sorted(second_ports.keys() - first_ports.keys())
            ],
            "removed_ports": [
                first_ports[key].to_dict() | {"host": key[0]}
                for key in sorted(first_ports.keys() - second_ports.keys())
            ],
            "changed_ports": changed_ports,
            "added_findings": [
                second_findings[key].to_dict()
                for key in sorted(second_findings.keys() - first_findings.keys())
            ],
            "removed_findings": [
                first_findings[key].to_dict()
                for key in sorted(first_findings.keys() - second_findings.keys())
            ],
        }


def _screenshot_artifacts(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    plugin_metadata = metadata.get("plugin_metadata")
    if not isinstance(plugin_metadata, dict):
        return []
    screenshot_metadata = plugin_metadata.get("screenshot")
    if not isinstance(screenshot_metadata, dict):
        return []
    artifacts = screenshot_metadata.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    return [item for item in artifacts if isinstance(item, dict)]
