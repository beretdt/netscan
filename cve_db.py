from __future__ import annotations

import gzip
import hashlib
import json
import re
import subprocess
import urllib.request
from contextlib import closing
from pathlib import Path
from shutil import which
from typing import Any, Iterable

from persistence import NetMapperStore
from plugins import (
    MissingDependencyError,
    PluginError,
    PluginResult,
    ScanContext,
    register_plugin,
)
from schema import FindingRecord


class CveDatabaseError(PluginError):
    """Falha ao atualizar ou consultar a base local de CVEs."""


class SearchsploitError(CveDatabaseError):
    """Falha ao consultar o índice local do SearchSploit."""


TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
VERSION_TOKEN_PATTERN = re.compile(r"[0-9][A-Za-z0-9._+-]*")


def update_cve_database(
    *,
    database_path: str | Path,
    feed_file: str | Path | None = None,
    feed_url: str | None = None,
) -> dict[str, Any]:
    if bool(feed_file) == bool(feed_url):
        raise CveDatabaseError("Informe exatamente uma fonte: --feed-file ou --feed-url.")
    source = str(feed_file or feed_url)
    payload = _load_feed_payload(feed_file=feed_file, feed_url=feed_url)
    store = NetMapperStore(database_path)
    vulnerabilities = _extract_vulnerabilities(payload)
    checksum = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    with closing(store._connect()) as connection:  # noqa: SLF001
        connection.execute("DELETE FROM cve_match_tokens")
        connection.execute("DELETE FROM cve_matches")
        connection.execute("DELETE FROM cve_records")
        for item in vulnerabilities:
            connection.execute(
                """
                INSERT INTO cve_records(cve_id, description, severity, cvss_score, published_at, updated_at, references_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["cve_id"],
                    item["description"],
                    item["severity"],
                    item["cvss_score"],
                    item["published_at"],
                    item["updated_at"],
                    json.dumps(item["references"], ensure_ascii=False),
                ),
            )
            for match in item["matches"]:
                cursor = connection.execute(
                    """
                    INSERT INTO cve_matches(cve_id, part, vendor, product, version,
                                            version_start_including, version_start_excluding,
                                            version_end_including, version_end_excluding, criteria)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["cve_id"],
                        match.get("part"),
                        match.get("vendor"),
                        match.get("product"),
                        match.get("version"),
                        match.get("version_start_including"),
                        match.get("version_start_excluding"),
                        match.get("version_end_including"),
                        match.get("version_end_excluding"),
                        match["criteria"],
                    ),
                )
                match_id = int(cursor.lastrowid)
                for token in sorted(_name_tokens(match.get("vendor", ""), match.get("product", ""))):
                    connection.execute(
                        "INSERT INTO cve_match_tokens(match_id, token) VALUES (?, ?)",
                        (match_id, token),
                    )
        connection.execute(
            "REPLACE INTO cve_feeds(source, fetched_at, checksum) VALUES (?, datetime('now'), ?)",
            (source, checksum),
        )
        connection.commit()
    return {"source": source, "cves": len(vulnerabilities), "checksum": checksum}



def lookup_local_cves(
    *,
    database_path: str | Path,
    product: str,
    version: str,
    vendor: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise CveDatabaseError("O limite de CVEs deve ficar entre 1 e 1000.")
    tokens = sorted(_name_tokens(vendor or "", product))
    if not tokens:
        return []
    placeholders = ",".join("?" for _ in tokens)
    min_hits = 1 if len(tokens) == 1 else min(2, len(tokens))
    store = NetMapperStore(database_path)
    with closing(store._connect()) as connection:  # noqa: SLF001
        rows = connection.execute(
            f"""
            SELECT cm.*, cr.description, cr.severity, cr.cvss_score, cr.references_json,
                   COUNT(DISTINCT cmt.token) AS token_hits
            FROM cve_matches cm
            JOIN cve_match_tokens cmt ON cmt.match_id = cm.id
            JOIN cve_records cr ON cr.cve_id = cm.cve_id
            WHERE cmt.token IN ({placeholders})
            GROUP BY cm.id
            HAVING token_hits >= ?
            ORDER BY token_hits DESC, COALESCE(cr.cvss_score, 0) DESC, cm.cve_id
            LIMIT ?
            """,
            [*tokens, min_hits, limit * 20],
        ).fetchall()
    matches: list[dict[str, Any]] = []
    for row in rows:
        if not _version_matches(version, row):
            continue
        matches.append(
            {
                "cve_id": row["cve_id"],
                "vendor": row["vendor"],
                "product": row["product"],
                "criteria": row["criteria"],
                "description": row["description"],
                "severity": row["severity"] or "UNKNOWN",
                "cvss_score": row["cvss_score"],
                "references": json.loads(row["references_json"]),
                "token_hits": row["token_hits"],
            }
        )
        if len(matches) >= limit:
            break
    return matches


@register_plugin(
    name="cve-local",
    description="Correlaciona banners product/version com base SQLite local de CVEs.",
    profiles=("enrich", "web", "audit"),
    depends_on=("nmap-service",),
    traffic="offline-db",
    opt_in=True,
)
def cve_local_plugin(context: ScanContext) -> PluginResult:
    database_path = context.database_path
    findings: list[FindingRecord] = []
    matched = 0
    cve_limit = int(context.options.get("cve_limit") or 10)
    if not 1 <= cve_limit <= 1000:
        raise CveDatabaseError("O limite de CVEs deve ficar entre 1 e 1000.")
    searchsploit_enabled = bool(context.options.get("searchsploit"))
    searchsploit_binary = str(context.options.get("searchsploit_binary") or "searchsploit")
    if searchsploit_enabled and which(searchsploit_binary) is None:
        raise MissingDependencyError(
            f"Binário '{searchsploit_binary}' ausente no PATH; desative --searchsploit "
            "ou instale o SearchSploit."
        )
    for host in context.iter_hosts():
        for port in host.ports:
            if port.state != "open" or not port.product or not port.version:
                continue
            rows = lookup_local_cves(
                database_path=database_path,
                product=port.product,
                version=port.version,
                vendor=host.vendor,
                limit=cve_limit,
            )
            for row in rows:
                matched += 1
                evidence = {
                    "product": port.product,
                    "version": port.version,
                    "criteria": row["criteria"],
                }
                references = list(row["references"])
                if searchsploit_enabled:
                    exploits = searchsploit_lookup(
                        row["cve_id"],
                        binary=searchsploit_binary,
                    )
                    evidence["searchsploit"] = exploits
                    references.extend(
                        str(item["URL"])
                        for item in exploits
                        if item.get("URL")
                    )
                findings.append(
                    FindingRecord(
                        host=host.address,
                        title=f"Correlação local {row['cve_id']}",
                        plugin="cve-local",
                        severity=str(row["severity"]).lower(),
                        description=row["description"],
                        category="vulnerability",
                        port=port.port,
                        protocol=port.protocol,
                        cves=[row["cve_id"]],
                        references=_deduplicate_strings(references),
                        evidence=evidence,
                    )
                )
    if matched == 0:
        with closing(NetMapperStore(database_path)._connect()) as connection:  # noqa: SLF001
            has_feed = connection.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0]
        if not has_feed:
            raise CveDatabaseError(
                "Base CVE local vazia; execute 'netscan cve update --feed-file ...' ou '--feed-url ...'."
            )
    return PluginResult(findings=findings, metadata={"matched": matched})


def searchsploit_lookup(
    cve_id: str,
    *,
    binary: str = "searchsploit",
    timeout: float = 30.0,
    runner: Any = subprocess.run,
) -> list[dict[str, Any]]:
    """Consulta resultados locais do SearchSploit sem fazer requisições de rede."""
    executable = which(binary)
    if executable is None:
        raise MissingDependencyError(
            f"Binário '{binary}' ausente no PATH; instale o SearchSploit para consultar PoCs."
        )
    try:
        completed = runner(
            [executable, "--json", cve_id],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SearchsploitError(f"SearchSploit excedeu o timeout para {cve_id}.") from exc
    except OSError as exc:
        raise SearchsploitError(f"Não foi possível iniciar o SearchSploit: {exc}.") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "erro desconhecido").strip()
        raise SearchsploitError(f"SearchSploit falhou para {cve_id}: {detail[:400]}")
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SearchsploitError(f"SearchSploit retornou JSON inválido para {cve_id}.") from exc
    results = payload.get("RESULTS_EXPLOIT") or payload.get("results") or []
    if not isinstance(results, list):
        raise SearchsploitError("Formato JSON do SearchSploit não contém uma lista de resultados.")
    return [item for item in results if isinstance(item, dict)]


def _deduplicate_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _load_feed_payload(*, feed_file: str | Path | None, feed_url: str | None) -> dict[str, Any]:
    try:
        if feed_file:
            path = Path(feed_file)
            raw = path.read_bytes()
        else:
            request = urllib.request.Request(
                str(feed_url),
                headers={"User-Agent": "NetMapper/0.2 CVE feed updater"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
    except OSError as exc:
        raise CveDatabaseError(f"Não foi possível ler o feed CVE: {exc}.") from exc
    if str(feed_file or feed_url).endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise CveDatabaseError(f"Feed gzip inválido: {exc}.") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CveDatabaseError(f"Feed CVE inválido: {exc}") from exc



def _extract_vulnerabilities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = payload.get("vulnerabilities") or payload.get("CVE_Items") or []
    vulnerabilities: list[dict[str, Any]] = []
    for item in items:
        cve_wrapper = item.get("cve") if isinstance(item, dict) else None
        cve = cve_wrapper or item
        cve_id = (
            cve.get("id")
            or cve.get("CVE_data_meta", {}).get("ID")
            or item.get("id")
        )
        if not cve_id:
            continue
        description = _pick_description(cve)
        severity, score = _pick_metric(cve, item)
        references = _pick_references(cve)
        matches = [match for match in _iter_cpe_matches(item, cve) if match.get("criteria")]
        vulnerabilities.append(
            {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": score,
                "published_at": cve.get("published") or item.get("publishedDate"),
                "updated_at": cve.get("lastModified") or item.get("lastModifiedDate"),
                "references": references,
                "matches": matches,
            }
        )
    return vulnerabilities



def _pick_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions")
    if not descriptions:
        descriptions = cve.get("description", {}).get("description_data") or []
    if isinstance(descriptions, dict):
        descriptions = descriptions.get("description_data") or []
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    for item in descriptions:
        if item.get("value"):
            return item["value"]
    return "Sem descrição no feed."



def _pick_metric(cve: dict[str, Any], item: dict[str, Any] | None = None) -> tuple[str, float | None]:
    fallback = item or {}
    metrics = cve.get("metrics") or fallback.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            first = entries[0]
            severity = first.get("cvssData", {}).get("baseSeverity") or first.get("baseSeverity") or "UNKNOWN"
            score = first.get("cvssData", {}).get("baseScore") or first.get("baseScore")
            return str(severity), float(score) if score is not None else None
    impact = cve.get("impact") or fallback.get("impact") or {}
    if impact.get("baseMetricV3"):
        data = impact["baseMetricV3"].get("cvssV3", {})
        score = data.get("baseScore")
        return str(data.get("baseSeverity") or "UNKNOWN"), float(score) if score is not None else None
    if impact.get("baseMetricV2"):
        data = impact["baseMetricV2"].get("cvssV2", {})
        score = data.get("baseScore")
        return str(data.get("severity") or "UNKNOWN"), float(score) if score is not None else None
    return "UNKNOWN", None



def _pick_references(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references") or []
    if isinstance(references, dict):
        references = references.get("reference_data") or []
    urls: list[str] = []
    for item in references:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if url:
            urls.append(url)
    return urls[:10]



def _iter_cpe_matches(item: dict[str, Any], cve: dict[str, Any]) -> Iterable[dict[str, Any]]:
    configurations = item.get("configurations") or cve.get("configurations") or []
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes") or []
    else:
        nodes = configurations
    yield from _walk_configuration_nodes(nodes)



def _walk_configuration_nodes(nodes: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for node in nodes:
        if isinstance(node, dict):
            nested_nodes = node.get("nodes")
            if nested_nodes:
                yield from _walk_configuration_nodes(nested_nodes)
            for match in node.get("cpeMatch") or node.get("cpe_match") or []:
                if match.get("vulnerable", True):
                    parsed = _parse_cpe_match(match)
                    if parsed:
                        yield parsed
            for child in node.get("children") or []:
                yield from _walk_configuration_nodes([child])



def _parse_cpe_match(match: dict[str, Any]) -> dict[str, Any] | None:
    criteria = match.get("criteria") or match.get("cpe23Uri")
    if not criteria:
        return None
    parts = criteria.split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        part = parts[2]
    elif criteria.startswith("cpe:/"):
        legacy_parts = criteria[5:].split(":")
        if len(legacy_parts) < 3:
            return None
        part, vendor, product = legacy_parts[:3]
        version = legacy_parts[3] if len(legacy_parts) > 3 else "*"
    else:
        return None
    return {
        "criteria": criteria,
        "part": _unescape_cpe_value(part),
        "vendor": _unescape_cpe_value(vendor).replace("_", " "),
        "product": _unescape_cpe_value(product).replace("_", " "),
        "version": _unescape_cpe_value(version),
        "version_start_including": match.get("versionStartIncluding"),
        "version_start_excluding": match.get("versionStartExcluding"),
        "version_end_including": match.get("versionEndIncluding"),
        "version_end_excluding": match.get("versionEndExcluding"),
    }


def _unescape_cpe_value(value: str) -> str:
    return value.replace(r"\:", ":").replace(r"\_", "_").replace(r"\-", "-")



def _name_tokens(*values: str) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        normalized = str(value or "").lower().replace("_", " ").replace("-", " ")
        for token in TOKEN_PATTERN.findall(normalized):
            if len(token) > 1:
                tokens.add(token)
    return tokens



def _version_matches(banner_version: str, row: Any) -> bool:
    candidates = _version_candidates(banner_version)
    if not candidates:
        return False
    for candidate in candidates:
        if _single_version_matches(candidate, row):
            return True
    return False



def _version_candidates(version: str) -> list[str]:
    normalized = version.strip().lower()
    candidates: list[str] = []
    if normalized:
        candidates.append(normalized)
    match = VERSION_TOKEN_PATTERN.search(normalized)
    if match and match.group(0) not in candidates:
        candidates.append(match.group(0))
    return candidates



def _single_version_matches(candidate: str, row: Any) -> bool:
    exact_version = row["version"]
    if exact_version and exact_version not in {"*", "-"}:
        if _compare_versions(candidate, exact_version) != 0:
            return False
    if row["version_start_including"] and _compare_versions(candidate, row["version_start_including"]) < 0:
        return False
    if row["version_start_excluding"] and _compare_versions(candidate, row["version_start_excluding"]) <= 0:
        return False
    if row["version_end_including"] and _compare_versions(candidate, row["version_end_including"]) > 0:
        return False
    if row["version_end_excluding"] and _compare_versions(candidate, row["version_end_excluding"]) >= 0:
        return False
    return True



def _compare_versions(left: str, right: str) -> int:
    left_parts = _split_version(left)
    right_parts = _split_version(right)
    for index in range(max(len(left_parts), len(right_parts))):
        left_part = left_parts[index] if index < len(left_parts) else 0
        right_part = right_parts[index] if index < len(right_parts) else 0
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        return -1 if str(left_part) < str(right_part) else 1
    return 0



def _split_version(value: str) -> list[int | str]:
    parts: list[int | str] = []
    for token in re.findall(r"\d+|[a-z]+", value.lower()):
        if token.isdigit():
            parts.append(int(token))
        else:
            parts.append(token)
    return parts or [value.lower()]
