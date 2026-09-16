from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from cve_db import CveDatabaseError, lookup_local_cves, update_cve_database
from credentials import load_credentials_file
from external import (
    DEFAULT_EXTERNAL_TIMEOUT,
    DEFAULT_TOP_PORTS,
    NmapError,
    nmap_hosts_to_records,
    run_nmap,
)
from nuclei import NucleiError
from passive import DEFAULT_PASSIVE_TIMEOUT
from persistence import NetMapperStore, default_database_path
from plugins import (
    MissingDependencyError,
    PluginError,
    ScanContext,
    expand_plugin_names,
    list_plugins,
    run_plugins,
)
from reporting import render_scan_report
from scanner import ConfigurationError, DEFAULT_TIMEOUT, NetworkScanError, discover_hosts
from screenshots import ScreenshotError, capture_screenshots
from scope import load_scope_file
from subdomains import SubfinderError, enumerate_subdomains
from tlsinfo import DEFAULT_TLS_TIMEOUT, TLSInspectionError, inspect_tls_certificate
from vendor import VendorLookupService
from vuln import DEFAULT_VULN_TIMEOUT, run_vulnerability_scan


SCAN_PROFILES = ("basic", "enrich", "web", "audit")
PASSIVE_PROFILES = ("cache", "lan")
SUBCOMMANDS = {"scan", "passive", "cve", "diff", "report", "tls", "screenshot", "subdomains", "plugins"}


class CliError(RuntimeError):
    """Erro de uso da CLI."""



def build_root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Netscan",
        description="NetMapper/Netscan: ARP local legado, scan externo, descoberta passiva, CVE offline e persistência SQLite.",
        epilog=(
            "Compatibilidade legada preservada: Netscan 192.168.1.0/24, Netscan -ext IP, "
            "Netscan -ext -vuln IP. Use 'Netscan scan --help' para o fluxo novo."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan externo com plugins/persistência.")
    scan_parser.add_argument("target", help="IP externo autorizado.")
    scan_parser.add_argument("--profile", choices=SCAN_PROFILES, default="basic")
    scan_parser.add_argument("--plugin", action="append", default=[], help="Plugin extra, repetível.")
    scan_parser.add_argument("--ports", help="Portas do Nmap, ex.: 22,80,443.")
    scan_parser.add_argument("--top-ports", type=int, default=DEFAULT_TOP_PORTS)
    scan_parser.add_argument("--timeout", type=float, default=DEFAULT_EXTERNAL_TIMEOUT)
    scan_parser.add_argument("-O", "--os-detect", action="store_true")
    scan_parser.add_argument("--tls", action="store_true", help="Inclui o plugin TLS.")
    scan_parser.add_argument("--tls-timeout", type=float, default=DEFAULT_TLS_TIMEOUT)
    scan_parser.add_argument("--tls-insecure", action="store_true")
    scan_parser.add_argument("--cve-local", action="store_true", help="Correla CVEs a partir do banco local.")
    scan_parser.add_argument("--cve-limit", type=int, default=10)
    scan_parser.add_argument(
        "--searchsploit",
        action="store_true",
        help="Consulta PoCs locais do SearchSploit para CVEs correlacionadas.",
    )
    scan_parser.add_argument("--searchsploit-binary", default="searchsploit")
    scan_parser.add_argument("--nuclei", action="store_true")
    scan_parser.add_argument("--nuclei-timeout", type=float, default=120.0)
    scan_parser.add_argument("--nuclei-rate-limit", type=int, default=25)
    scan_parser.add_argument("--nuclei-templates")
    scan_parser.add_argument("--default-creds", action="store_true")
    scan_parser.add_argument("--creds-file", help="JSON com pequena lista de credenciais.")
    scan_parser.add_argument("--default-creds-max-attempts", type=int, default=5)
    scan_parser.add_argument("--default-creds-timeout", type=float, default=3.0)
    scan_parser.add_argument("--default-creds-rate-limit", type=float, default=0.25)
    scan_parser.add_argument("--default-creds-insecure", action="store_true")
    scan_parser.add_argument("--screenshot", action="store_true")
    scan_parser.add_argument("--screenshot-output-dir")
    scan_parser.add_argument("--screenshot-timeout-ms", type=int, default=7000)
    scan_parser.add_argument("--screenshot-insecure", action="store_true")
    scan_parser.add_argument("--nmap-vuln", action="store_true", help="Executa scripts NSE vuln via plugin.")
    scan_parser.add_argument("--vuln-timeout", type=float, default=DEFAULT_VULN_TIMEOUT)
    scan_parser.add_argument("--script-timeout", type=float, default=120.0)
    scan_parser.add_argument("--database", default=str(default_database_path()))
    scan_parser.add_argument("--scope-file")
    scan_parser.add_argument("--json", action="store_true", dest="as_json")
    scan_parser.add_argument("--save", action=argparse.BooleanOptionalAction, default=True)

    passive_parser = subparsers.add_parser("passive", help="Descoberta passiva/cache e sondas UDP locais opt-in.")
    passive_parser.add_argument("targets", nargs="*", help="Alvos SNMP opcionais.")
    passive_parser.add_argument("--profile", choices=PASSIVE_PROFILES, default="cache")
    passive_parser.add_argument("--plugin", action="append", default=[], help="Plugin extra, repetível.")
    passive_parser.add_argument("--timeout", type=float, default=DEFAULT_PASSIVE_TIMEOUT)
    passive_parser.add_argument("--llmnr-name", default="wpad")
    passive_parser.add_argument("--snmp-community", default="public")
    passive_parser.add_argument("--database", default=str(default_database_path()))
    passive_parser.add_argument("--scope-file")
    passive_parser.add_argument("--json", action="store_true", dest="as_json")
    passive_parser.add_argument("--save", action=argparse.BooleanOptionalAction, default=True)

    cve_parser = subparsers.add_parser("cve", help="Atualiza ou consulta a base CVE local.")
    cve_sub = cve_parser.add_subparsers(dest="cve_command", required=True)
    cve_update = cve_sub.add_parser("update", help="Importa feed NVD/CVE explicitamente para SQLite local.")
    cve_update.add_argument("--feed-file")
    cve_update.add_argument("--feed-url")
    cve_update.add_argument("--database", default=str(default_database_path()))
    cve_update.add_argument("--json", action="store_true", dest="as_json")
    cve_lookup = cve_sub.add_parser("lookup", help="Consulta local por product/version sem rede.")
    cve_lookup.add_argument("product")
    cve_lookup.add_argument("version")
    cve_lookup.add_argument("--vendor")
    cve_lookup.add_argument("--database", default=str(default_database_path()))
    cve_lookup.add_argument("--json", action="store_true", dest="as_json")

    diff_parser = subparsers.add_parser("diff", help="Compara dois scans persistidos.")
    diff_parser.add_argument("first_scan", type=int)
    diff_parser.add_argument("second_scan", type=int)
    diff_parser.add_argument("--database", default=str(default_database_path()))
    diff_parser.add_argument("--json", action="store_true", dest="as_json")

    report_parser = subparsers.add_parser("report", help="Gera relatório JSON/Markdown/HTML de um scan salvo.")
    report_parser.add_argument("scan_id", type=int)
    report_parser.add_argument("--format", choices=("json", "md", "html"), default="json")
    report_parser.add_argument("--output")
    report_parser.add_argument("--database", default=str(default_database_path()))

    tls_parser = subparsers.add_parser("tls", help="Inspeciona certificado TLS de uma porta específica.")
    tls_parser.add_argument("target")
    tls_parser.add_argument("--port", type=int, required=True)
    tls_parser.add_argument("--timeout", type=float, default=DEFAULT_TLS_TIMEOUT)
    tls_parser.add_argument("--insecure", action="store_true")
    tls_parser.add_argument("--scope-file")
    tls_parser.add_argument("--json", action="store_true", dest="as_json")

    screenshot_parser = subparsers.add_parser("screenshot", help="Captura screenshots apenas de portas HTTP/HTTPS descobertas.")
    screenshot_parser.add_argument("target")
    screenshot_parser.add_argument("--scan-id", type=int, help="Usa portas HTTP/HTTPS de um scan salvo.")
    screenshot_parser.add_argument("--ports", help="Opcional: restringe a descoberta inicial do Nmap antes do screenshot.")
    screenshot_parser.add_argument("--top-ports", type=int, default=DEFAULT_TOP_PORTS)
    screenshot_parser.add_argument("--timeout", type=float, default=DEFAULT_EXTERNAL_TIMEOUT)
    screenshot_parser.add_argument("--output-dir", default=str(Path.cwd() / "screenshots"))
    screenshot_parser.add_argument("--timeout-ms", type=int, default=7000)
    screenshot_parser.add_argument("--insecure", action="store_true")
    screenshot_parser.add_argument("--database", default=str(default_database_path()))
    screenshot_parser.add_argument("--scope-file")
    screenshot_parser.add_argument("--json", action="store_true", dest="as_json")

    subdomains_parser = subparsers.add_parser("subdomains", help="Enumera subdomínios com subfinder opt-in.")
    subdomains_parser.add_argument("domain")
    subdomains_parser.add_argument("--timeout", type=float, default=60.0)
    subdomains_parser.add_argument("--scope-file")
    subdomains_parser.add_argument("--json", action="store_true", dest="as_json")

    subparsers.add_parser("plugins", help="Lista plugins, perfis e tipos de tráfego.")
    return parser



def build_legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Netscan",
        description="Modo legado: ARP local ou Nmap externo.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="IP único ou rede IPv4 em CIDR, por exemplo 192.168.15.1 ou 192.168.15.0/24",
    )
    parser.add_argument(
        "-Ext",
        "-ext",
        "--ext",
        dest="external_target",
        metavar="IP",
        help="Executa um scan TCP externo com Nmap no IP informado.",
    )
    parser.add_argument(
        "-vuln",
        "--vuln",
        dest="vulnerability",
        action="store_true",
        help="Com -ext: executa os scripts NSE da categoria vuln.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=(
            f"Timeout em segundos (local: {DEFAULT_TIMEOUT}; externo: "
            f"{DEFAULT_EXTERNAL_TIMEOUT:g})."
        ),
    )
    parser.add_argument("-p", "--ports", help="Portas do scan externo, por exemplo 22,80,443 ou 1-1024.")
    parser.add_argument(
        "--top-ports",
        type=int,
        default=DEFAULT_TOP_PORTS,
        help=f"Quantidade de portas mais comuns no scan externo (padrão: {DEFAULT_TOP_PORTS}).",
    )
    parser.add_argument("-O", "--os-detect", action="store_true", help="Solicita detecção de sistema operacional ao Nmap.")
    parser.add_argument("--scope-file", help="Arquivo de escopo para proteger o alvo externo.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Exibe os resultados em JSON.")
    return parser



def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    if not raw_argv or raw_argv[0] in {"-h", "--help"}:
        build_root_parser().parse_args(raw_argv)
        return 0
    if raw_argv[0] in SUBCOMMANDS:
        return _run_modern(raw_argv)
    return _run_legacy(raw_argv)



def _run_modern(argv: list[str]) -> int:
    args = build_root_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _handle_scan(args)
        if args.command == "passive":
            return _handle_passive(args)
        if args.command == "cve":
            return _handle_cve(args)
        if args.command == "diff":
            return _handle_diff(args)
        if args.command == "report":
            return _handle_report(args)
        if args.command == "tls":
            return _handle_tls(args)
        if args.command == "screenshot":
            return _handle_screenshot(args)
        if args.command == "subdomains":
            return _handle_subdomains(args)
        if args.command == "plugins":
            return _handle_plugins(args)
        raise CliError("Subcomando não implementado.")
    except (
        CliError,
        PluginError,
        NmapError,
        CveDatabaseError,
        TLSInspectionError,
        ScreenshotError,
        SubfinderError,
        NucleiError,
        OSError,
    ) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2



def _handle_scan(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope_file)
    if scope:
        scope.assert_allowed(args.target, label="scan")
    plugin_names = _collect_scan_plugins(args)
    options = {
        "ports": args.ports,
        "top_ports": args.top_ports,
        "external_timeout": args.timeout,
        "os_detect": args.os_detect,
        "tls_timeout": args.tls_timeout,
        "tls_insecure": args.tls_insecure,
        "cve_limit": args.cve_limit,
        "searchsploit": args.searchsploit,
        "searchsploit_binary": args.searchsploit_binary,
        "nuclei_timeout": args.nuclei_timeout,
        "nuclei_rate_limit": args.nuclei_rate_limit,
        "nuclei_templates": args.nuclei_templates,
        "default_creds_timeout": args.default_creds_timeout,
        "default_creds_rate_limit": args.default_creds_rate_limit,
        "default_creds_insecure": args.default_creds_insecure,
        "default_credentials": load_credentials_file(args.creds_file) if args.default_creds else None,
        "default_creds_max_attempts": args.default_creds_max_attempts,
        "screenshot_output_dir": args.screenshot_output_dir,
        "screenshot_timeout_ms": args.screenshot_timeout_ms,
        "screenshot_insecure": args.screenshot_insecure,
        "vuln_timeout": args.vuln_timeout,
        "script_timeout": args.script_timeout,
    }
    context = ScanContext(
        scan_type="active-scan",
        target=args.target,
        profile=args.profile,
        command="Netscan " + " ".join(sys.argv[1:]),
        timeout=args.timeout,
        database_path=Path(args.database),
        options=options,
        scope=scope,
    )
    result = run_plugins(context, plugin_names)
    scan_id = _save_scan_if_requested(result, args.database, args.save)
    payload = result.to_dict()
    if scan_id:
        payload["scan_id"] = scan_id
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_scan_result(result, scan_id=scan_id)
        _print_plugin_errors(result)
    return 0



def _handle_passive(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope_file)
    for target in args.targets:
        if scope:
            scope.assert_allowed(target, label="SNMP target")
    context = ScanContext(
        scan_type="passive-discovery",
        target=",".join(args.targets) or "local",
        profile=args.profile,
        command="Netscan " + " ".join(sys.argv[1:]),
        timeout=args.timeout,
        database_path=Path(args.database),
        options={
            "udp_timeout": args.timeout,
            "llmnr_name": args.llmnr_name,
            "snmp_targets": list(args.targets),
            "snmp_community": args.snmp_community,
        },
        scope=scope,
    )
    result = run_plugins(context, expand_plugin_names(args.profile, args.plugin))
    scan_id = _save_scan_if_requested(result, args.database, args.save)
    payload = result.to_dict()
    if scan_id:
        payload["scan_id"] = scan_id
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_scan_result(result, scan_id=scan_id)
        _print_plugin_errors(result)
    return 0



def _handle_cve(args: argparse.Namespace) -> int:
    if args.cve_command == "update":
        result = update_cve_database(database_path=args.database, feed_file=args.feed_file, feed_url=args.feed_url)
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"Base CVE atualizada: {result['cves']} CVEs importados de {result['source']}.")
        return 0
    rows = lookup_local_cves(
        database_path=args.database,
        product=args.product,
        version=args.version,
        vendor=args.vendor,
    )
    if args.as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        if not rows:
            print("Nenhuma correlação local encontrada.")
        for row in rows:
            print(f"{row['cve_id']} [{row['severity']}] {row['description']}")
    return 0



def _handle_diff(args: argparse.Namespace) -> int:
    diff = NetMapperStore(args.database).diff_scans(args.first_scan, args.second_scan)
    if args.as_json:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
    else:
        print(f"Hosts adicionados: {len(diff['added_hosts'])}")
        print(f"Hosts removidos: {len(diff['removed_hosts'])}")
        print(f"Portas adicionadas: {len(diff['added_ports'])}")
        print(f"Portas removidas: {len(diff['removed_ports'])}")
        print(f"Portas alteradas: {len(diff['changed_ports'])}")
        print(f"Findings adicionados: {len(diff['added_findings'])}")
        print(f"Findings removidos: {len(diff['removed_findings'])}")
    return 0



def _handle_report(args: argparse.Namespace) -> int:
    text = render_scan_report(args.scan_id, fmt=args.format, store=NetMapperStore(args.database))
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Relatório salvo em {args.output}")
    else:
        print(text)
    return 0



def _handle_tls(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope_file)
    if scope:
        scope.assert_allowed(args.target, label="TLS target")
    result = inspect_tls_certificate(args.target, port=args.port, timeout=args.timeout, insecure=args.insecure)
    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"SHA-256: {result['sha256']}")
        print(f"Subject: {result.get('subject')}")
        print(f"Issuer: {result.get('issuer')}")
        print(f"SANs: {', '.join(result.get('subject_alt_names') or []) or '—'}")
        print(f"Validade: {result.get('not_before')} -> {result.get('not_after')}")
    return 0



def _handle_screenshot(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope_file)
    if scope:
        scope.assert_allowed(args.target, label="screenshot target")
    urls = _discover_http_urls_for_screenshot(args)
    artifacts = capture_screenshots(
        urls,
        output_dir=args.output_dir,
        timeout_ms=args.timeout_ms,
        insecure=args.insecure,
    )
    if args.scan_id:
        NetMapperStore(args.database).save_screenshot_artifacts(args.scan_id, artifacts)
    if args.as_json:
        print(json.dumps(artifacts, ensure_ascii=False, indent=2))
    else:
        for artifact in artifacts:
            print(f"{artifact['url']} -> {artifact['path']}")
    return 0



def _handle_subdomains(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope_file)
    if scope:
        scope.assert_allowed(args.domain, label="domain")
    result = enumerate_subdomains(args.domain, timeout=args.timeout)
    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for item in result:
            print(item)
    return 0



def _handle_plugins(args: argparse.Namespace) -> int:
    rows = [
        {
            "name": spec.name,
            "profiles": list(spec.profiles),
            "traffic": spec.traffic,
            "opt_in": spec.opt_in,
            "requirements": list(spec.requirements),
            "description": spec.description,
        }
        for spec in list_plugins()
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0



def _run_legacy(argv: list[str]) -> int:
    normalized_argv = _normalize_vulnerability_order(argv)
    args = build_legacy_parser().parse_args(normalized_argv)

    if args.external_target:
        if args.target:
            build_legacy_parser().error("Não combine um alvo posicional com -Ext/--ext.")

        try:
            scope = load_scope_file(args.scope_file)
            if scope:
                scope.assert_allowed(args.external_target, label="scan externo")
            if args.vulnerability:
                result = run_vulnerability_scan(
                    args.external_target,
                    ports=args.ports,
                    top_ports=args.top_ports,
                    timeout=(args.timeout if args.timeout is not None else DEFAULT_VULN_TIMEOUT),
                    os_detect=args.os_detect,
                )
            else:
                result = run_nmap(
                    args.external_target,
                    ports=args.ports,
                    top_ports=args.top_ports,
                    timeout=(args.timeout if args.timeout is not None else DEFAULT_EXTERNAL_TIMEOUT),
                    os_detect=args.os_detect,
                )
        except (NmapError, PluginError) as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 2

        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.vulnerability:
            print_vulnerability_result(result)
        else:
            print_external_result(result)
        return 0

    if not args.target:
        build_legacy_parser().error("Informe um IP/CIDR local ou use -Ext IP para um scan externo.")
    if args.vulnerability:
        build_legacy_parser().error("-vuln/--vuln só pode ser usado com -Ext/--ext.")
    if args.ports is not None or args.os_detect or args.top_ports != DEFAULT_TOP_PORTS:
        build_legacy_parser().error(
            "--ports, --top-ports e --os-detect só podem ser usados com -Ext/--ext."
        )

    try:
        devices = discover_hosts(
            args.target,
            timeout=args.timeout if args.timeout is not None else DEFAULT_TIMEOUT,
        )
    except (ConfigurationError, NetworkScanError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    vendor_lookup = VendorLookupService()
    results = [
        {
            "ip": device["ip"],
            "mac": device["mac"],
            "vendor": vendor_lookup.lookup(device["mac"]) or "Desconhecido",
        }
        for device in devices
    ]

    if args.as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    if not results:
        print(f"Nenhum dispositivo respondeu em {args.target}.")
        return 0

    print(f"{'IP':<16} {'MAC':<18} Fabricante")
    print("-" * 72)
    for device in results:
        print(f"{device['ip']:<16} {device['mac']:<18} {device['vendor']}")

    return 0



def _collect_scan_plugins(args: argparse.Namespace) -> list[str]:
    extra = list(args.plugin)
    if args.tls:
        extra.append("tls")
    if args.cve_local:
        extra.append("cve-local")
    if args.searchsploit:
        extra.append("cve-local")
    if args.nuclei:
        extra.append("nuclei")
    if args.default_creds:
        extra.append("default-creds")
    if args.screenshot:
        extra.append("screenshot")
    if args.nmap_vuln:
        extra.append("nmap-vuln")
    return expand_plugin_names(args.profile, extra)



def _save_scan_if_requested(result, database: str, save: bool) -> int | None:
    if not save:
        return None
    return NetMapperStore(database).save_scan(result)



def _discover_http_urls_for_screenshot(args: argparse.Namespace) -> list[str]:
    if args.scan_id:
        scan = NetMapperStore(args.database).load_scan(args.scan_id)
        hosts = scan.hosts
    else:
        result = run_nmap(
            args.target,
            ports=args.ports,
            top_ports=args.top_ports,
            timeout=args.timeout,
        )
        hosts = nmap_hosts_to_records(result)
    urls: list[str] = []
    for host in hosts:
        if host.address != args.target:
            continue
        for port in host.ports:
            service = (port.service or "").lower()
            if service.startswith("http") or port.port in {80, 443, 8080, 8443}:
                scheme = "https" if "https" in service or port.port in {443, 8443} else "http"
                url = f"{scheme}://{host.address}:{port.port}"
                if url not in urls:
                    urls.append(url)
    if not urls:
        raise CliError("Nenhuma porta HTTP/HTTPS descoberta para screenshot.")
    return urls



def print_scan_result(result, *, scan_id: int | None = None) -> None:
    print(f"Tipo: {result.scan_type}")
    print(f"Alvo: {result.target}")
    print(f"Perfil: {result.profile}")
    print(f"Plugins: {', '.join(result.plugins)}")
    print(f"Hosts: {len(result.hosts)}")
    print(f"Findings: {len(result.findings)}")
    if scan_id is not None:
        print(f"Scan ID: {scan_id}")
    for host in result.hosts:
        names = ", ".join(host.hostnames) or "-"
        print(f"\nHost {host.address} state={host.state} source={host.source or '-'} names={names}")
        for port in host.ports:
            version = " ".join(part for part in (port.product, port.version, port.extra) if part)
            print(f"  {port.port}/{port.protocol} {port.service or '-'} {version}".rstrip())
    if result.findings:
        print("\nAchados:")
        for finding in result.findings[:20]:
            location = f"{finding.host}:{finding.port}/{finding.protocol}" if finding.port else finding.host
            print(f"- [{finding.severity}] {location} {finding.plugin}: {finding.title}")
        if len(result.findings) > 20:
            print(f"... {len(result.findings) - 20} achados omitidos")



def _print_plugin_errors(result) -> None:
    errors = result.metadata.get("plugin_errors") if isinstance(result.metadata, dict) else None
    if not errors:
        return
    print("\nAvisos de plugins opcionais/soft-fail:")
    for item in errors:
        print(f"- {item['plugin']}: {item['error']}")



def _normalize_vulnerability_order(argv: Sequence[str] | None) -> list[str] | None:
    if argv is None:
        argv = sys.argv[1:]

    normalized = list(argv)
    for index, token in enumerate(normalized[:-2]):
        if token.lower() in {"-ext", "--ext"} and normalized[index + 1].lower() in {
            "-vuln",
            "--vuln",
        }:
            normalized[index + 1], normalized[index + 2] = (
                normalized[index + 2],
                normalized[index + 1],
            )
            break
    return normalized



def print_vulnerability_result(result: dict[str, object]) -> None:
    print(f"Alvo: {result['target']}")
    print(f"Estado: {result['host_state']}")
    if result.get("hostname"):
        print(f"Hostname: {result['hostname']}")
    if result.get("os"):
        print(f"Sistema operacional: {result['os']}")

    ports = result["ports"]
    if ports:
        print("\nPortas abertas:")
        for port in ports:
            version = " ".join(part for part in (port["product"], port["version"]) if part)
            print(f"  {port['port']}/{port['protocol']}  {port['service'] or '-':<12} {version}")

    findings = result["findings"]
    relevant_findings = [finding for finding in findings if finding["severity"] != "OK"]
    counts = {
        severity: sum(finding["severity"] == severity for finding in relevant_findings)
        for severity in ("ALTA", "MEDIA", "INFO")
    }
    print(
        f"\nAchados: {len(relevant_findings)} "
        f"(alta={counts['ALTA']}, media={counts['MEDIA']}, info={counts['INFO']})"
    )
    if not relevant_findings:
        print("Nenhum achado relevante retornado pelos scripts NSE.")
        return

    for finding in relevant_findings:
        location = f"{finding['port']}/{finding['protocol']}" if finding["port"] is not None else "host"
        print(f"\n[{finding['severity']}] {location} {finding['service']} - {finding['script']}")
        if finding["cves"]:
            print(f"  CVEs: {', '.join(finding['cves'])}")
        output_lines = finding["output"].splitlines()
        for line in output_lines[:8]:
            print(f"  {line}")
        if len(output_lines) > 8:
            print(f"  ... ({len(output_lines) - 8} linhas omitidas)")



def print_external_result(result: dict[str, object]) -> None:
    hosts = result["hosts"]
    print(f"Alvo: {result['target']}")
    print(f"Nmap: {result.get('nmap_version') or 'versão desconhecida'}")

    if not hosts:
        print("Nenhum host respondeu.")
        return

    for host in hosts:
        print(
            f"\nHost: {host['ip']}  estado={host['state']}  "
            f"hostname={', '.join(host['hostnames']) or '-'}"
        )
        open_ports = [port for port in host["ports"] if port["state"] == "open"]
        if not open_ports:
            print("  Nenhuma porta aberta detectada.")
            continue

        print("  PORTA/PROTO  SERVIÇO       VERSÃO")
        for port in open_ports:
            version = " ".join(part for part in (port["product"], port["version"], port["extra"]) if part)
            print(f"  {port['port']}/{port['protocol']:<5} {port['service']:<13} {version}")


if __name__ == "__main__":
    raise SystemExit(main())
