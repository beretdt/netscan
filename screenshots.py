from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from plugins import MissingDependencyError, PluginError, PluginResult, ScanContext, register_plugin
from schema import FindingRecord


class ScreenshotError(PluginError):
    """Falha ao capturar screenshots web."""



def capture_screenshots(
    urls: list[str],
    *,
    output_dir: str | Path,
    timeout_ms: int,
    insecure: bool,
) -> list[dict[str, str]]:
    if timeout_ms < 100:
        raise ScreenshotError("Timeout de screenshot deve ser de pelo menos 100 ms.")
    try:
        from playwright.sync_api import Error as PlaywrightError, sync_playwright  # type: ignore[import-untyped]
    except ImportError as exc:
        raise MissingDependencyError(
            "Playwright não está instalado; use o extra [screenshots] e execute 'playwright install'."
        ) from exc

    destination = Path(output_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScreenshotError(f"Não foi possível criar o diretório de screenshots: {exc}.") from exc
    artifacts: list[dict[str, str]] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(ignore_https_errors=insecure)
            try:
                page = context.new_page()
                for url in urls:
                    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", url).strip("_") or "screenshot"
                    output_path = destination / f"{safe_name}.png"
                    try:
                        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                        page.screenshot(path=str(output_path), full_page=True)
                    except PlaywrightError as exc:
                        raise ScreenshotError(f"Falha ao capturar {url}: {exc}") from exc
                    artifacts.append({"url": url, "path": str(output_path)})
            finally:
                context.close()
                browser.close()
    except ScreenshotError:
        raise
    except (OSError, PlaywrightError) as exc:
        raise ScreenshotError(f"Falha ao inicializar ou finalizar o Playwright: {exc}.") from exc
    return artifacts


@register_plugin(
    name="screenshot",
    description="Captura screenshots Playwright de URLs HTTP/HTTPS descobertas.",
    profiles=("web",),
    depends_on=("nmap-service",),
    traffic="http-get",
    opt_in=True,
    requirements=("playwright",),
)
def screenshot_plugin(context: ScanContext) -> PluginResult:
    urls = _http_urls_from_context(context)
    output_dir = Path(context.options.get("screenshot_output_dir") or (Path.cwd() / "screenshots"))
    artifacts = capture_screenshots(
        urls,
        output_dir=output_dir,
        timeout_ms=int(context.options.get("screenshot_timeout_ms") or 7000),
        insecure=bool(context.options.get("screenshot_insecure")),
    )
    findings = [
        FindingRecord(
            host=item["url"],
            title="Screenshot capturado",
            plugin="screenshot",
            severity="info",
            description=item["path"],
            category="artifact",
            references=[item["path"]],
            evidence=item,
        )
        for item in artifacts
    ]
    return PluginResult(findings=findings, metadata={"artifacts": artifacts})



def _http_urls_from_context(context: ScanContext) -> list[str]:
    urls: list[str] = []
    for host in context.iter_hosts():
        for port in host.ports:
            service = (port.service or "").lower()
            if service.startswith("http") or port.port in {80, 443, 8080, 8443}:
                scheme = "https" if "https" in service or port.port in {443, 8443} else "http"
                urls.append(f"{scheme}://{host.address}:{port.port}")
    unique_urls: list[str] = []
    for url in urls:
        if url not in unique_urls:
            unique_urls.append(url)
    if not unique_urls:
        raise ScreenshotError("Nenhuma URL HTTP/HTTPS descoberta para screenshot.")
    return unique_urls
