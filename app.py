from __future__ import annotations

import atexit
import argparse
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

from scanner import (
    ConfigurationError,
    DEFAULT_TIMEOUT,
    NetworkScanError,
    detect_local_cidr,
    discover_hosts,
    normalize_cidr,
    normalize_mac,
    validate_timeout,
)
from vendor import VendorLookupService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

DEFAULT_PREFIX = 24
DEFAULT_INTERVAL = 60
MIN_INTERVAL = 5
MAX_INTERVAL = 86400
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


class ScanAlreadyRunningError(RuntimeError):
    """Sinaliza tentativa de sobrepor duas varreduras."""


@dataclass(frozen=True)
class RuntimeConfig:
    cidr: str
    interval: int
    timeout: float


@dataclass
class ScanState:
    configured_cidr: str
    configured_interval: int
    configured_timeout: float
    devices: list[dict[str, Any]] = field(default_factory=list)
    scan_in_progress: bool = False
    current_scan_source: str | None = None
    last_scan_source: str | None = None
    last_scan_started_at: str | None = None
    last_scan_finished_at: str | None = None
    last_effective_cidr: str | None = None
    last_effective_timeout: float | None = None
    last_error: str | None = None
    scan_count: int = 0


class NetMapperController:
    def __init__(
        self,
        config: RuntimeConfig,
        scanner: Callable[[Any, Any], list[dict[str, str]]] | None = None,
        vendor_lookup: VendorLookupService | None = None,
    ) -> None:
        self._config = config
        self._scanner = scanner or discover_hosts
        self._vendor_lookup = vendor_lookup or VendorLookupService()
        self._state = ScanState(
            configured_cidr=config.cidr,
            configured_interval=config.interval,
            configured_timeout=config.timeout,
        )
        self._state_lock = threading.RLock()
        self._scan_lock = threading.Lock()
        self._thread_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None

    def start(self) -> None:
        with self._thread_lock:
            if self._worker and self._worker.is_alive():
                return

            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._periodic_loop,
                name="netmapper-periodic-scan",
                daemon=True,
            )
            self._worker.start()
            logger.info(
                "Scanner periódico iniciado para %s a cada %s segundos.",
                self._config.cidr,
                self._config.interval,
            )

    def stop(self) -> None:
        self._stop_event.set()
        worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            devices = [device.copy() for device in self._state.devices]
            return {
                "configured_cidr": self._state.configured_cidr,
                "configured_interval": self._state.configured_interval,
                "configured_timeout": self._state.configured_timeout,
                "devices": devices,
                "device_count": len(devices),
                "scan_in_progress": self._state.scan_in_progress,
                "current_scan_source": self._state.current_scan_source,
                "last_scan_source": self._state.last_scan_source,
                "last_scan_started_at": self._state.last_scan_started_at,
                "last_scan_finished_at": self._state.last_scan_finished_at,
                "last_effective_cidr": self._state.last_effective_cidr,
                "last_effective_timeout": self._state.last_effective_timeout,
                "last_error": self._state.last_error,
                "scan_count": self._state.scan_count,
            }

    def run_scan(
        self,
        source: str,
        cidr: Any | None = None,
        timeout: Any | None = None,
    ) -> dict[str, Any]:
        effective_cidr = normalize_cidr(cidr if cidr is not None else self._config.cidr)
        effective_timeout = validate_timeout(
            timeout if timeout is not None else self._config.timeout
        )

        if not self._scan_lock.acquire(blocking=False):
            raise ScanAlreadyRunningError("Já existe uma varredura em andamento.")

        started_at = _utcnow()
        with self._state_lock:
            self._state.scan_in_progress = True
            self._state.current_scan_source = source
            self._state.last_scan_started_at = started_at
            self._state.last_effective_cidr = effective_cidr
            self._state.last_effective_timeout = effective_timeout
            self._state.last_error = None

        try:
            devices = self._scanner(effective_cidr, effective_timeout)
            enriched_devices = [self._enrich_device(device) for device in devices]

            with self._state_lock:
                self._state.devices = enriched_devices
                self._state.last_scan_source = source
                self._state.last_scan_finished_at = _utcnow()
                self._state.last_error = None
                self._state.scan_count += 1
        except NetworkScanError as exc:
            logger.warning("Falha operacional ao varrer %s: %s", effective_cidr, exc)
            self._record_failure(source, exc)
            raise
        except Exception as exc:
            logger.exception("Falha inesperada ao varrer %s.", effective_cidr)
            self._record_failure(source, exc)
            raise
        finally:
            with self._state_lock:
                self._state.scan_in_progress = False
                self._state.current_scan_source = None

            self._scan_lock.release()

        return self.snapshot()

    def _periodic_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.run_scan("periodic")
            except ScanAlreadyRunningError:
                logger.info("Varredura periódica ignorada porque outra varredura está ativa.")
            except ConfigurationError:
                logger.exception("Configuração inválida na varredura periódica.")
            except NetworkScanError as exc:
                logger.warning("Falha operacional na varredura periódica: %s", exc)
            except Exception:
                logger.exception("Falha na varredura periódica.")

            if self._stop_event.wait(self._config.interval):
                break

    def _record_failure(self, source: str, exc: BaseException) -> None:
        with self._state_lock:
            self._state.last_scan_source = source
            self._state.last_scan_finished_at = _utcnow()
            self._state.last_error = f"{type(exc).__name__}: {exc}"

    def _enrich_device(self, device: dict[str, str]) -> dict[str, Any]:
        normalized_mac = normalize_mac(device["mac"])
        enriched = {"ip": str(device["ip"]), "mac": normalized_mac, "vendor": None}
        try:
            enriched["vendor"] = self._vendor_lookup.lookup(normalized_mac)
        except Exception as exc:
            logger.warning("Falha ao enriquecer fabricante de %s: %s", normalized_mac, exc)
            enriched["vendor"] = None
        return enriched


def validate_interval(value: Any) -> int:
    if value is None:
        raise ConfigurationError("Intervalo não informado.")

    try:
        interval = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"Intervalo inválido: {value!r}.") from exc

    if not (MIN_INTERVAL <= interval <= MAX_INTERVAL):
        raise ConfigurationError(
            f"Intervalo deve ficar entre {MIN_INTERVAL} e {MAX_INTERVAL} segundos."
        )

    return interval


def validate_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"Porta inválida: {value!r}.") from exc

    if not (1 <= port <= 65535):
        raise ConfigurationError("Porta deve ficar entre 1 e 65535.")

    return port


def load_runtime_config(
    cidr: Any | None = None,
    interval: Any | None = None,
    timeout: Any | None = None,
) -> RuntimeConfig:
    configured_cidr = cidr if cidr is not None else os.getenv("NETMAPPER_CIDR")
    cidr = (
        normalize_cidr(configured_cidr)
        if configured_cidr and configured_cidr.strip()
        else detect_local_cidr(DEFAULT_PREFIX)
    )
    configured_interval = (
        interval if interval is not None else os.getenv("NETMAPPER_SCAN_INTERVAL", DEFAULT_INTERVAL)
    )
    configured_timeout = (
        timeout if timeout is not None else os.getenv("NETMAPPER_SCAN_TIMEOUT", DEFAULT_TIMEOUT)
    )
    interval = validate_interval(configured_interval)
    timeout = validate_timeout(configured_timeout)
    return RuntimeConfig(cidr=cidr, interval=interval, timeout=timeout)


def create_app(
    config: RuntimeConfig | None = None,
    *,
    start_background: bool = True,
    scanner: Callable[[Any, Any], list[dict[str, str]]] | None = None,
    vendor_lookup: VendorLookupService | None = None,
) -> Flask:
    runtime_config = config or load_runtime_config()
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "netmapper_templates"),
    )
    controller = NetMapperController(
        config=runtime_config,
        scanner=scanner,
        vendor_lookup=vendor_lookup,
    )
    app.extensions["netmapper_controller"] = controller

    if start_background:

        @app.before_request
        def ensure_background_worker() -> None:
            controller.start()

        atexit.register(controller.stop)

    @app.get("/")
    def index() -> str:
        return render_template("index.html", snapshot=controller.snapshot())

    @app.get("/api/status")
    def api_status() -> Any:
        return jsonify(controller.snapshot())

    @app.post("/api/scan")
    def api_scan() -> Any:
        try:
            payload = _get_json_payload()
            snapshot = controller.run_scan(
                "manual",
                cidr=payload.get("cidr"),
                timeout=payload.get("timeout"),
            )
        except ConfigurationError as exc:
            return jsonify({"error": str(exc)}), 400
        except ScanAlreadyRunningError as exc:
            return jsonify({"error": str(exc), "status": controller.snapshot()}), 409
        except NetworkScanError as exc:
            return jsonify({"error": str(exc), "status": controller.snapshot()}), 500

        return jsonify(snapshot), 200

    return app


def _get_json_payload() -> dict[str, Any]:
    if not request.data:
        return {}

    try:
        payload = request.get_json(force=False, silent=False)
    except BadRequest as exc:
        raise ConfigurationError("Corpo JSON inválido.") from exc

    if payload is None:
        return {}

    if not isinstance(payload, dict):
        raise ConfigurationError("O corpo JSON deve ser um objeto.")

    return payload


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mapeador ARP de redes IPv4 com dashboard Flask")
    parser.add_argument(
        "--cidr",
        "--subnet",
        dest="cidr",
        help="Rede IPv4 alvo, por exemplo 192.168.15.0/24. Sem este argumento, detecta a rede local.",
    )
    parser.add_argument("--interval", type=int, help=f"Intervalo periódico em segundos (padrão: {DEFAULT_INTERVAL}).")
    parser.add_argument("--timeout", type=float, help=f"Timeout ARP em segundos (padrão: {DEFAULT_TIMEOUT}).")
    parser.add_argument("--host", help=f"Endereço do servidor (padrão: {DEFAULT_HOST}).")
    parser.add_argument("--port", type=int, help=f"Porta do servidor (padrão: {DEFAULT_PORT}).")
    args = parser.parse_args()

    try:
        runtime_config = load_runtime_config(
            cidr=args.cidr,
            interval=args.interval,
            timeout=args.timeout,
        )
        host = (args.host or os.getenv("NETMAPPER_HOST", DEFAULT_HOST) or DEFAULT_HOST).strip()
        port = validate_port(args.port if args.port is not None else os.getenv("NETMAPPER_PORT", DEFAULT_PORT))
    except ConfigurationError as exc:
        parser.error(str(exc))

    app = create_app(config=runtime_config)
    controller: NetMapperController = app.extensions["netmapper_controller"]

    controller.start()
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
