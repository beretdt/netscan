from __future__ import annotations

import logging
import threading
from typing import Any

from scanner import normalize_mac

logger = logging.getLogger(__name__)


class VendorLookupService:
    """Resolve fabricante por OUI com cache simples e inicialização preguiçosa."""

    def __init__(self) -> None:
        self._cache: dict[str, str | None] = {}
        self._cache_lock = threading.Lock()
        self._client_lock = threading.Lock()
        self._client: Any | None = None
        self._disabled = False
        self._expected_errors: tuple[type[BaseException], ...] = ()

    def lookup(self, mac_address: str) -> str | None:
        normalized_mac = normalize_mac(mac_address)

        with self._cache_lock:
            if normalized_mac in self._cache:
                return self._cache[normalized_mac]

        client = self._get_client()
        if client is None:
            return None

        try:
            vendor_name = client.lookup(normalized_mac)
        except self._expected_errors as exc:
            logger.info("Fabricante não encontrado para %s: %s", normalized_mac, exc)
            vendor_name = None
        except Exception:
            logger.exception("Falha inesperada ao resolver fabricante de %s.", normalized_mac)
            raise

        normalized_vendor = vendor_name.strip() if isinstance(vendor_name, str) else None
        if normalized_vendor == "":
            normalized_vendor = None

        with self._cache_lock:
            self._cache[normalized_mac] = normalized_vendor

        return normalized_vendor

    def _get_client(self) -> Any | None:
        if self._disabled:
            return None

        if self._client is not None:
            return self._client

        with self._client_lock:
            if self._disabled:
                return None
            if self._client is not None:
                return self._client

            try:
                from mac_vendor_lookup import (  # type: ignore[import-untyped]
                    InvalidMacError,
                    MacLookup,
                    VendorNotFoundError,
                )
            except ImportError as exc:
                logger.warning(
                    "Biblioteca mac-vendor-lookup indisponível; fabricantes serão omitidos: %s",
                    exc,
                )
                self._disabled = True
                return None

            try:
                self._client = MacLookup()
            except (FileNotFoundError, OSError, ValueError) as exc:
                logger.warning(
                    "Base OUI indisponível; fabricantes serão omitidos até a dependência ser corrigida: %s",
                    exc,
                )
                self._disabled = True
                return None

            self._expected_errors = (VendorNotFoundError, InvalidMacError, KeyError)
            return self._client
