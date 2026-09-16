from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from plugins import PluginError, ScopeViolationError


@dataclass(frozen=True)
class ScopeFile:
    path: Path
    allowed: tuple[str, ...]
    denied: tuple[str, ...]

    def assert_allowed(self, target: str, *, label: str = "alvo") -> None:
        normalized = _normalize_target(target)
        for rule in self.denied:
            if _matches(rule, normalized):
                raise ScopeViolationError(
                    f"{label} {target!r} foi negado por {rule!r} em {self.path.name}."
                )
        if self.allowed and not any(_matches(rule, normalized) for rule in self.allowed):
            raise ScopeViolationError(
                f"{label} {target!r} está fora do escopo permitido por {self.path.name}."
            )


def load_scope_file(path: str | Path | None) -> ScopeFile | None:
    if path is None:
        return None
    scope_path = Path(path)
    try:
        content = scope_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScopeConfigurationError(
            f"Não foi possível ler o arquivo de escopo {scope_path}: {exc}."
        ) from exc
    try:
        parsed = _parse_simple_yaml(content)
    except ValueError as exc:
        raise ScopeConfigurationError(
            f"Arquivo de escopo inválido {scope_path}: {exc}."
        ) from exc
    allowed = tuple(str(item).strip() for item in parsed.get("allowed", []) if str(item).strip())
    denied = tuple(str(item).strip() for item in parsed.get("denied", []) if str(item).strip())
    return ScopeFile(path=scope_path, allowed=allowed, denied=denied)


class ScopeConfigurationError(PluginError):
    """Arquivo de escopo ausente ou malformado."""


def _parse_simple_yaml(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"allowed": [], "denied": []}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw_line.startswith((" ", "\t")) and ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            current_key = key if key in {"allowed", "denied"} else None
            if current_key and value:
                if value.startswith("[") and value.endswith("]"):
                    items = [
                        item.strip().strip('"\'')
                        for item in value[1:-1].split(",")
                        if item.strip()
                    ]
                    result[current_key] = items
                else:
                    result[current_key] = [value.strip('"\'')]
            elif current_key:
                result.setdefault(current_key, [])
            continue
        stripped = line.strip()
        if stripped.startswith("-") and current_key is not None:
            result.setdefault(current_key, []).append(stripped[1:].strip().strip('"\''))
            continue
        if current_key is not None:
            raise ValueError("listas de allowed/denied devem conter itens iniciados por '-'.")
    return result


def _normalize_target(value: str) -> Any:
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate
    try:
        if "/" in candidate:
            return ipaddress.ip_network(candidate, strict=False)
        return ipaddress.ip_address(candidate)
    except ValueError:
        return candidate.lower().rstrip(".")


def _matches(rule: str, target: Any) -> bool:
    normalized_rule = _normalize_target(rule)
    if isinstance(normalized_rule, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return isinstance(target, type(normalized_rule)) and target == normalized_rule
    if isinstance(normalized_rule, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return target in normalized_rule
        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return target.subnet_of(normalized_rule)
        return False
    if isinstance(target, str):
        return target == normalized_rule or target.endswith(f".{normalized_rule}")
    return False
