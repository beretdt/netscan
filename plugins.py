from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from schema import FindingRecord, HostRecord, ScanResult, utcnow


class PluginError(RuntimeError):
    """Falha ao executar um plugin."""


class MissingDependencyError(PluginError):
    """Dependência opcional ausente."""


class ScopeViolationError(PluginError):
    """Alvo fora do escopo permitido."""


@dataclass(frozen=True)
class PluginSpec:
    name: str
    description: str
    profiles: tuple[str, ...]
    depends_on: tuple[str, ...] = ()
    requirements: tuple[str, ...] = ()
    traffic: str = "local"
    opt_in: bool = False
    soft_fail: bool = False


@dataclass
class PluginResult:
    hosts: list[HostRecord] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    scan_type: str
    target: str
    profile: str
    command: str
    timeout: float
    database_path: Path
    options: dict[str, Any] = field(default_factory=dict)
    scope: Any | None = None
    inventory: dict[str, HostRecord] = field(default_factory=dict)
    findings: list[FindingRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(
        default_factory=lambda: {"plugin_errors": [], "plugin_timestamps": {}}
    )

    def iter_hosts(self) -> list[HostRecord]:
        return [self.inventory[key] for key in sorted(self.inventory)]

    def merge_result(self, plugin_name: str, result: PluginResult) -> None:
        for host in result.hosts:
            existing = self.inventory.get(host.address)
            if existing is None:
                self.inventory[host.address] = host
            else:
                existing.merge_from(host)
        self.findings.extend(result.findings)
        if result.metadata:
            self.metadata.setdefault("plugin_metadata", {})[plugin_name] = result.metadata
        self.metadata.setdefault("plugin_timestamps", {})[plugin_name] = utcnow()

    def build_scan_result(self, plugin_names: list[str]) -> ScanResult:
        result = ScanResult(
            scan_type=self.scan_type,
            target=self.target,
            profile=self.profile,
            command=self.command,
            plugins=plugin_names,
            hosts=self.iter_hosts(),
            findings=list(self.findings),
            metadata=dict(self.metadata),
        )
        result.finish()
        return result


PluginRunner = Callable[[ScanContext], PluginResult]
_PLUGIN_SPECS: dict[str, PluginSpec] = {}
_PLUGIN_RUNNERS: dict[str, PluginRunner] = {}
_BUILTINS_LOADED = False


def register_plugin(
    *,
    name: str,
    description: str,
    profiles: tuple[str, ...],
    depends_on: tuple[str, ...] = (),
    requirements: tuple[str, ...] = (),
    traffic: str = "local",
    opt_in: bool = False,
    soft_fail: bool = False,
) -> Callable[[PluginRunner], PluginRunner]:
    def decorator(func: PluginRunner) -> PluginRunner:
        if name in _PLUGIN_RUNNERS:
            raise ValueError(f"Plugin já registrado: {name}")
        _PLUGIN_SPECS[name] = PluginSpec(
            name=name,
            description=description,
            profiles=profiles,
            depends_on=depends_on,
            requirements=requirements,
            traffic=traffic,
            opt_in=opt_in,
            soft_fail=soft_fail,
        )
        _PLUGIN_RUNNERS[name] = func
        return func

    return decorator


def ensure_builtin_plugins_loaded() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    import passive  # noqa: F401
    import scanner  # noqa: F401
    import external  # noqa: F401
    import vuln  # noqa: F401
    import tlsinfo  # noqa: F401
    import cve_db  # noqa: F401
    import credentials  # noqa: F401
    import nuclei  # noqa: F401
    import screenshots  # noqa: F401
    import subdomains  # noqa: F401
    _BUILTINS_LOADED = True


def list_plugins() -> list[PluginSpec]:
    ensure_builtin_plugins_loaded()
    return [_PLUGIN_SPECS[name] for name in sorted(_PLUGIN_SPECS)]


def get_plugin_spec(name: str) -> PluginSpec:
    ensure_builtin_plugins_loaded()
    return _PLUGIN_SPECS[name]


def resolve_profile(profile: str) -> list[str]:
    ensure_builtin_plugins_loaded()
    return [spec.name for spec in list_plugins() if profile in spec.profiles and not spec.opt_in]


def expand_plugin_names(profile: str, include: list[str] | None = None) -> list[str]:
    ensure_builtin_plugins_loaded()
    requested = set(resolve_profile(profile))
    for item in include or []:
        requested.add(item)
    return _topological_sort(requested)


def _topological_sort(names: set[str]) -> list[str]:
    ordered: list[str] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(name: str) -> None:
        if name in permanent:
            return
        if name in temporary:
            raise PluginError(f"Dependência circular entre plugins envolvendo {name}.")
        if name not in _PLUGIN_RUNNERS:
            raise PluginError(f"Plugin desconhecido: {name}")
        temporary.add(name)
        spec = _PLUGIN_SPECS[name]
        for dependency in spec.depends_on:
            visit(dependency)
        temporary.remove(name)
        permanent.add(name)
        if name not in ordered:
            ordered.append(name)

    for name in sorted(names):
        visit(name)
    return ordered


def run_plugins(context: ScanContext, plugin_names: list[str]) -> ScanResult:
    ensure_builtin_plugins_loaded()
    for name in plugin_names:
        spec = _PLUGIN_SPECS[name]
        runner = _PLUGIN_RUNNERS[name]
        try:
            result = runner(context)
        except PluginError as exc:
            if not spec.soft_fail:
                raise
            context.metadata.setdefault("plugin_errors", []).append(
                {"plugin": name, "error": str(exc), "requirements": list(spec.requirements)}
            )
            continue
        context.merge_result(name, result)
    return context.build_scan_result(plugin_names)
