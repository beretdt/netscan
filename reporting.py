from __future__ import annotations

import json

from jinja2 import Environment, PackageLoader, select_autoescape

from persistence import NetMapperStore


_ENVIRONMENT = Environment(
    loader=PackageLoader("netmapper_templates", package_path=""),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_scan_report(scan_id: int, *, fmt: str, store: NetMapperStore) -> str:
    scan = store.load_scan(scan_id)
    payload = scan.to_dict()
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    if fmt == "md":
        return _ENVIRONMENT.get_template("scan_report.md.j2").render(scan=payload)
    if fmt == "html":
        return _ENVIRONMENT.get_template("scan_report.html.j2").render(scan=payload)
    raise ValueError(f"Formato de relatório inválido: {fmt}")
