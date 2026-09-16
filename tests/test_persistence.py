import unittest
from contextlib import closing
from pathlib import Path

from persistence import NetMapperStore
from reporting import render_scan_report
from schema import FindingRecord, HostRecord, PortRecord, ScanResult


class PersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database_path = Path(__file__).resolve().parent / "workspace" / "scan-test.sqlite3"
        if self.database_path.exists():
            self.database_path.unlink()
        self.store = NetMapperStore(self.database_path)

    def tearDown(self) -> None:
        if self.database_path.exists():
            self.database_path.unlink()

    def test_save_diff_and_report(self) -> None:
        first = ScanResult(
            scan_type="active-scan",
            target="203.0.113.10",
            profile="basic",
            command="netscan scan 203.0.113.10",
            plugins=["nmap-service"],
            hosts=[HostRecord(address="203.0.113.10", ports=[PortRecord(port=80, service="http")])],
        )
        first.finish()
        first_id = self.store.save_scan(first)

        second = ScanResult(
            scan_type="active-scan",
            target="203.0.113.10",
            profile="enrich",
            command="netscan scan 203.0.113.10 --tls",
            plugins=["nmap-service", "tls"],
            hosts=[HostRecord(address="203.0.113.10", ports=[PortRecord(port=80, service="http"), PortRecord(port=443, service="https")])],
            findings=[FindingRecord(host="203.0.113.10", title="TLS", plugin="tls", port=443, protocol="tcp")],
        )
        second.finish()
        second_id = self.store.save_scan(second)

        diff = self.store.diff_scans(first_id, second_id)
        self.assertEqual(len(diff["added_ports"]), 1)
        self.assertEqual(len(diff["added_findings"]), 1)

        markdown = render_scan_report(second_id, fmt="md", store=self.store)
        html = render_scan_report(second_id, fmt="html", store=self.store)
        self.assertIn("203.0.113.10", markdown)
        self.assertIn("Relatório NetMapper", html)

    def test_persists_certificates_and_screenshots(self) -> None:
        scan = ScanResult(
            scan_type="active-scan",
            target="203.0.113.10",
            profile="web",
            command="test",
            plugins=["nmap-service", "tls", "screenshot"],
            hosts=[
                HostRecord(
                    address="203.0.113.10",
                    ports=[
                        PortRecord(
                            port=443,
                            service="https",
                            tls={"sha256": "abc", "subject_alt_names": ["example.test"]},
                        )
                    ],
                )
            ],
            metadata={
                "plugin_metadata": {
                    "screenshot": {
                        "artifacts": [
                            {
                                "url": "https://203.0.113.10:443",
                                "path": "screenshots/example.png",
                            }
                        ]
                    }
                }
            },
        )
        scan.finish()
        scan_id = self.store.save_scan(scan)
        loaded = self.store.load_scan(scan_id)
        self.assertEqual(loaded.hosts[0].ports[0].tls["sha256"], "abc")
        self.assertEqual(loaded.metadata["screenshots"][0]["path"], "screenshots/example.png")
        with closing(self.store._connect()) as connection:  # noqa: SLF001
            certificate_count = connection.execute(
                "SELECT COUNT(*) FROM certificates WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
            screenshot_count = connection.execute(
                "SELECT COUNT(*) FROM screenshots WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
        self.assertEqual(certificate_count, 1)
        self.assertEqual(screenshot_count, 1)


if __name__ == "__main__":
    unittest.main()
