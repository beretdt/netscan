import json
import unittest
from pathlib import Path

from cve_db import lookup_local_cves, update_cve_database


class CveDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace = Path(__file__).resolve().parent / "workspace"
        self.database_path = workspace / "cve-test.sqlite3"
        self.feed_path = workspace / "cve-feed.json"
        if self.database_path.exists():
            self.database_path.unlink()
        self.feed_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-0001",
                                "published": "2024-01-01T00:00:00.000",
                                "lastModified": "2024-01-02T00:00:00.000",
                                "descriptions": [{"lang": "en", "value": "Example Apache issue."}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.8}}
                                    ]
                                },
                                "references": [{"url": "https://example.test/CVE-2024-0001"}],
                            },
                            "configurations": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "2.4.0",
                                            "versionEndExcluding": "2.4.50",
                                            "vulnerable": True,
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        for path in (self.database_path, self.feed_path):
            if path.exists():
                path.unlink()

    def test_update_and_lookup_local_cves(self) -> None:
        result = update_cve_database(database_path=self.database_path, feed_file=self.feed_path)
        self.assertEqual(result["cves"], 1)
        rows = lookup_local_cves(
            database_path=self.database_path,
            product="Apache httpd",
            version="2.4.49",
            vendor="apache",
        )
        self.assertEqual(rows[0]["cve_id"], "CVE-2024-0001")

    def test_lookup_respects_version_range(self) -> None:
        update_cve_database(database_path=self.database_path, feed_file=self.feed_path)
        rows = lookup_local_cves(
            database_path=self.database_path,
            product="Apache httpd",
            version="2.4.50",
            vendor="apache",
        )
        self.assertEqual(rows, [])

    def test_imports_legacy_nvd_11_feed(self) -> None:
        self.feed_path.write_text(
            json.dumps(
                {
                    "CVE_Items": [
                        {
                            "cve": {
                                "CVE_data_meta": {"ID": "CVE-2020-0001"},
                                "description": {
                                    "description_data": [
                                        {"lang": "en", "value": "Legacy issue."}
                                    ]
                                },
                                "references": {
                                    "reference_data": [
                                        {"url": "https://example.test/legacy"}
                                    ]
                                },
                            },
                            "impact": {
                                "baseMetricV3": {
                                    "cvssV3": {"baseSeverity": "HIGH", "baseScore": 8.0}
                                }
                            },
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpe_match": [
                                                {
                                                    "cpe23Uri": "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*",
                                                    "versionStartIncluding": "2.4.0",
                                                    "versionEndExcluding": "2.4.50",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        update_cve_database(database_path=self.database_path, feed_file=self.feed_path)
        rows = lookup_local_cves(
            database_path=self.database_path,
            product="httpd",
            version="2.4.49",
            vendor="apache",
        )
        self.assertEqual(rows[0]["cve_id"], "CVE-2020-0001")
        self.assertEqual(rows[0]["severity"], "HIGH")
        self.assertEqual(rows[0]["references"], ["https://example.test/legacy"])


if __name__ == "__main__":
    unittest.main()
