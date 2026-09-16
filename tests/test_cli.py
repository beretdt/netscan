import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

import nestscan
from schema import ScanResult


class CliTests(unittest.TestCase):
    def test_help_mentions_scan_and_passive(self) -> None:
        parser = nestscan.build_root_parser()
        help_text = parser.format_help()
        self.assertIn("scan", help_text)
        self.assertIn("passive", help_text)

    @mock.patch("nestscan.run_plugins")
    @mock.patch("nestscan.expand_plugin_names", return_value=["nmap-service"])
    def test_scan_command_outputs_json(self, _expand, run_plugins) -> None:
        run_plugins.return_value = ScanResult(
            scan_type="active-scan",
            target="203.0.113.10",
            profile="basic",
            command="test",
            plugins=["nmap-service"],
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = nestscan.main(["scan", "203.0.113.10", "--no-save", "--json"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["target"], "203.0.113.10")

    @mock.patch("nestscan.VendorLookupService")
    @mock.patch("nestscan.discover_hosts", return_value=[{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}])
    def test_legacy_local_mode_still_works(self, _discover, vendor_lookup_cls) -> None:
        vendor_lookup_cls.return_value.lookup.return_value = "Vendor"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = nestscan.main(["192.168.1.0/24"])
        self.assertEqual(exit_code, 0)
        self.assertIn("192.168.1.10", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
