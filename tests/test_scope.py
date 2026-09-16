import unittest
from pathlib import Path

from plugins import ScopeViolationError
from scope import load_scope_file


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope_path = Path(__file__).resolve().parent / "workspace" / "scope-test.yaml"
        self.scope_path.write_text(
            "engagement: demo\nwindow:\n  start: 2026-01-01\nallowed:\n  - 203.0.113.0/24\n  - example.com\ndenied:\n  - admin.example.com\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        if self.scope_path.exists():
            self.scope_path.unlink()

    def test_scope_allows_ip_and_domain_suffix(self) -> None:
        scope = load_scope_file(self.scope_path)
        assert scope is not None
        scope.assert_allowed("203.0.113.10")
        scope.assert_allowed("api.example.com")

    def test_scope_denies_explicit_host(self) -> None:
        scope = load_scope_file(self.scope_path)
        assert scope is not None
        with self.assertRaises(ScopeViolationError):
            scope.assert_allowed("admin.example.com")


if __name__ == "__main__":
    unittest.main()
