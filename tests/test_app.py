import unittest

from app import RuntimeConfig, create_app


class AppTests(unittest.TestCase):
    def test_dashboard_template_is_available_from_packaged_template_dir(self) -> None:
        app = create_app(
            RuntimeConfig(
                cidr="192.168.1.0/24",
                interval=60,
                timeout=2.0,
            ),
            start_background=False,
        )

        response = app.test_client().get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NetMapper", response.data)


if __name__ == "__main__":
    unittest.main()
