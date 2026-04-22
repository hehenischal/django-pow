import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class PackageStructureTests(unittest.TestCase):
    def test_expected_files_exist(self):
        expected_files = [
            REPO_ROOT / "django_pow" / "__init__.py",
            REPO_ROOT / "django_pow" / "apps.py",
            REPO_ROOT / "django_pow" / "models.py",
            REPO_ROOT / "django_pow" / "views.py",
            REPO_ROOT / "django_pow" / "urls.py",
            REPO_ROOT / "django_pow" / "admin.py",
            REPO_ROOT / "django_pow" / "migrations" / "__init__.py",
            REPO_ROOT / "django_pow" / "fixtures" / "dummy_data.json",
        ]

        for file_path in expected_files:
            self.assertTrue(file_path.exists(), f"Missing expected file: {file_path}")

    def test_dummy_data_fixture_shape(self):
        fixture_path = REPO_ROOT / "django_pow" / "fixtures" / "dummy_data.json"
        fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))

        self.assertIsInstance(fixture_data, list)
        self.assertGreaterEqual(len(fixture_data), 2)

        for item in fixture_data:
            self.assertIn("model", item)
            self.assertIn("pk", item)
            self.assertIn("fields", item)
            self.assertIn("name", item["fields"])
            self.assertIn("is_active", item["fields"])


if __name__ == "__main__":
    unittest.main()
