"""Every module in the package tree must import cleanly from the repo root."""
import importlib
import unittest

MODULES = [
    "core.report",
    "core.database",
    "core.scanner",
    "core.log_analyzer",
    "core.alerting",
    "core.rule_loader",
    "core.detection_engine",
    "ingestion.log_ingestor",
    "ingestion.realtime_monitor",
    "modules.mitre_mapping",
    "modules.geo_ip",
    "modules.threat_intel",
    "modules.anomaly_detection",
]


class TestImports(unittest.TestCase):
    def test_every_module_imports(self):
        failures = []
        for name in MODULES:
            try:
                importlib.import_module(name)
            except Exception as exc:
                failures.append("{}: {}".format(name, exc))
        self.assertEqual([], failures)


if __name__ == "__main__":
    unittest.main()
