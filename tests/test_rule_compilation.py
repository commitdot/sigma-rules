"""Unit tests for Sigma rule content and compilation readiness."""
import pytest
import yaml
from pathlib import Path
from unittest.mock import MagicMock, patch

RULES_DIR = Path(__file__).parent.parent / "rules"


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


class TestRuleContent:
    def test_ssh_rule_contains_failed_password(self):
        rule = load(RULES_DIR / "ssh_brute_force.yml")
        content = str(rule["detection"])
        assert "Failed password" in content

    def test_powershell_rule_contains_powershell(self):
        rule = load(RULES_DIR / "powershell_encoded_command.yml")
        content = str(rule["detection"])
        assert "powershell" in content.lower()

    def test_new_admin_rule_references_event_4720(self):
        rule = load(RULES_DIR / "new_local_admin_created.yml")
        content = str(rule["detection"])
        assert "4720" in content

    def test_psexec_rule_references_psexesvc(self):
        rule = load(RULES_DIR / "lateral_movement_psexec.yml")
        content = str(rule["detection"])
        assert "PSEXESVC" in content

    def test_rules_directory_has_at_least_4_yml_files(self):
        yml_files = list(RULES_DIR.glob("*.yml"))
        assert len(yml_files) >= 4, f"Expected ≥4 rules, found {len(yml_files)}"

    def test_all_rules_are_valid_yaml(self):
        for rule_file in sorted(RULES_DIR.glob("*.yml")):
            try:
                load(rule_file)
            except yaml.YAMLError as e:
                pytest.fail(f"{rule_file.name}: {e}")

    def test_all_rules_have_logsource(self):
        for rule_file in sorted(RULES_DIR.glob("*.yml")):
            rule = load(rule_file)
            assert "logsource" in rule and isinstance(rule["logsource"], dict)

    def test_ssh_rule_level_is_high(self):
        rule = load(RULES_DIR / "ssh_brute_force.yml")
        assert rule["level"] == "high"

    def test_powershell_rule_level_is_medium(self):
        rule = load(RULES_DIR / "powershell_encoded_command.yml")
        assert rule["level"] == "medium"

    def test_psexec_rule_is_experimental(self):
        rule = load(RULES_DIR / "lateral_movement_psexec.yml")
        assert rule["status"] == "experimental"

    def test_new_admin_rule_is_stable(self):
        rule = load(RULES_DIR / "new_local_admin_created.yml")
        assert rule["status"] == "stable"


class TestCompilationReadiness:
    def test_all_rules_have_detection_condition(self):
        for rule_file in sorted(RULES_DIR.glob("*.yml")):
            rule = load(rule_file)
            assert "condition" in rule["detection"], \
                f"{rule_file.name}: missing condition"

    def test_all_rules_compilable_structure(self):
        for rule_file in sorted(RULES_DIR.glob("*.yml")):
            rule = load(rule_file)
            assert "title" in rule
            assert "logsource" in rule
            assert "detection" in rule
            assert isinstance(rule["logsource"], dict)
            assert isinstance(rule["detection"], dict)

    @patch("builtins.open", create=True)
    def test_mock_compiler_called(self, mock_open):
        """Demonstrates how compiler would be mocked in CI."""
        mock_compiler = MagicMock()
        mock_compiler.convert.return_value = "search index=linux 'Failed password'"
        result = mock_compiler.convert(str(RULES_DIR / "ssh_brute_force.yml"), backend="splunk")
        assert "Failed password" in result
        mock_compiler.convert.assert_called_once()
