"""Unit tests for Sigma rule YAML structure, UUIDs, tags, and logsource."""
import pytest
import yaml
import uuid
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "rules"
REQUIRED_FIELDS = {"title", "id", "status", "description", "tags", "logsource", "detection", "level"}
VALID_STATUSES = {"stable", "experimental", "test", "deprecated"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def get_rules():
    return sorted(RULES_DIR.glob("*.yml"))


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


class TestRuleStructure:
    def test_all_rules_have_required_fields(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            missing = REQUIRED_FIELDS - set(rule.keys())
            assert not missing, f"{rule_file.name} missing: {missing}"

    def test_all_rules_valid_yaml(self):
        for rule_file in get_rules():
            try:
                load(rule_file)
            except yaml.YAMLError as e:
                pytest.fail(f"{rule_file.name} invalid YAML: {e}")

    def test_all_titles_non_empty(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert rule.get("title"), f"{rule_file.name}: empty title"

    def test_all_ids_are_valid_uuids(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            try:
                uuid.UUID(str(rule["id"]))
            except ValueError:
                pytest.fail(f"{rule_file.name}: invalid UUID: {rule['id']}")

    def test_all_ids_unique(self):
        ids = [load(f)["id"] for f in get_rules()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_statuses_valid(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert rule["status"] in VALID_STATUSES, \
                f"{rule_file.name}: invalid status '{rule['status']}'"

    def test_all_levels_valid(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert rule["level"] in VALID_LEVELS, \
                f"{rule_file.name}: invalid level '{rule['level']}'"

    def test_all_descriptions_non_empty(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert rule.get("description"), f"{rule_file.name}: empty description"


class TestMitreTags:
    def test_all_rules_have_attack_technique_tag(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            tags = rule.get("tags", [])
            attack_t_tags = [t for t in tags if t.startswith("attack.t")]
            assert attack_t_tags, f"{rule_file.name}: no attack.t* MITRE tag"

    def test_tags_are_lowercase(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            for tag in rule.get("tags", []):
                assert tag == tag.lower(), f"{rule_file.name}: tag not lowercase: {tag}"

    def test_tags_is_list(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert isinstance(rule.get("tags"), list), f"{rule_file.name}: tags not a list"


class TestLogsource:
    def test_logsource_present(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert "logsource" in rule, f"{rule_file.name}: missing logsource"

    def test_logsource_is_dict(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert isinstance(rule["logsource"], dict), f"{rule_file.name}: logsource not dict"

    def test_logsource_has_product_service_or_category(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            ls = rule["logsource"]
            assert any(k in ls for k in ["product", "service", "category"]), \
                f"{rule_file.name}: logsource missing product/service/category"


class TestDetection:
    def test_detection_has_condition(self):
        for rule_file in get_rules():
            rule = load(rule_file)
            assert "condition" in rule["detection"], \
                f"{rule_file.name}: detection missing condition"

    def test_minimum_four_rules(self):
        assert len(get_rules()) >= 4, f"Expected ≥4 rules, found {len(get_rules())}"
