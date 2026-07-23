import pytest

from mcp_hayabusa import knowledge

VALID_RULE_A = """\
title: Mimikatz Command Line
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects mimikatz usage via command line
tags:
    - attack.credential-access
    - attack.t1003.001
    - cve.2021-1675
level: critical
"""

VALID_RULE_B = """\
title: PowerShell Encoded Command
id: 22222222-2222-2222-2222-222222222222
status: stable
description: Detects obfuscated PowerShell execution
tags:
    - attack.execution
    - attack.t1059.001
level: high
"""

VALID_RULE_C = """\
title: Suspicious Scheduled Task
id: 33333333-3333-3333-3333-333333333333
status: test
description: Detects scheduled task persistence
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.g0007
level: medium
"""

MALFORMED_RULE = "title: [unterminated\n  - broken yaml"

NON_MAPPING_RULE = "- just\n- a\n- list\n"


@pytest.fixture
def rules_dir(tmp_path):
    category_a = tmp_path / "sigma" / "builtin"
    category_a.mkdir(parents=True)
    (category_a / "mimikatz.yml").write_text(VALID_RULE_A, encoding="utf-8")
    (category_a / "powershell.yml").write_text(VALID_RULE_B, encoding="utf-8")

    category_b = tmp_path / "sigma" / "community"
    category_b.mkdir(parents=True)
    (category_b / "scheduled_task.yml").write_text(VALID_RULE_C, encoding="utf-8")

    (tmp_path / "broken.yml").write_text(MALFORMED_RULE, encoding="utf-8")
    (tmp_path / "not_a_mapping.yml").write_text(NON_MAPPING_RULE, encoding="utf-8")
    return tmp_path


def test_load_rule_catalog_parses_valid_and_counts_errors(rules_dir):
    rules_path, records, parse_errors = knowledge.load_rule_catalog(str(rules_dir))

    assert rules_path == rules_dir
    assert parse_errors == 2  # broken.yml + not_a_mapping.yml
    assert {r["title"] for r in records} == {
        "Mimikatz Command Line",
        "PowerShell Encoded Command",
        "Suspicious Scheduled Task",
    }


def test_load_rule_catalog_missing_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        knowledge.load_rule_catalog(str(tmp_path / "nope"))


def test_technique_ids_matches_technique_and_subtechnique_only():
    tags = ["attack.t1003.001", "attack.t1059", "attack.execution", "cve.2021-1675", "attack.g0007"]
    assert knowledge._technique_ids(tags) == ["T1003.001", "T1059"]


def test_tactic_names_excludes_techniques_and_group_software_tags():
    tags = [
        "attack.credential-access",
        "attack.t1003.001",
        "attack.g0007",
        "attack.s0002",
        "cve.2021-1675",
    ]
    assert knowledge._tactic_names(tags) == ["credential-access"]


def test_rules_index_groups_by_top_two_path_segments(rules_dir):
    result = knowledge.rules_index(str(rules_dir))

    assert result["total_rules"] == 3
    assert result["parse_errors"] == 2
    assert set(result["categories"]) == {"sigma/builtin", "sigma/community"}
    assert result["categories"]["sigma/builtin"]["total_rules"] == 2
    assert result["categories"]["sigma/community"]["total_rules"] == 1


def test_rules_index_bounds_per_category(rules_dir):
    result = knowledge.rules_index(str(rules_dir), max_items=1)

    builtin = result["categories"]["sigma/builtin"]
    assert builtin["total_rules"] == 2
    assert builtin["returned_rules"] == 1
    assert builtin["truncated"] is True
    assert len(builtin["rules"]) == 1


def test_get_rule_returns_full_detail(rules_dir):
    rule = knowledge.get_rule("22222222-2222-2222-2222-222222222222", str(rules_dir))

    assert rule["title"] == "PowerShell Encoded Command"
    assert rule["tags"] == ["attack.execution", "attack.t1059.001"]
    assert rule["path"] in ("sigma\\builtin\\powershell.yml", "sigma/builtin/powershell.yml")


def test_get_rule_unknown_id_raises_key_error(rules_dir):
    with pytest.raises(KeyError):
        knowledge.get_rule("does-not-exist", str(rules_dir))


def test_list_attack_techniques_aggregates_by_technique(rules_dir):
    result = knowledge.list_attack_techniques(str(rules_dir))

    assert result["total_techniques"] == 3
    assert set(result["techniques"]) == {"T1003.001", "T1059.001", "T1053.005"}
    assert result["techniques"]["T1003.001"]["rule_count"] == 1
    assert result["techniques"]["T1003.001"]["rules"][0]["title"] == "Mimikatz Command Line"


def test_get_attack_technique_matches_case_insensitively(rules_dir):
    result = knowledge.get_attack_technique("t1059.001", str(rules_dir))

    assert result["technique_id"] == "T1059.001"
    assert result["total_rules"] == 1
    assert result["rules"][0]["title"] == "PowerShell Encoded Command"


def test_get_attack_technique_no_matches_returns_empty(rules_dir):
    result = knowledge.get_attack_technique("T9999", str(rules_dir))

    assert result["total_rules"] == 0
    assert result["rules"] == []


def test_list_attack_tactics_aggregates_by_tactic(rules_dir):
    result = knowledge.list_attack_tactics(str(rules_dir))

    assert result["total_tactics"] == 3
    assert set(result["tactics"]) == {"credential-access", "execution", "persistence"}
    assert result["tactics"]["persistence"]["rule_count"] == 1
    assert result["tactics"]["persistence"]["rules"][0]["title"] == "Suspicious Scheduled Task"
