# 📜 Sigma Detection Rules

[![Tests](https://github.com/commitdot/sigma-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/commitdot/sigma-rules/actions)
[![Sigma](https://img.shields.io/badge/Format-Sigma-orange)](https://github.com/SigmaHQ/sigma)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)

> SIEM-agnostic detection rules written in Sigma YAML format, mapped to MITRE ATT&CK, compilable to Splunk SPL, Elastic KQL, and QRadar AQL.

## Rules Inventory

| Rule | Tactic | Technique | Severity | Log Source |
|------|--------|-----------|----------|------------|
| SSH Brute Force | Credential Access | T1110.001 | High | Linux auth |
| PowerShell Encoded Command | Execution | T1059.001 | Medium | Windows Sysmon |
| New Local Admin Account | Persistence | T1136.001 | High | Windows Security |
| PsExec Lateral Movement | Lateral Movement | T1021.002 | High | Windows System |

## Compile Rules

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch

# Compile single rule to Splunk SPL
sigma convert -t splunk rules/ssh_brute_force.yml

# Compile single rule to Elastic KQL
sigma convert -t elasticsearch rules/powershell_encoded_command.yml

# Compile all rules
sigma convert -t splunk rules/ -o output/splunk_queries.txt
```

## Rule Structure

```yaml
title: SSH Brute Force Attack
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects multiple SSH authentication failures from a single source IP
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - "Failed password for"
  timeframe: 5m
  condition: keywords | count() by src_ip > 10
level: high
```

## Testing

```bash
pip install pytest pyyaml
pytest tests/ -v
# 35 tests — YAML structure, UUID validation, MITRE tags, compilation
```

## Skills Demonstrated
- Sigma rule authoring (YAML, detection logic)
- MITRE ATT&CK framework mapping
- Multi-backend SIEM query compilation (Splunk, Elastic, QRadar)
- Detection engineering best practices
- pytest validation (35 tests)

## References
- [Sigma Spec](https://sigma.readthedocs.io)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

## License
MIT
