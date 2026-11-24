# Detection Rules

The default rules live in [`src/linuxguard/resources/rules/default.yaml`](../src/linuxguard/resources/rules/default.yaml).
A custom rule file can be configured with `detection.rules_path` or the `LINUXGUARD_RULES` environment variable.

## Default rules

| ID | Name | Type | Severity | ATT&CK |
| --- | --- | --- | --- | --- |
| LG-AUTH-001 | Remote authentication brute force | threshold: 5 failures / 60 s per address | high | T1110.001 |
| LG-AUTH-002 | Password spraying across accounts | threshold: 4 distinct users / 300 s per address | high | T1110.003 |
| LG-AUTH-003 | Successful login after repeated failures | sequence: ≥3 failures then success / 600 s | critical | T1078 |
| LG-AUTH-004 | Repeated local privilege authentication failures | threshold: 3 / 120 s per user | medium | T1110 |
| LG-CRED-001 | Credential store accessed by unexpected program | single | high | T1003.008 |
| LG-PERS-001 | Account or sudo configuration modified directly | single | high | T1098 |
| LG-ACCT-001 | New local account created | single | medium | T1136.001 |
| LG-ACCT-002 | Account added to privileged group | single | high | T1098 |
| LG-EXEC-001 | Execution from temporary directory | single | high | T1204.002 |
| LG-EXEC-002 | Reverse shell command pattern | single | critical | T1059.004 |
| LG-EXEC-003 | Remote content piped into an interpreter | single | high | T1105 |
| LG-EXEC-004 | Shell spawned by a network service | single | critical | T1505.003 |
| LG-PERS-002 | Scheduled task created or modified | single | medium | T1053.003 |
| LG-PERS-003 | Systemd unit created or modified | single | medium | T1543.002 |
| LG-PERS-004 | SSH authorized keys modified | single | medium | T1098.004 |
| LG-PRIV-001 | Setuid or setgid permission set | single | high | T1548.001 |
| LG-PRIV-002 | Root shell obtained through sudo | single | medium | T1548.003 |
| LG-PRIV-003 | Sudo use denied | single | medium | T1548.003 |
| LG-KERN-001 | Kernel module loaded | single | high | T1547.006 |
| LG-DEF-001 | Audit subsystem tampering | single | critical | T1562.012 |
| LG-DEF-002 | System log tampering | single | high | T1070.002 |
| LG-DISC-001 | Burst of discovery commands | threshold: 6 distinct commands / 60 s per session | low | T1082 |
| LG-NET-001 | Outbound connection from shell or netcat | single | high | T1095 |

## Rule language

```yaml
rules:
  - id: LG-EXAMPLE-001            # unique identifier
    name: Example rule
    description: What the rule detects.
    severity: high                # low | medium | high | critical
    tactic: Credential Access     # optional ATT&CK tactic
    technique: T1110              # optional ATT&CK technique
    match:                        # all conditions must hold (exactly one of match or sequence)
      category: authentication
      outcome: failure
      src_ip: {exists: true}
    exclude:                      # optional list of matchers that suppress a match
      - src_ip: {prefix: "10."}
    threshold:                    # optional aggregation
      count: 5
      window_seconds: 60
      group_by: [src_ip]
      distinct: user              # count distinct values instead of events
    suppress_seconds: 60          # single-event rules: repeat suppression per correlation id (0 disables)
    explanation: >-               # template used for standard explanations
      {src_ip} failed {count} times against {host}.
    response:                     # recommended actions in reports
      - Block the address.
```

Sequence rules replace `match`:

```yaml
    sequence:
      within_seconds: 600
      group_by: [src_ip]
      steps:
        - match: {category: authentication, outcome: failure}
          min_count: 3
        - match: {category: [authentication, login], outcome: success}
```

### Conditions

A scalar value means equality and a list means membership. Mappings select operators:

| Operator | Meaning |
| --- | --- |
| `equals`, `not_equals` | exact comparison |
| `in`, `not_in` | membership |
| `prefix`, `not_prefix`, `suffix`, `contains` | string tests (value or list of values) |
| `regex` | Python regular expression search |
| `exists` | field is present and non-empty (`true`) or missing (`false`) |
| `gte`, `lte` | numeric comparison |
| `mode_any` | any of the octal permission bits is set, for example `"6000"` for setuid/setgid |

`any_of` combines alternative matchers: `any_of: [{action: remove_rule}, {details.audit_enabled: "0"}]`.
Fields are the attributes of `SecurityEvent`; additional attributes are available as `details.<name>`.
Rule files are validated when they are loaded: unknown keys, unknown fields, invalid operators, invalid regular
expressions and duplicate identifiers are rejected.

### Template placeholders

`{user}`, `{src_ip}`, `{target_path}`, `{target_user}`, `{executable}`, `{parent_executable}`, `{process_name}`,
`{command_line}`, `{dest_ip}`, `{dest_port}`, `{action}`, `{group}`, `{host}`, `{entity}`, `{count}`,
`{distinct_values}`, `{first_seen}` and `{last_seen}`. Missing values render as `unknown`.
