# Security Considerations

LinuxGuard processes security logs that may contain attacker-controlled content and sensitive information. The
following measures protect the tool itself and the data it handles.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Attacker-controlled strings (command lines, file names, user names) rendered in reports or the dashboard (stored XSS) | HTML reports escape every value and carry a restrictive Content-Security-Policy; Markdown reports neutralise table separators, code fences and HTML; the dashboard never renders event data as HTML. |
| Log injection: a local program writing text that looks like an SSH failure to syslog | Syslog patterns are bound to the program name (`sshd`, `sudo`, `su`, …) recorded by the logging daemon, so other programs cannot create authentication events. |
| SQL injection through log content or API parameters | All database access uses parameterised queries; column names are never derived from input. |
| Tampering with the trained model (pickle deserialisation executes code) | Models are saved with a SHA-256 digest and loading refuses a model whose digest is missing or does not match. Model files should be readable and writable by root only. |
| Prompt injection through evidence sent to a language model | Evidence is wrapped in an `<evidence>` block declared as untrusted data, the system prompt forbids following instructions inside it, and model output is display-only: it never drives detection or executes commands. |
| Disclosure of sensitive data to a cloud model provider | Cloud mode is disabled by default, requires explicit consent for every use (or a deliberate configuration change), shows the payload before sending, limits evidence to 20 events, replaces users, hosts, IP addresses, e-mail addresses and home directories with consistent pseudonyms and removes passwords, tokens, bearer credentials, credentials in URLs and long secrets. Pseudonyms are mapped back locally after the response arrives. |
| Unauthorised access to alerts through the API or dashboard | Both bind to `127.0.0.1` by default; the API supports an API key compared in constant time. |
| Exposure of the evidence database | The database file is created with mode `0600`; the systemd unit uses `UMask=0077`. |
| Attacker disabling monitoring | Audit rule removal, disabling auditing, stopping `auditd` and tampering with log files are detected by LG-DEF-001 and LG-DEF-002. An attacker with root can still stop LinuxGuard; forwarding alerts to a separate host is future work. |

## Service hardening

The systemd unit runs with a minimal capability bounding set (`CAP_DAC_READ_SEARCH` to read protected logs and
`CAP_SYS_PTRACE` to resolve `/proc/<pid>/exe`), `NoNewPrivileges`, `ProtectSystem=strict`, read-only home
directories, a private `/tmp`, kernel tunable and module protection, and write access only to `/var/lib/linuxguard`.

## Responsible testing

The lab scripts only perform authorised, reversible actions on localhost inside a dedicated virtual machine. No
malware or exploit code is used. Do not run them on shared or production systems.
