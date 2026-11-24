# LinuxGuard Evaluation Results

Generated 2026-11-24 19:35 UTC. Seeds: 1, 2, 3, 4, 5. Values are mean ± standard deviation across seeds.

- Test events per seed: 4400 ± 112
- Labelled cases per seed: 93.6 ± 0.5
- Baseline training windows per seed: 2780 ± 153
- Parsing throughput: 3279 ± 71 events/s
- Baseline training time: 2.15 ± 0.06 s

## Detection Performance

| Configuration | Alerts | Alert precision | Case precision | Recall | False-positive rate | F1 | Mean detection delay (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline A: rules only | 44.6 ± 0.5 | 0.892 ± 0.009 | 0.876 ± 0.010 | 0.708 ± 0.000 | 0.105 ± 0.010 | 0.783 ± 0.004 | 10.5 ± 0.6 |
| Baseline B: rules + anomaly detector | 62.8 ± 2.4 | 0.841 ± 0.030 | 0.824 ± 0.017 | 0.858 ± 0.023 | 0.193 ± 0.019 | 0.841 ± 0.019 | 17.7 ± 2.2 |
| Rules + Isolation Forest without range guard | 54.8 ± 2.2 | 0.817 ± 0.039 | 0.808 ± 0.021 | 0.775 ± 0.034 | 0.193 ± 0.019 | 0.791 ± 0.028 | 15.1 ± 3.3 |
| Anomaly detector only (reference) | 18.2 ± 2.5 | 0.715 ± 0.091 | 0.707 ± 0.060 | 0.212 ± 0.031 | 0.092 ± 0.018 | 0.326 ± 0.042 | 49.2 ± 6.8 |
| Isolation Forest only, no guard (reference) | 10.2 ± 2.3 | 0.462 ± 0.238 | 0.429 ± 0.198 | 0.075 ± 0.048 | 0.092 ± 0.018 | 0.127 ± 0.078 | 57.6 ± 17.5 |
| Rules + anomaly detector (q=0.990) | 75.0 ± 3.1 | 0.809 ± 0.027 | 0.787 ± 0.013 | 0.875 ± 0.000 | 0.250 ± 0.018 | 0.828 ± 0.007 | 17.5 ± 0.6 |
| Rules + anomaly detector (q=0.999) | 55.4 ± 2.5 | 0.877 ± 0.007 | 0.851 ± 0.007 | 0.808 ± 0.017 | 0.149 ± 0.011 | 0.829 ± 0.009 | 14.4 ± 0.9 |

Recall and false-positive rate are measured per labelled case. A benign case counts as a false positive only when an alert whose evidence contains no malicious activity touches it. Alert precision is the fraction of alerts whose evidence contains malicious activity.

## Resource Consumption

| Configuration | Detection time (s) | CPU time (s) | Time per event (ms) | Throughput (events/s) | Peak traced memory (MB) | Database size (KB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline A: rules only | 0.37 ± 0.02 | 0.37 ± 0.01 | 0.084 ± 0.005 | 11883 ± 703 | 0.0 ± 0.0 | 7036 ± 150 |
| Baseline B: rules + anomaly detector | 13.04 ± 0.53 | 12.86 ± 0.48 | 2.965 ± 0.118 | 338 ± 13 | 3.9 ± 0.9 | 7241 ± 144 |
| Rules + Isolation Forest without range guard | 14.40 ± 2.83 | 14.18 ± 2.78 | 3.271 ± 0.635 | 313 ± 50 | 3.8 ± 0.7 | 7096 ± 152 |
| Anomaly detector only (reference) | 14.07 ± 3.21 | 13.80 ± 3.12 | 3.191 ± 0.687 | 324 ± 64 | 4.4 ± 0.1 | 7208 ± 144 |
| Isolation Forest only, no guard (reference) | 13.86 ± 3.28 | 13.53 ± 3.10 | 3.139 ± 0.672 | 329 ± 62 | 4.4 ± 0.1 | 7069 ± 148 |
| Rules + anomaly detector (q=0.990) | 14.39 ± 3.58 | 14.15 ± 3.46 | 3.258 ± 0.726 | 317 ± 55 | 3.9 ± 0.8 | 7281 ± 146 |
| Rules + anomaly detector (q=0.999) | 14.09 ± 2.48 | 13.83 ± 2.29 | 3.195 ± 0.492 | 318 ± 42 | 3.6 ± 0.9 | 7203 ± 140 |

## Detection by Scenario

Counts are detected cases / total cases summed over all seeds. For benign scenarios the count is the number of falsely flagged cases.

| Scenario | Type | Rule coverage | Baseline A: rules only | Baseline B: rules + anomaly detector | Anomaly detector only (reference) | Isolation Forest only, no guard (reference) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| audit_tampering | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| backdoor_account | malicious | yes | 10/10 | 10/10 | 2/10 | 2/10 |
| brute_force_success | malicious | yes | 10/10 | 10/10 | 3/10 | 0/10 |
| credential_file_access | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| credential_hunting | malicious | no | 0/10 | 0/10 | 0/10 | 0/10 |
| cron_persistence | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| cryptominer | malicious | no | 0/10 | 6/10 | 6/10 | 6/10 |
| data_exfiltration | malicious | no | 0/10 | 10/10 | 10/10 | 9/10 |
| discovery_burst | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| download_and_execute | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| dropped_implant_beacon | malicious | no | 0/10 | 0/10 | 0/10 | 0/10 |
| internal_network_scan | malicious | no | 0/10 | 10/10 | 10/10 | 1/10 |
| kernel_module_load | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| log_tampering | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| mass_file_encryption | malicious | no | 0/10 | 10/10 | 10/10 | 0/10 |
| off_hours_privileged_activity | malicious | no | 0/10 | 0/10 | 0/10 | 0/10 |
| password_spray | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| reverse_shell | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| setuid_backdoor | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| ssh_brute_force | malicious | yes | 10/10 | 10/10 | 10/10 | 0/10 |
| ssh_key_persistence | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| sudoers_modification | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| temporary_directory_execution | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| web_shell | malicious | yes | 10/10 | 10/10 | 0/10 | 0/10 |
| administrator_account_creation | benign | - | 10/10 | 10/10 | 0/10 | 0/10 |
| administrator_troubleshooting | benign | - | 10/10 | 10/10 | 0/10 | 0/10 |
| backup_job | benign | - | 0/10 | 0/10 | 0/10 | 0/10 |
| developer_build | benign | - | 0/10 | 0/10 | 0/10 | 0/10 |
| password_typo | benign | - | 2/10 | 2/10 | 0/10 | 0/10 |
| scheduled_jobs | benign | - | 0/120 | 0/120 | 0/120 | 0/120 |
| system_update | benign | - | 0/10 | 9/10 | 9/10 | 9/10 |
| work_session | benign | - | 2/48 | 13/48 | 12/48 | 12/48 |
