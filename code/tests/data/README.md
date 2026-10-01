# Audit fixtures

Real VM logs belong here locally as `sample_benign.log`; this directory's captured
data is Git-ignored because audit records can contain sensitive details.

No curated benign sample has been collected yet. The mixed real development
capture is under `code/data/captures/`, separate from future normal-use fixtures.
Current synthetic parser cases are generated directly in `tests/test_parser.py`.
Future synthetic parser fixture files should be
clearly labelled and explicitly allowed in `.gitignore` before committing them.
Never treat synthetic fixtures as experimental results.

Phase 6 rule fixtures are synthetic audit records generated inline in
`tests/test_rules.py`; they are not experimental results. The Phase 9 scenario
runner is checked in `tests/test_scenarios.py` without running any privileged action.
