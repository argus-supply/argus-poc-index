# argus-poc-index

Public ARGUS metadata, maintained independently by GitHub Actions. No runtime, full corpus Release, exploit code or private asset data is distributed.

Install fixed dependencies with `python -m pip install -r requirements.txt`, then run `python tools/check_distribution.py` and `python -m unittest discover -s tests -v`.

The `data` branch is an atomic manifest plus deterministic UTF-8 JSONL shards; clients resolve its commit once and verify exact byte counts and SHA-256. Source `partial`/`failed` states and coverage gaps are authoritative. Empty results do not establish safety. Full source terms and attribution are in `sources.json`.

The control branch reserves daily HTTP bytes before upstream access and measured compressed Git object costs before data/code push. Initialization storage is separately reported; the regular 1 MiB/day allowance begins only after the complete baseline. All phases and branches still count toward cumulative history. Crashed reservations remain charged for the UTC day. Never reset the ledger to bypass limits. Resume through `gh workflow run sync.yml --repo argus-supply/argus-poc-index` and inspect the run summary and seven-day diagnostic artifact. A partial source makes the workflow fail visibly after publishing completed units and retaining valid old data.

Baseline collection starts with seven days and remains partial until 30-day coverage is established. Requests, wire bytes, record/shard/tree size and history growth are bounded by `policy.json`. Cron enabled: true. Runtime acceptance, real schedules and 24-hour costs are recorded separately in the ARGUS implementation report.

Generated code provenance: `df182b2acb39b9c35a3f0a8dbb4f55dfae43b148`. Verify with `python tools/check_distribution.py`; edit the application source and regenerate.
