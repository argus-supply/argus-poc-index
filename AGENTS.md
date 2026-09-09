# Data repository instructions

This public repository supplies bounded facts and references; it never executes upstream content.
`sync/`, schemas, tests and policy are generated from the source revision in `distribution.json`.
Change the application collector, then regenerate; `python tools/check_distribution.py` rejects drift.
Run `python -m unittest discover -s tests -v` from a clean environment before publishing.
`main` contains code, `data` contains JSONL snapshots, and `control` contains durable budget reservations.
Never publish archives, SQLite, secrets, private assets or execution evidence. Never rewrite history.
Only scheduled/manual publication jobs hold this repository's contents-write token.
