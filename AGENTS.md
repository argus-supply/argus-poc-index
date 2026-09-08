# Repository instructions

This is a standalone ARGUS data supplier, not an application runtime or an execution service.

- Configure sources in `sources.json`; keep record and snapshot formats versioned.
- Persist records and source checkpoints together. A failed source must roll back its changes.
- Never execute upstream scripts, exploits, templates or Git hooks.
- API credentials are Actions Secrets (`VULNCHECK_API_KEY`, `VULNERS_API_KEY`), never files or release assets.
- Retain upstream provenance and license/attribution information. These private supply releases do not grant permission to redistribute data publicly.
- Run `python -m unittest discover -s tests -v` before committing behavioral changes.
- Preserve immutable published releases. Publish uploads as a draft and promote only after verification.
- ARGUS activation remains owned by its existing Catalog and operator workflow.
- Use Conventional Commit subjects.
