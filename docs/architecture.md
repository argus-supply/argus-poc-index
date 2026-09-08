# Independent ARGUS data supply / 独立数据供应

## Ownership / 职责

Daily GitHub Actions jobs fetch upstream data independently of the ARGUS process. The service consumes a published version later; this repository does not change the current application's importer or activation policy.

每日 GitHub Actions 独立采集。ARGUS 停机不影响采集；现有程序的导入适配和激活策略不在本仓库中更改。三个仓库的数据格式一致，采集源配置不同。

## Persistence / 持久化

SQLite holds source-scoped normalized records (including raw provenance), per-file Git blob IDs / object ETags, API cursors and refresh ledgers. Each source runs inside a savepoint. Failures roll back that source and preserve the previous data and checkpoint; successful sources can still publish. State only becomes durable for the next runner when the complete release is promoted from draft. Ephemeral runner directories and caches are not authoritative.

SQLite 同时保存源记录、Git blob ID / 对象 ETag、API 游标和复查账本。单源失败回滚；数据包完整上传并发布后，进度才对下一次 Runner 生效。不依赖 Actions cache 保存唯一副本。

## Publication / 发布

`manifest.json` names the schema, producer repository, version, exact delta base, source status/revision and SHA-256 / byte length of every asset. `state.sqlite.gz` is the producer restart snapshot. `records.jsonl.gz` is a complete consumer-facing metadata snapshot. `delta.jsonl.gz` carries source/id keyed upserts and deletions relative to `base_version`; a client missing that base must use the full snapshot. `resources.tar.gz`, when present, contains the complete source-namespaced resource tree; binary resource deltas are not provided in v1.

消费者按清单验证校验和。增量包只适用于完全匹配的基础版本；离线跨过多个版本时可直接导入完整快照。资源包始终为全量。源级记录保留各自原始字段和别名，v1 不跨源物理合并公告；消费者可以按 CVE/别名关联。

Sources can report `ok`, `partial`, `skipped`, or `failed`. A partial Git backfill records both the observed upstream revision and the last completely imported revision. Newest CVE paths are processed first. A release can contain independently fresh and stale sources; clients must examine each source status rather than treating publication time as universal freshness.

源状态有成功、分批补采中、缺少凭据跳过、失败四种。发布时刻不代表每个源都已更新到该时刻。初次全量需多轮完成，未完成进度明确写入清单。

## Limits / 边界

- OSV keeps CVE aliases, including CVE-bearing entries, unlike ARGUS's previous CVE-less-only importer. Missing objects are not automatically treated as withdrawn; explicit upstream withdrawal fields are retained. A change is revisited on the next full ecosystem loop.
- Chaitin reserves a quarter of its budget for due detail refreshes; remaining capacity discovers unseen advisories. API disappearance is not interpreted as deletion.
- Vulners exploit search is publication-window based, with a two-day overlap. Older modified bulletins are not guaranteed to be discovered; expand `lookback_days` on a fresh bootstrap or deliberately reset that source checkpoint for a historical rescan. API history starts with the configured lookback, not the entire paid database.
- A stored VulnCheck cursor can expire upstream. Such a failure retains the old data; an operator can clear only its pending cursor/window in an audited state migration and restart from its last completed watermark.
- Template validation is YAML structure / JSON syntax validation. Resources are not executed, signatures are not reissued, and no engine compatibility or activation approval is implied. Paths remain source-namespaced; consumers must handle template ID collisions explicitly.
- Sources retain their own licenses and terms. These repositories start private. Public redistribution and integration into the existing `argus-rules` catalog require their existing review process.
- GitHub schedules can be delayed; daily collection is a target cadence, not a delivery SLA. No-change healthy polls do not create a redundant release. Workflow summaries report the poll outcome.
- Each compressed asset is capped below GitHub's 2 GiB limit. Beyond that scale, shard assets or migrate data storage to an object store.

OSV 的缺失对象不等于已撤回；更新时效受完整遍历周期影响。付费 API 的首次采集受回看窗口与预算约束。模板结构检查不等于引擎验证。当前源保留各自许可证，私有发布不会赋予公开再分发权。GitHub 定时任务可能延迟。

## Verification / 验证

Keyless tests exercise per-source rollback, snapshot restore/checksums, delta replay including deletions, Git backfill and removal propagation through a real local Git repository, bounded OSV pagination, API continuation, and source parsers. Initial live smoke runs should use a small `workflow_dispatch` limit before a complete backfill.

无 Key 测试覆盖事务回滚、快照恢复、增量重放、真实本地 Git 增量删除、OSV 分页续采和 API 游标；小预算 Actions 实跑用于验证外部服务与发布链路。
