# ARGUS PoC / Exploit 索引

独立于 ARGUS 应用运行的每日索引采集。每日北京时间 **03:43** 运行，也支持 Actions → **Sync data** → **Run workflow** 手动触发。

| 来源 | 采集方式 | 默认单轮预算 |
| --- | --- | --- |
| PoC-in-GitHub | nomi-sec 项目 Git 索引，比较文件 blob ID，逐 CVE 更新与删除 | 10,000 文件 |
| Exploit-DB | 官方 GitLab，稀疏读取 `files_exploits.csv`，按 Exploit ID / CVE 比较完整索引 | 1 CSV |
| VulnCheck | `exploits` API，固定修改时间窗口、持久分页 cursor | 1,000 文档 |
| Vulners | exploit 公告搜索，固定发布时间窗口、持久分页 offset | 200 公告 |

Actions Secrets：`VULNCHECK_API_KEY`、`VULNERS_API_KEY`。未配置的源跳过；余额不足或 API 故障会保留旧数据、报告失败。API 初次默认回看 30 天，完成后使用上次完成时间加两天重叠窗口，不代表全量历史已获取。

只发布 PoC 元数据、链接和 CVE 关联，不发布或执行利用代码。Exploit-DB 的稀疏 checkout 只选择 CSV 和许可文件。相同来源内去重，不丢失不同来源的证据；消费者可按规范化链接聚合展示。

## 发布与恢复

Releases 提供 `manifest.json`、`records.jsonl.gz`、`delta.jsonl.gz`、`state.sqlite.gz`，以及存在上游许可文件时的 `resources.tar.gz`。记录使用来源 + `CVE:upstream_id` 标识，包含标题、URL、来源原始元数据与可用时间字段。

核对清单中的 SHA-256 和文件大小后导入。增量中的 `upsert` / `delete` 仅相对 `base_version` 有效；版本不匹配时使用完整快照。Git 来源补采中显示 `partial`，每个来源独立显示更新时间和错误。

当前 ARGUS 应用尚未对接新发布包；本仓库不改变其验证执行或资源激活流程。

## 本地验证

需要 Python 3.12、Git，以及用于发布/恢复的 GitHub CLI。

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/sync.py --source poc-in-github --limit 10 --repository OWNER/argus-poc-index
```

`.work/` 与 `dist/` 不提交 Git。初始为私有仓库，源数据遵循上游各自的许可和服务条款。

边界：Vulners 按发布时间查询，旧公告的修改不保证被发现；VulnCheck 服务端 cursor 过期会保留旧数据并报错，需要受控重置该源 pending cursor/window 后从已完成时间恢复。完整说明见 [architecture.md](docs/architecture.md)。
