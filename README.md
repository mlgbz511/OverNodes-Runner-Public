# OverNodes-Runner-Public

公开 GitHub Actions 测速执行端，生成并推送节点到私有订阅仓 `mlgbz511/OverNodes`。

## 必需 Secrets

| Secret | 用途 |
|---|---|
| `DISPATCH_PAT` | 推送 `mlgbz511/OverNodes` 的 PAT |
| `PROBE_DOMAIN` | edgetunnel 业务域名探针 |
| `CF_API_TOKEN` / `CF_ZONE_ID` / `CF_DNS_NAME` | 可选 DDNS |

## 运行

- 手动：Actions → `Cloudflare Private Speedtest Runner` → Run workflow
- 定时：由 `worker-cron-trigger` 调度（目标 `mlgbz511/OverNodes-Runner-Public`）
- 产物：`artifacts/<run_id>/` 仅本地校验，不上传 Actions artifact，避免公开仓泄露节点

## 安全边界

- 公开仓不含任何明文 token/账号
- `private/chain-auth.json` 永不进入 Actions artifact
- 发布前强制 Schema 校验与秘密扫描，失败即停止
