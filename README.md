# grokcli-2api

把 **Grok OIDC 登录态** 转成 **OpenAI / Anthropic 兼容 API**，并附带 Web 管理台：多 API Key、多账号轮询、设备码 / 导入 / 协议注册。

**当前版本：v1.9.19（高并发 hybrid）**

[![GHCR](https://img.shields.io/badge/ghcr.io-HM2899%2Fgrokcli--2api-blue)](https://github.com/HM2899/grokcli-2api/pkgs/container/grokcli-2api)

- **独立运行**：不依赖本地 Grok CLI / 浏览器 OAuth
- **Hybrid 存储（默认强制）**：PostgreSQL 持久 + Redis 热状态 + 多 Worker
- **协议注册**：内置 `grok-build-auth`（纯 HTTP，无需 Chromium）
- **中继友好**：兼容 new-api / sub2api / Claude Code 工具流
- **大账号池**：Token 自动续期、模型健康探测、冷却状态落库

---

## 架构

```
客户端 (OpenAI / Anthropic SDK · new-api · Claude Code)
        │  /v1/chat/completions  ·  /v1/messages
        ▼
  grokcli-2api  (FastAPI · multi-worker)
        │  管理台 /admin
        │  账号轮询 · 失败切换 · 对话粘性
        │  PostgreSQL（账号 / Key / 设置 / 冷却状态）
        │  Redis（粘性 / 计数 / 锁 / 会话）
        ▼
  cli-chat-proxy.grok.com
```

> `data/*.json` **仅作旧版迁移源或可选镜像**，运行时权威数据在 PostgreSQL。

---

## 功能一览

| 功能 | 说明 |
|------|------|
| OpenAI 兼容 | `/v1/models` · `/v1/chat/completions` · SSE |
| Anthropic 兼容 | `/v1/messages` · tools / tool_use · `count_tokens` |
| 管理台 | 账号、Key、协议注册、测活、续期、日志、设置 |
| 多账号轮询 | `round_robin` / `least_used` / `random` |
| 冷却状态 | free-usage 等写入 DB；测活成功恢复为「冷却中」→ 正常 |
| Token 续期 | 后台 leader 维护；支持单选/多选立即续期 |
| 模型探测 | 单账号 / 多选批量 / 全量；状态实时回填 |
| 协议注册 | MoeMail + YesCaptcha，多线程批量；入池后延迟测活 |

---

## 快速开始

### 方式 A：Docker Compose（源码构建）

```bash
git clone https://github.com/HM2899/grokcli-2api.git
cd grokcli-2api
cp .env.example .env
# 编辑 .env：GROK2API_ADMIN_PASSWORD、可选注册相关 Key

docker compose up -d --build
curl -fsS http://127.0.0.1:3000/health
```

浏览器打开：`http://127.0.0.1:3000/admin`

### 方式 B：GHCR 镜像

```bash
docker pull ghcr.io/HM2899/grokcli-2api:1.9.19
```

`docker-compose.yml` 中将 app 服务改为：

```yaml
services:
  grokcli-2api:
    image: ghcr.io/HM2899/grokcli-2api:1.9.19
    # 仍需 redis + postgres 服务，或外部 REDIS_URL / DATABASE_URL
```

若包为 private，需先：

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
```

### 必要环境变量

| 变量 | 说明 |
|------|------|
| `GROK2API_ADMIN_PASSWORD` | 管理台密码（首次） |
| `GROK2API_STORE_BACKEND=hybrid` | 生产模式 |
| `GROK2API_REQUIRE_SHARED_STORES=1` | Redis/PG 不可用则拒绝启动 |
| `REDIS_URL` | 如 `redis://redis:6379/0` |
| `DATABASE_URL` | 如 `postgresql://grok2api:grok2api@postgres:5432/grok2api` |
| `GROK2API_WORKERS` | 建议 ≥2（按 CPU） |

完整模板见 [`.env.example`](./.env.example)。**生产请修改默认数据库密码。**

---

## 从旧版（JSON 文件）升级

详见 **[docs/UPGRADE.md](./docs/UPGRADE.md)**。

```bash
# 备份 data/ 后
chmod +x scripts/upgrade_from_file_backend.sh
./scripts/upgrade_from_file_backend.sh --data-dir ./data

# 或
docker compose up -d redis postgres
docker compose run --rm \
  -e DATABASE_URL=postgresql://grok2api:grok2api@postgres:5432/grok2api \
  grokcli-2api \
  python migrate_json_to_pg.py --data-dir /app/data --merge-pool
```

迁移内容：`auth.json` / `keys.json` / `settings.json`（含账号池状态）→ PostgreSQL。  
不迁移：Redis 热状态、管理台登录会话。

已是 hybrid 时，拉新镜像即可；表结构由 `store/pg.py` 启动时幂等升级。

---

## 客户端接入

### OpenAI 兼容

```bash
export OPENAI_BASE_URL=http://127.0.0.1:3000/v1
export OPENAI_API_KEY=你的管理台API_Key

curl "$OPENAI_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","messages":[{"role":"user","content":"hi"}]}'
```

### Anthropic 兼容

```bash
curl http://127.0.0.1:3000/v1/messages \
  -H "x-api-key: 你的管理台API_Key" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}'
```

Claude Code / Cursor / Cherry Studio：Base URL 填服务地址（通常带 `/v1`），Key 用管理台创建的 API Key。

---

## 管理台

| 页面 | 用途 |
|------|------|
| 概览 | 池规模、续期/探测状态 |
| 账号 / 轮询 | 导入、设备码、协议注册、测活、续期 |
| API Keys | 客户端密钥 |
| 日志 | 登录、账号、Key、探测、设置等记录 |
| 设置 | 轮询与冷却策略等 |

协议注册依赖 **MoeMail** + **YesCaptcha**（环境变量或管理台配置，存 PG）。  
邮箱有效期：1 小时 / 1 天 / 3 天 / 永久。  
新注册账号入池后默认 **延迟 30s** 再自动测活（`GROK2API_REG_PROBE_DELAY_SEC`）。

---

## 运维

```bash
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:3000/metrics | head
docker compose logs -f grokcli-2api
```

- 仅 **leader** worker 跑 Token 续期与模型健康任务（Redis 选主）
- 备份重点：**PostgreSQL**；Redis 可丢
- 本地低停机重建：`./docker-rebuild.sh`

### 发布镜像（GHCR）

```bash
# app.py 中 APP_VERSION 必须与 tag 一致
git tag v1.9.19
git push origin v1.9.19
```

成功后可拉取：

- `ghcr.io/HM2899/grokcli-2api:1.9.19`
- `ghcr.io/HM2899/grokcli-2api:latest`（tag 发布时）
- `ghcr.io/HM2899/grokcli-2api:edge`（main 分支）

---

## 目录提示

```
app.py / admin_routes.py              # API 与管理路由
store/                                # Redis + PostgreSQL 后端
migrate_json_to_pg.py                 # JSON → PG
scripts/upgrade_from_file_backend.sh  # 旧版升级包装
scripts/build_admin_assets.py         # 管理台静态资源打包
docs/UPGRADE.md                       # 升级说明
static/                               # 管理台前端
grok-build-auth/                      # 协议注册引擎（vendored）
docker-compose.yml                    # redis + postgres + app
.github/workflows/docker-publish.yml  # GHCR 多架构构建
```

---

## 安全与免责

- 勿将 `.env`、`data/`、真实 Token 提交到 Git
- 生产务必修改 Postgres 密码与管理员密码
- 协议注册与账号自动化请遵守 xAI 服务条款与当地法律；本项目仅供自用/研究集成

---

## 版本

- **v1.9.19**（当前）：高并发 **hybrid** 默认强制（PostgreSQL + Redis + multi-worker）；管理台静态资源拆分；GHCR 多架构发布；JSON→PG 迁移与升级文档；sub2api / Claude Code 单 tool 出站与 inter-tool gap；移除仓库内临时测试脚本
- **v1.8.x**：文件后端时代（`data/*.json` 权威存储）；工具流 / history compact 等修复
- 更早变更见 [GitHub Releases](https://github.com/HM2899/grokcli-2api/releases)

> 镜像 tag 与 `app.py` 中 `APP_VERSION` 一致（当前 **1.9.19**）。推 `main` 会打 `edge` 与版本号；打 `v1.9.19` tag 会额外发布 `latest`。

## License

见 [LICENSE](./LICENSE)。
