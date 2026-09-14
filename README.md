# CF-Workers-WebSSH（访问密码 + 跨设备同步魔改版）

此项目是秋名山魔改版。

一个运行在 Cloudflare Workers 上的原生 WebSSH 终端。浏览器通过 HTTPS/WebSocket 连接 Worker，Worker 使用 Cloudflare TCP Sockets 直接连接公网 SSH 服务器，并在边缘运行时内完成 SSH 2.0 握手、主机密钥校验、用户认证和交互式 PTY 会话。

本仓库是基于开源项目 [cmliu/CF-Workers-WebSSH](https://github.com/cmliu/CF-Workers-WebSSH) 的魔改版本，遵循 Apache License 2.0。原版运行时无 SSH 第三方依赖，前端、会话网关、SSH 客户端实现和静态资源均由同一个 Worker 部署提供。

> [!IMPORTANT]
> 本魔改版新增了 `ACCESS_PASSWORD` 访问密码与 `CONNECTIONS_KV` 跨设备同步。公网部署前请务必：
> 1. 设置强 `ACCESS_PASSWORD`；
> 2. 创建并绑定 `CONNECTIONS_KV`；
> 3. 使用 Cloudflare Access、WAF 与限流策略保护页面和 API；
> 4. 关闭不需要的 `workers.dev` 公网入口。
>
> `ACCESS_PASSWORD` 同时作为跨设备同步数据的加密口令。它一旦泄露，攻击者不仅可能进入 WebSSH，还可能解密 KV 中的连接列表密文。请使用高强度独立密码。

## 魔改亮点

### 1. 访问密码门禁

原版允许匿名创建网关会话，本魔改版增加了 `ACCESS_PASSWORD`：

- `/api/session` 会校验请求体中的 `password` 是否等于 `ACCESS_PASSWORD`；
- `/api/connections` 会校验请求头 `X-Access-Password`；
- 前端首次加载会提示输入访问密码，并暂存在 `sessionStorage`；
- 如果 `/api/session` 返回 `401`，前端会清除缓存并要求重新输入；
- 密码比较使用常量时间比较，降低时序侧信道风险；
- CORS 预检允许 `X-Access-Password` 请求头。

未配置 `ACCESS_PASSWORD` 时，原版匿名会话逻辑仍可工作，但 `/api/connections` 会拒绝服务。公网部署不建议保持未配置状态。

### 2. 跨设备连接列表加密同步

新增 `CONNECTIONS_KV` 与 `/api/connections`，用于在多台设备之间同步“历史连接列表”：

- 前端新增 `frontend/src/kv-sync.ts`；
- 使用 `ACCESS_PASSWORD` 通过 PBKDF2 派生 AES-256-GCM 密钥；
- PBKDF2 参数：`SHA-256`、盐 `cf-workers-webssh/kv-sync/salt/v1`、迭代 `210000`；
- 连接列表在浏览器端加密后，才发送到 Worker；
- Worker 只把密文写入 Cloudflare KV，不保存明文连接列表；
- 密文格式为 `v1.<iv>.<ciphertext>`；
- 页面加载时合并“本地 Local Storage + 远端 KV 解密结果”，并尽力把合并结果推送回 KV；
- 新增、删除、保存连接、更新主机指纹时，都会 best-effort 推送同步；
- 同步失败不会阻塞本地使用，Local Storage 仍是本地事实源。

> 注意：`ACCESS_PASSWORD` 既是访问密码，也是同步加密口令。修改密码后，旧 KV 密文通常无法解密，前端会忽略旧远端数据并用新密码重新推送当前本地列表。

### 3. 保留原版完整能力

本魔改版没有移除原版核心功能：

- Cloudflare Workers 原生部署，Durable Objects 隔离每个 SSH 会话；
- xterm.js 响应式终端，支持桌面端和移动端、自动缩放、全屏和会话日志；
- 内置 SFTP 文件管理；
- 内置实时进程管理；
- 支持 SSH password、单密码提示 keyboard-interactive、Ed25519 / RSA / ECDSA 未加密 OpenSSH 私钥；
- 首次连接显示主机 SHA-256 指纹，确认后才发送凭据；
- 历史密码使用 AES-256-GCM 加密，密钥保存在 IndexedDB；
- 支持 UTF-8、GB18030、Big5、初始命令和分享链接；
- 一次性会话票据、同源检查、HTTPS 强制、安全响应头和公网目标校验。

## 与原版的主要差异

| 项目 | 原版 | 本魔改版 |
| --- | --- | --- |
| 访问控制 | 匿名创建会话 | 支持 `ACCESS_PASSWORD` 访问密码 |
| 会话票据接口 | `POST /api/session` 空对象 | 可携带 `{ "password": "..." }` 校验 |
| 连接列表同步 | 仅浏览器本地 | 新增 KV + 客户端 AES-GCM 加密同步 |
| 新增 API | 无 | `GET/POST /api/connections` |
| 新增绑定 | 无 | `CONNECTIONS_KV` |
| CORS | 仅 `Content-Type` | 额外允许 `X-Access-Password` |
| 前端新增模块 | 无 | `frontend/src/kv-sync.ts` |
| 部署配置 | `CONNECT_TIMEOUT_MS` | 额外需要 `ACCESS_PASSWORD`、`CONNECTIONS_KV` |

## 工作原理

```text
浏览器（xterm.js）
    │  HTTPS：申请一次性会话票据，可携带访问密码
    │  WSS：终端输入、输出和控制消息；独立 SFTP / 进程通道
    │  HTTPS：/api/connections 读写加密后的连接列表密文
    ▼
Cloudflare Worker
    │  访问密码校验、同源检查、会话票据、静态资源、KV 同步接口
    ▼
每会话 Durable Object
    │  消耗一次性票据、校验目标地址、运行 SSH 2.0 客户端
    │  Cloudflare TCP Socket
    ▼
公网 SSH 服务器

跨设备同步：
浏览器 Web Crypto（PBKDF2 → AES-256-GCM）
    │  明文连接列表只在浏览器内出现
    ▼
/api/connections（X-Access-Password 校验）
    ▼
Cloudflare KV：只保存 `v1.iv.ciphertext` 密文
```

## 支持范围

| 类别 | 当前支持 |
| --- | --- |
| SSH 协议 | SSH 2.0 交互式 Shell、PTY、SFTP v3、窗口尺寸同步、Keepalive |
| 用户认证 | Password、单密码提示 keyboard-interactive、OpenSSH Ed25519、RSA、ECDSA P-256/P-384/P-521 私钥 |
| 密钥交换 | `curve25519-sha256`、`ecdh-sha2-nistp256` |
| 主机密钥 | Ed25519、ECDSA P-256/P-384/P-521、RSA SHA-2 |
| 加密算法 | AES-128/256-GCM、AES-128/192/256-CTR |
| MAC | HMAC-SHA2-256、HMAC-SHA2-512（AES-GCM 不使用独立 MAC） |
| 终端编码 | UTF-8、GB18030、Big5（取决于浏览器 `TextDecoder` 支持） |
| 连接同步 | 基于 Cloudflare KV，客户端 AES-256-GCM 加密，访问密码派生密钥 |

**限制**：只能连接公网 IP 或解析结果全部为公网地址的域名；不支持出站 TCP 25 端口；不支持加密私钥、PEM/PKCS#8 私钥、SSH Agent、多因素键盘交互认证、SCP、端口转发、ProxyJump、SSH 压缩和会话内 rekey。文件上传与下载单文件限制为 64 MiB，目录删除仅支持空目录。

## 新版本部署教程

### 前置条件

- Cloudflare 账号；
- 已 Fork 本魔改仓库到自己的 GitHub；
- Node.js `>= 22.12.0`；
- Wrangler `>= 4.114.0`；
- 一个 Cloudflare KV Namespace。

### 方式一：Cloudflare Dashboard + GitHub 集成部署

#### 1. Fork 仓库

Fork 本魔改仓库到你自己的 GitHub 账号。

#### 2. 创建 KV Namespace

进入 Cloudflare Dashboard：

```text
Workers 和 Pages → KV → 创建命名空间
```

建议名称：

```text
cf-webssh-connections
```

创建后复制 KV Namespace ID。

#### 3. 修改 `wrangler.toml`

打开仓库中的 `wrangler.toml`，把 `CONNECTIONS_KV` 的 `id` 替换成你自己的 KV Namespace ID：

```toml
[[kv_namespaces]]
binding = "CONNECTIONS_KV"
id = "<你的 KV Namespace ID>"
```

不要直接使用示例中的 ID。

#### 4. 设置 `ACCESS_PASSWORD`

推荐使用 Cloudflare Dashboard 或 Wrangler 设置加密 Secret，不要提交到 Git。

方式 A：Dashboard

```text
Workers 和 Pages → 选择你的 Worker → Settings → Variables and Secrets
→ Add → Secret
Name: ACCESS_PASSWORD
Value: <一个高强度密码>
```

方式 B：Wrangler

```bash
npx wrangler secret put ACCESS_PASSWORD
```

按提示输入密码。

#### 5. 配置构建命令

在 Cloudflare Workers 创建应用时，选择你 Fork 后的仓库，构建命令填写：

```bash
npm run deploy
```

部署平台会读取 `wrangler.toml`，执行 `npm run deploy`，该命令会通过 Wrangler 构建前端并部署 Worker。

#### 6. 部署并验证

部署完成后访问 Worker 域名，应出现访问密码输入提示。

验证接口：

```bash
curl https://<你的域名>/api/health
```

返回类似：

```json
{ "status": "ok", "runtime": "cloudflare-workers", "ssh": true }
```

连接一次 SSH 后，再用另一台设备访问同一站点并输入相同访问密码，历史连接列表应通过 KV 同步。

#### 7. 自定义域名与 Cloudflare Access

绑定自定义域名：

```text
Workers & Pages → 选择 Worker → Settings → Domains & Routes → Add → Custom domain
```

也可在 `wrangler.toml` 中配置：

```toml
routes = [
  { pattern = "ssh.example.com", custom_domain = true }
]
```

确认自定义域名可用后，建议关闭公网 `workers.dev`：

```toml
workers_dev = false
```

然后在 Cloudflare Zero Trust 中为自定义域名创建 Self-hosted Application，只允许指定用户、邮箱域或身份提供商访问。

建议纵深防御：

- 所有可访问域名都受 Access 保护；
- 设置 `workers_dev = false`；
- 使用 WAF 规则限制异常请求；
- 对 `/api/session`、`/api/ssh`、`/api/connections` 配置限流与告警；
- 验证 Access 策略覆盖页面、`/api/session`、`/api/ssh`、`/api/connections`。

### 方式二：本地 Wrangler 部署

```bash
git clone <你的魔改仓库地址>
cd <仓库目录>
npm install
```

创建 KV：

```bash
npx wrangler kv namespace create CONNECTIONS_KV
```

把输出的 ID 填入 `wrangler.toml`。

设置访问密码：

```bash
npx wrangler secret put ACCESS_PASSWORD
```

部署：

```bash
npm run deploy
```

## 本地开发

复制环境变量示例：

```bash
cp .env.example .dev.vars
# Windows: Copy-Item .env.example .dev.vars
```

在 `.dev.vars` 中加入：

```dotenv
CONNECT_TIMEOUT_MS=10000
ACCESS_PASSWORD=你的本地访问密码
```

启动：

```bash
npm run dev
```

默认访问：

```text
http://localhost:8787
```

如需前端热更新，使用两个终端：

```bash
# 终端 1
npm run build:web
npx wrangler dev

# 终端 2
npm run dev:web
```

Vite 默认运行在 `http://localhost:5173`，并代理 `/api` 到 `8787`。

> 本地 Wrangler 会使用本地 KV 模拟。生产环境的 `CONNECTIONS_KV` ID 不会影响本地模拟数据。

## 配置项

| 名称 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CONNECT_TIMEOUT_MS` | Variable | `"10000"` | TCP 建连超时，运行时限制在 2000–30000 ms。 |
| `SSH_SESSIONS` | Durable Object binding | 已配置 | 每个连接独立的会话对象。 |
| `ASSETS` | Workers Assets binding | 已配置 | 将 `dist/` 静态资源交给 Worker 提供。 |
| `ACCESS_PASSWORD` | Secret | 无 | 访问密码，同时用于 KV 同步加密密钥派生。建议必须配置。 |
| `CONNECTIONS_KV` | KV Namespace binding | 无 | 存储跨设备同步的加密连接列表密文。 |

## API 概览

| 接口 | 方法 | 用途 | 鉴权 |
| --- | --- | --- | --- |
| `/api/health` | `GET` | 返回 Worker 与 SSH 功能健康状态 | 无 |
| `/api/session` | `POST` | 创建一次性会话票据；如配置 `ACCESS_PASSWORD`，请求体需带 `password` | 可选访问密码 |
| `/api/ssh?ticket=...&session=...` | `GET` + WebSocket Upgrade | 进入 Durable Object 并建立 SSH 会话 | 一次性票据 |
| `/api/sftp?session=...&token=...` | `GET` + WebSocket Upgrade | 文件通道 | 一次性附着令牌 |
| `/api/processes?session=...&token=...` | `GET` + WebSocket Upgrade | 进程监控通道 | 一次性附着令牌 |
| `/api/connections` | `GET` | 读取加密连接列表密文 | `X-Access-Password` |
| `/api/connections` | `POST` | 写入加密连接列表密文，Body：`{ "blob": "v1..." }` | `X-Access-Password` |

所有 `/api/*` 响应均允许跨站访问，并支持浏览器 `OPTIONS` 预检请求。公网访问控制应由 Cloudflare Access、WAF 和限流策略提供。

## 安全说明

- `ACCESS_PASSWORD` 是访问密码，也是跨设备同步数据的加密口令。请使用高强度、独立、不与其他服务复用的密码。
- 连接列表在浏览器端使用 PBKDF2 + AES-256-GCM 加密，KV 中只保存密文。
- Worker 会校验 `ACCESS_PASSWORD`，但不会在 KV 中保存明文连接列表。
- 如果 `ACCESS_PASSWORD` 泄露，攻击者可能进入 WebSSH，也可能解密已同步的连接列表密文。
- 修改 `ACCESS_PASSWORD` 后，旧 KV 密文通常无法解密；前端会忽略旧远端数据并用新密码重新推送当前本地列表。
- 历史密码仍使用浏览器 IndexedDB 中的 AES-256-GCM 密钥加密，私钥不保存。
- SSH 主机密钥会验证交换签名并计算 `SHA256:` 指纹；没有固定指纹时，认证会暂停等待用户确认。
- Worker 是实际的 SSH 客户端，密码或私钥会在 Worker 会话内存中被处理。请使用权限最小化的独立账号或密钥。
- 公网部署必须叠加 Cloudflare Access、WAF、限流和使用监控。

## 项目结构

```text
.
├── frontend/                  # xterm.js 前端
│   ├── index.html
│   └── src/
│       ├── main.ts            # 连接管理、xterm、WebSocket 客户端
│       ├── kv-sync.ts         # 新增：KV 跨设备同步与客户端 AES-GCM 加密
│       ├── history.ts         # 历史记录归一化与去重
│       ├── history-key.ts     # IndexedDB 中的 AES-GCM 密钥
│       ├── password-crypto.ts # 历史密码 AES-GCM 加解密
│       ├── ui-state.ts        # 连接按钮与面板状态机
│       └── style.css
├── src/
│   ├── backend/
│   │   ├── durable-object.ts  # 会话票据、TCP Socket 与会话生命周期
│   │   ├── security.ts        # 票据、同源与公网目标校验
│   │   ├── session.ts         # SSH 状态机与浏览器消息桥接
│   │   └── sftp-handler.ts    # SFTP 文件操作与传输状态
│   ├── ssh/                   # SSH 协议、KEX、密码学、认证与通道
│   ├── http-security.ts       # HTTPS、安全响应头与 CORS
│   ├── types.ts               # Worker 环境、连接消息和 SSH 类型
│   └── worker.ts              # HTTP/API/Assets 入口，新增 /api/connections
├── wrangler.toml              # Worker、Assets、Durable Object、KV 与 migration
└── package.json
```

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | 通过 Wrangler 构建前端并启动本地 Worker |
| `npm run dev:web` | 启动 Vite 前端开发服务器 |
| `npm run build:web` | 将前端构建到 `dist/` |
| `npm run typecheck` | 检查 Worker 与前端 TypeScript |
| `npm run check` | 执行全部检查、构建和部署 dry-run |
| `npm run deploy` | 通过 Wrangler 构建前端并部署到 Cloudflare |
| `npx wrangler secret put ACCESS_PASSWORD` | 设置访问密码 Secret |
| `npx wrangler kv namespace create CONNECTIONS_KV` | 创建同步用 KV Namespace |

## 许可证与开源合规

本项目是 [cmliu/CF-Workers-WebSSH](https://github.com/cmliu/CF-Workers-WebSSH) 的衍生修改版，遵循 **Apache License 2.0**。

分发或再修改时请遵守 Apache-2.0：

- 保留原项目的 `LICENSE` 文件；
- 保留原始版权、专利、商标和归属声明；
- 对修改过的文件加入显著修改说明；
- 如果原项目包含 `NOTICE` 文件，衍生作品需要保留可读副本；
- 不得暗示原作者为你的修改版背书；
- 本魔改版新增代码同样按 Apache-2.0 发布，除非文件中另有说明。

建议在仓库中保留：

```text
LICENSE
NOTICE
```

`NOTICE` 可写为：

```text
This product includes software developed by
cmliu/CF-Workers-WebSSH (https://github.com/cmliu/CF-Workers-WebSSH),
licensed under the Apache License, Version 2.0.

This repository contains modifications that add:
- ACCESS_PASSWORD based access control
- Cloudflare KV based cross-device connection-list sync
- Client-side AES-GCM encryption for synchronized connection data
```

## 致谢

本项目在开发过程中参考了以下优秀开源项目，特此致谢：

- [huashengdun/webssh](https://github.com/huashengdun/webssh) —— 基于 WebSocket 的 WebSSH 终端，本项目前端兼容其 `wssh` JavaScript API。
- [newbietan/CloudSSH](https://github.com/newbietan/CloudSSH) —— Cloudflare Workers 上的 SSH 实现参考。
- [crazypeace/huashengdun-webssh](https://github.com/crazypeace/huashengdun-webssh) —— huashengdun/webssh 的二次开发维护分支，为本项目前端兼容性提供了参考。
- [cmliu/CF-Workers-WebSSH](https://github.com/cmliu/CF-Workers-WebSSH) —— 本魔改版的上游原项目。