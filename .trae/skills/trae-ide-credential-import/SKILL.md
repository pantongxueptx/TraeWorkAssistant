---
name: trae-ide-credential-import
description: 从 Trae IDE 加密存储解密登录凭据并导入 AI Work 助手账号库，恢复 JWT 过期账号。Use when 用户说导入账号、恢复账号、JWT 过期、解密 IDE 凭据、iCubeAuthInfo、账号凭据迁移。不用于 OAuth 登录流程开发。
---

# Trae IDE 凭据解密导入

从本机 Trae IDE 的加密凭据存储中解出 access_token（JWT）与 refresh_token，写入 AI Work 助手账号库，绕过 OAuth 授权流程直接恢复账号。

## 前置条件

- 本机已安装并登录过 Trae IDE（凭据存在于 IDE 数据目录）
- Node.js ≥ 18（需内置 webcrypto；本机可用 D:\Application\nodejs\node22\node.exe）

## 步骤

1. **解密**：运行解密脚本（自动探测 IDE 数据与安装目录，也可显式传参）：

   ```bash
   node scripts/decrypt_icube.mjs "<storage.json 路径>" "<IDE main.js 路径>"
   ```

   常见 storage.json 位置：`%APPDATA%\Trae CN\User\globalStorage\storage.json`（Trae CN）或 `%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json`（SOLO）。

   输出每个 `iCubeAuthInfo://` 键的明文 JSON。凭据在 `icube.cloudide` 键中，字段：
   `token`（JWT）、`refreshToken`、`expiredAt`、`refreshExpiredAt`、`userId`、`account.username`。
   `usertag` 键可辅助确认用户 ID 与区域映射。

2. **导入**：编辑应用账号库 `%APPDATA%\AIWorkAssistant\data\checkin_accounts.json`，找到 `UserID` 相同的条目（无则新增），写入：

   - `jwt`：`Cloud-IDE-JWT <token>`（必须带此前缀，解析器按前缀剥离）
   - `refresh_token`：`<refreshToken>` 原值
   - `updated_at`：当前时间（`YYYY-MM-DDTHH:mm:ss` 本地格式）

   JSON 明文凭据优先于 vault 加密存储（load_accounts 语义），应用运行中直写安全；下次保存时应用会自动迁入 vault 并将 JSON 占位化。

3. **验证**：用导入的 token 调服务端接口确认有效：

   ```bash
   curl -X POST https://api.trae.com.cn/cloudide/api/v3/trae/GetUserInfo \
     -H "x-cloudide-token: <token>" -H "content-type: application/json" \
     -d '{"ReqSource":"IDE","IDEVersion":"1.107.1"}'
   ```

   预期响应含 `Result.UserID` 且与导入账号一致。注意新 token 必须走 `x-cloudide-token` 头，旧 `Authorization: Cloud-IDE-JWT` 头对新 token 会返回 401。

## 关键事实

- JWT 有效期约 14 天；refresh_token 约 6 个月
- 后续自动续期：应用调 `ExchangeToken` 只需 ClientID + RefreshToken，不校验设备标识，无需再走 OAuth
- 解密算法细节见 [references/algorithm.md](references/algorithm.md)
