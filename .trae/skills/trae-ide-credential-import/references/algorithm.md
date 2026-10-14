# iCubeAuthInfo 加密算法与应用侧导入细节

## 加密存储位置

- IDE 凭据：`%APPDATA%\Trae CN\User\globalStorage\storage.json`（或 `TRAE SOLO CN` 同级路径）
- 键 `iCubeAuthInfo://icube.cloudide`：当前登录账号完整凭据
- 键 `iCubeAuthInfo://usertag`：userId → 区域映射（如 `{"1888313866731017":"cn"}`）
- 键 `iCubeAuthInfo://icube-dc:<device_id>`：设备注册密钥对（ECDSA P-256 PEM）

三者的值都是 base64，解码后为统一二进制格式。

## 二进制格式（AES 变体）

常量来源：IDE 安装目录 `resources/app/out/main.js` 内 `out-build/vs/base/common/byteCrypto.js` 模块（压缩后可全文检索 `iCubeAuthInfo` / `ule=Uint8Array.from` 定位）。

```
偏移      长度   内容
[0..6)    6     头部 74 63 05 10 00 00（'t','c',5,16,0,0 → Jn.AES 变体）
[6..38)   32    密钥材料（加密时随机生成，随机化每次密文）
[38..)    n     AES-128-CBC 密文（PKCS7 填充）
```

明文结构：`SHA512(明文)[0..64)` 前缀 + 明文本体。解密后先校验前 64 字节摘要。

另有 `AES_PRIVATE` 变体：头部第 3-6 字节为 `20 20 02 03`，密钥派生用 `cle^lle` 表；本场景凭据均走 AES 变体。

## 密钥派生（tle）

```
sbox  = ule[0..64)   // main.js 内硬编码 64 字节表
sbox2 = dle[0..64)   // 同上
a     = ule[i] ^ dle[i]  (i = 0..63)
n     = SHA512(keyMaterial[32B]) ‖ a          // 128 字节
n[0..64) = SHA512(n)                          // 覆盖前 64 字节
aesKey    = n[0..16)
iv        = n[16..32)
```

解密：AES-128-CBC(key, iv) → 去填充 → 校验 SHA512 前缀 → 取 `[64..)` 为明文 JSON。

脚本 `scripts/decrypt_icube.mjs` 在运行时直接从目标 IDE 的 main.js 提取 ule/dle 表，避免硬编码（IDE 升级换表也无需改脚本）。

## 解出 JSON（icube.cloudide 键）

```json
{
  "token": "eyJhbGciOiJSUzI1NiI...",           // RS256 JWT，payload.data.id = user_id
  "refreshToken": "_a0g5kbhClODAMENS....18de55d04ec076a2",
  "expiredAt": "2026-10-28T07:47:34.885Z",     // access token 过期（约 14 天）
  "refreshExpiredAt": "2027-04-12T07:47:34.885Z", // refresh token 过期（约 6 个月）
  "tokenReleaseAt": "2026-10-14T07:47:30.513Z",
  "userId": "1888313866731017",
  "host": "https://api.trae.cn",
  "userRegion": { "region": "CN", "_aiRegion": "CN" },
  "account": { "username": "用户9791157600", "nonPlainTextMobile": "191******81", "...": "..." }
}
```

## 应用侧账号库（AI Work 助手）

- 文件：`%APPDATA%\AIWorkAssistant\data\checkin_accounts.json`，结构 `{accounts:[...]}`，条目字段
  `name / UserID / jwt / refresh_token / added_at / updated_at / DcID`
- 读取语义（vault.rs load_accounts）：**JSON 明文优先**——条目 jwt 非空即直接使用；
  为空则从 Stronghold vault（`conf/vault.stronghold`）按 UserID 回填
- 保存语义（save_accounts）：写入 vault 后将 JSON 中 jwt/refresh_token 占位化清空——
  外部直写的明文会在应用下次保存时自动迁入 vault，属预期行为
- jwt 必须带 `Cloud-IDE-JWT ` 前缀（jwt.rs 解析器按前缀剥离，也兼容 `Bearer ` 与裸 token）

## 服务端接口

- 验证：`POST https://api.trae.com.cn/cloudide/api/v3/trae/GetUserInfo`
  头 `x-cloudide-token: <token>`（**必须用此头**；`Authorization: Cloud-IDE-JWT` 对新 token 返回 401）
  体 `{"ReqSource":"IDE","IDEVersion":"1.107.1"}` → `Result.UserID / Result.ScreenName`
- 自动续期：`POST https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken`
  体 `{"ClientID":"en1oxy7wnw8j9n","RefreshToken":"<rt>","ClientSecret":"-","UserID":""}`
  → 新信封 `{ResponseMetadata, Result}`（Result.Token / Result.RefreshToken），
  错误在 `ResponseMetadata.Error.Code/Message`；**不校验设备标识**
