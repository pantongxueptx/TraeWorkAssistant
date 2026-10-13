use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tauri::State;

use crate::fs_utils;
use crate::jwt;
use crate::models::RawAccount;
use crate::state::AppState;

/// OAuth 常量（对齐 Trae IDE v1.107.1 真实登录协议，2026-10-13 probe 实测）：
/// 旧版 `response_type=code` + `client_secret` 授权参数已被服务端废弃（授权页永久停在
/// 「认证中」，回调从不到达），现走 PKCE 授权码模式：登录页带 code_challenge(S256)
/// → 回调 authCodeInfo.AuthCode → POST /trae/api/v3/oauth/ExchangeToken
/// {AuthCode, CodeVerifier, DeviceInfo(含 DevicePublicKey)} 换 token。
const OAUTH_CLIENT_ID: &str = "en1oxy7wnw8j9n";
const OAUTH_REDIRECT_URI: &str = "http://127.0.0.1:17388/authorize";
/// 模拟的 IDE 版本（登录 URL 的 plugin_version/x_app_version 与 ExchangeToken 的
/// ClientVersion/IDEVersion 保持一致；随 IDE 版本演进需手动同步）
const OAUTH_IDE_VERSION: &str = "1.107.1";
/// 回调 host 未携带时的默认 API host（实测回调固定 host=https://api.trae.com.cn）
const OAUTH_DEFAULT_API_HOST: &str = "https://api.trae.com.cn";

/// 待完成登录的 PKCE 上下文：oauth_get_login_url 签发时记录，oauth_login 换 token 时读取。
/// 读取后不清除：AuthCode 一次性且 10 分钟过期，网络失败后重新粘贴回调重试仍可用；
/// 下次 get_login_url 整体覆盖。
#[derive(Clone)]
struct PendingLogin {
    code_verifier: String,
    login_trace_id: String,
    machine_id: String,
    device_id: String,
}

static PENDING_LOGIN: Mutex<Option<PendingLogin>> = Mutex::new(None);

/// OAuth 回调解析结果（新版 PKCE 流程）
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuthCallbackInfo {
    pub auth_code: String,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub avatar: Option<String>,
    /// 回调 host 字段（服务端指定的 ExchangeToken API host）
    pub api_host: Option<String>,
}

/// OAuth 登录 URL 响应
#[derive(Serialize)]
pub struct OAuthLoginUrl {
    pub url: String,
    /// 兼容字段名：现承载 login_trace_id（回调 loginTraceID 一致性校验用，前端未消费）
    pub state: String,
    pub redirect_uri: String,
}

/// OAuth 登录完成后的账号信息
#[derive(Serialize)]
pub struct OAuthLoginResult {
    pub user_id: String,
    pub name: String,
    pub jwt: String,
    pub refresh_token: String,
    pub has_refresh_token: bool,
}

/// 短请求 Agent（项目未启用 ureq 的 proxy-from-env feature，Agent 默认直连）
fn short_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .max_idle_connections(20)
        .max_idle_connections_per_host(20)
        .build()
}

/// 生成随机 hex 字符串。
/// 熵源：OS CSPRNG（Windows BCryptGenRandom 系统首选 RNG）。旧 LCG 以时间戳作种子，
/// 输出可预测，不适合 OAuth state / machine_id 等安全场景（审查 P2）；BCrypt 失败时
/// 保留 LCG 兜底（仅影响随机性，不中断流程）。
pub(crate) fn random_hex(len: usize) -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let mut bytes = vec![0u8; len.div_ceil(2)];
        let halg: windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE =
            unsafe { std::mem::zeroed() };
        // STATUS_SUCCESS == 0
        let status = unsafe {
            BCryptGenRandom(halg, bytes.as_mut_ptr(), bytes.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
        if status == 0 {
            let mut out = String::with_capacity(len);
            for b in bytes {
                if out.len() >= len {
                    break;
                }
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                if out.len() >= len {
                    break;
                }
                out.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
            }
            return out;
        }
    }
    // 兜底：旧 LCG（仅非 Windows 或 BCrypt 调用失败时）
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        // 简单 LCG
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let nibble = ((seed >> 32) & 0xF) as u8;
        out.push(if nibble < 10 {
            (b'0' + nibble) as char
        } else {
            (b'a' + nibble - 10) as char
        });
    }
    out
}

/// base64url 无填充编码（PKCE code_challenge 用）
fn b64url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 从 JSON 对象按候选键取字符串（数值兜底转字符串）
fn json_str(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        v.get(k).and_then(|x| {
            x.as_str()
                .map(String::from)
                .or_else(|| x.as_i64().map(|n| n.to_string()))
        })
    })
}

/// 生成一次性 ECDSA P-256 设备公钥（SPKI PEM）。
/// 对齐 IDE：ExchangeToken 的 DeviceInfo.DevicePublicKey 必填（2026-10-13 probe 实测
/// 缺失时 api.trae.com.cn 401 / api.trae.cn 400）。IDE 按 DeviceID 持久化密钥对；
/// 本应用每次登录都生成新随机设备标识，故密钥对同样一次性即可（无 DeviceProof 签名场景）。
fn device_public_key_pem() -> Result<String, String> {
    use p256::pkcs8::EncodePublicKey;
    use p256::SecretKey;

    for _ in 0..8 {
        let hex = random_hex(64);
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("随机数解析失败: {e}"))?;
        }
        // from_slice 仅在全零标量时报错（概率≈0），重试兜底
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let der = sk
                .public_key()
                .to_public_key_der()
                .map_err(|e| format!("公钥 DER 编码失败: {e}"))?;
            let b64 = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(der.as_bytes())
            };
            let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str("-----END PUBLIC KEY-----");
            return Ok(pem);
        }
    }
    Err("生成设备密钥对失败".into())
}

/// 生成 OAuth 登录 URL（PKCE 授权码模式，参数对齐 IDE koe 流程 probe 实测形态）
#[tauri::command]
pub fn oauth_get_login_url() -> OAuthLoginUrl {
    let code_verifier = random_hex(64); // hex 字符均属 PKCE verifier 合法字符集
    let challenge = b64url_no_pad(&Sha256::digest(code_verifier.as_bytes()));
    let login_trace_id = random_hex(16);
    let machine_id = random_hex(32);
    let device_id: String = (0..15).map(|_| {
        let n = (random_hex(2).chars().next().unwrap() as u8).wrapping_rem(10);
        (b'0' + n) as char
    }).collect();

    let url = format!(
        "https://www.trae.cn/authorization?\
        login_version=1\
        &auth_from=solo\
        &login_channel=native_ide\
        &plugin_version={ide_version}\
        &auth_type=local\
        &client_id={client_id}\
        &redirect=0\
        &login_trace_id={trace}\
        &auth_callback_url={redirect_uri}\
        &machine_id={machine_id}\
        &device_id={device_id}\
        &x_device_id={device_id}\
        &x_machine_id={machine_id}\
        &x_device_brand=\
        &x_device_type=Windows\
        &x_os_version={os_version}\
        &x_app_version={ide_version}\
        &x_app_type=solo\
        &code_challenge={challenge}\
        &code_challenge_method=S256\
        &hide_saas_login=true",
        ide_version = OAUTH_IDE_VERSION,
        client_id = OAUTH_CLIENT_ID,
        trace = login_trace_id,
        redirect_uri = urlencoding::encode(OAUTH_REDIRECT_URI),
        machine_id = machine_id,
        device_id = device_id,
        os_version = urlencoding::encode("Windows 10"),
        challenge = challenge,
    );

    // 记录 PKCE 上下文供回调接续（覆盖式：同一时刻仅一个进行中的登录）
    *PENDING_LOGIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingLogin {
        code_verifier,
        login_trace_id: login_trace_id.clone(),
        machine_id,
        device_id,
    });

    OAuthLoginUrl {
        url,
        state: login_trace_id,
        redirect_uri: OAUTH_REDIRECT_URI.to_string(),
    }
}

/// 解析 OAuth 回调 URL
/// 新版回调 query 形如：authCodeInfo={"AuthCode":"..."}&userInfo={...}&host=...&loginTraceID=...
#[tauri::command]
pub fn oauth_parse_callback(callback_url: String) -> Result<OAuthCallbackInfo, String> {
    let query_str = callback_url
        .split('?')
        .nth(1)
        .ok_or_else(|| "回调 URL 中缺少查询参数".to_string())?;

    let mut params: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for pair in query_str.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("").to_string();
        let value = kv.next().unwrap_or("").to_string();
        // URL decode
        let decoded = urlencoding::decode(&value)
            .map(|c| c.to_string())
            .unwrap_or(value);
        params.insert(key, decoded);
    }

    // authCodeInfo 为 URL 编码的 JSON {"AuthCode":"...","ExpireAt":...}
    let auth_code = params
        .get("authCodeInfo")
        .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
        .and_then(|v| v.get("AuthCode").and_then(|a| a.as_str()).map(String::from))
        .or_else(|| params.get("AuthCode").cloned())
        .or_else(|| params.get("authCode").cloned())
        .ok_or_else(|| {
            "回调 URL 中缺少 AuthCode（旧版授权链接已失效，请在应用内重新点击「打开登录页」完成授权）"
                .to_string()
        })?;

    // userInfo 为 URL 编码的 JSON {"UserID":...,"ScreenName":...,"AvatarUrl":...}
    let (user_id, user_name, avatar) = params
        .get("userInfo")
        .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
        .map(|u| {
            (
                json_str(&u, &["UserID", "user_id", "userId"]),
                json_str(&u, &["ScreenName", "name", "userName"]),
                json_str(&u, &["AvatarUrl", "avatar"]),
            )
        })
        .unwrap_or((None, None, None));

    let api_host = params
        .get("host")
        .cloned()
        .filter(|h| h.starts_with("https://"));

    // CSRF（审查 P2 延续）：回调 loginTraceID 与本进程签发的一致时才接受。
    // 本进程从未签发（如重启后直接粘贴回调）时保持宽容——AuthCode 本身一次性且 10 分钟过期
    if let Some(cb_trace) = params.get("loginTraceID") {
        let issued = PENDING_LOGIN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|p| p.login_trace_id.clone());
        if let Some(expected) = issued {
            if !expected.is_empty() && cb_trace != &expected {
                return Err("OAuth loginTraceID 校验失败：回调 URL 与本机发起的登录请求不匹配（可能为伪造或重放），已拒绝".into());
            }
        }
    }

    Ok(OAuthCallbackInfo {
        auth_code,
        user_id,
        user_name,
        avatar,
        api_host,
    })
}

/// AuthCode + CodeVerifier 换 token（POST {host}/trae/api/v3/oauth/ExchangeToken）。
/// 2026-10-13 probe 实测通过：头需带 x-cloudide-token（空值），
/// DeviceInfo 必须含 DevicePublicKey（ECDSA P-256 公钥 PEM），
/// 响应 {ResponseMetadata, Result:{Token, RefreshToken, TokenExpireAt, ...}}
fn exchange_token_by_auth_code(
    auth_code: &str,
    code_verifier: &str,
    machine_id: &str,
    device_id: &str,
    api_host: &str,
) -> Result<(String, String), String> {
    let pub_pem = device_public_key_pem()?;

    let resp = short_agent()
        .post(format!("{api_host}/trae/api/v3/oauth/ExchangeToken").as_str())
        .set("content-type", "application/json")
        .set("accept", "*/*")
        .set("x-cloudide-token", "")
        .send_json(ureq::json!({
            "ClientID": OAUTH_CLIENT_ID,
            "AuthCode": auth_code,
            "CodeVerifier": code_verifier,
            "DeviceInfo": {
                "DeviceID": device_id,
                "MachineID": machine_id,
                "PlatformCode": "SOLO_PC",
                "DeviceType": "PC",
                "DeviceName": std::env::var("COMPUTERNAME").unwrap_or_default(),
                "DeviceModel": "",
                "ClientVersion": OAUTH_IDE_VERSION,
                "DevicePublicKey": pub_pem,
                "DeviceBrand": "",
                "DeviceCPU": "",
                "OSInfo": "Windows",
                "OSVersion": "10",
            },
            "IDEVersion": OAUTH_IDE_VERSION,
        }))
        .map_err(|e| match e {
            // HTTP 错误：读出响应体附带服务端错误信息（便于诊断参数问题）
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                let snippet: String = body.chars().take(200).collect();
                format!("ExchangeToken 请求失败: status code {code}，响应: {snippet}")
            }
            other => format!("ExchangeToken 请求失败: {other}"),
        })?;

    let body: serde_json::Value =
        resp.into_json().map_err(|e| format!("解析响应失败: {e}"))?;

    if let Some(err) = body.pointer("/ResponseMetadata/Error").filter(|e| !e.is_null()) {
        let code = json_str(err, &["Code"]).unwrap_or_default();
        let msg = json_str(err, &["Message"]).unwrap_or_else(|| "未知错误".into());
        return Err(format!("ExchangeToken 失败 (code={code}): {msg}"));
    }

    let result = body.get("Result").ok_or("ExchangeToken 响应中缺少 Result")?;
    let token = json_str(result, &["Token"]).ok_or("ExchangeToken 响应中缺少 Token")?;
    let refresh_token = json_str(result, &["RefreshToken"])
        .ok_or("ExchangeToken 响应中缺少 RefreshToken")?;
    Ok((token, refresh_token))
}

/// GetUserInfo：获取用户信息。
/// 2026-10-13 实测：新签发 token 的鉴权走 x-cloudide-token 头（旧
/// Authorization: Cloud-IDE-JWT 头对新 token 返回 401「The user is not logged in」），
/// 响应体 {Result:{UserID, ScreenName, ...}}
fn get_user_info(access_token: &str) -> Result<(String, String), String> {
    let resp = short_agent()
        .post("https://api.trae.com.cn/cloudide/api/v3/trae/GetUserInfo")
        .set("x-cloudide-token", access_token)
        .set("content-type", "application/json")
        .set("accept", "*/*")
        .send_json(ureq::json!({"ReqSource": "IDE", "IDEVersion": OAUTH_IDE_VERSION}))
        .map_err(|e| format!("GetUserInfo 请求失败: {}", e))?;

    let body: serde_json::Value =
        resp.into_json().map_err(|e| format!("解析响应失败: {}", e))?;

    let data = body
        .get("Result")
        .or_else(|| body.get("result"))
        .or_else(|| body.get("data"))
        .ok_or("响应中缺少 data 字段")?;

    let user_id = json_str(data, &["UserID", "user_id", "userId"]).unwrap_or_default();
    let user_name = json_str(
        data,
        &["ScreenName", "name", "user_name", "userName", "nickname"],
    )
    .unwrap_or_default();

    Ok((user_id, user_name))
}

/// OAuth 登录闭环：解析回调（AuthCode）→ PKCE 换 token → 获取用户信息 → 保存账号
// async：内含最多两次 120s 超时的串行网络请求（exchange/get_user_info），同步命令会冻结 UI（审查修复）
#[tauri::command(async)]
pub fn oauth_login(
    state: State<AppState>,
    callback_url: String,
    account_name: Option<String>,
    group_id: Option<String>,
) -> Result<OAuthLoginResult, String> {
    // 1. 解析回调 URL（authCodeInfo / userInfo / host + loginTraceID 一致性校验）
    let callback_info = oauth_parse_callback(callback_url)?;

    // 2. PKCE：verifier 取自本进程签发登录 URL 时记录的上下文
    let pending = PENDING_LOGIN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let pending = pending.ok_or(
        "本进程未发起过登录（缺少 PKCE CodeVerifier）：请从应用内重新点击「打开登录页」完成授权",
    )?;

    // 3. AuthCode 换 token（API host 优先用回调里服务端指定的）
    let api_host = callback_info
        .api_host
        .clone()
        .unwrap_or_else(|| OAUTH_DEFAULT_API_HOST.to_string());
    let (access_token, refresh_token) = exchange_token_by_auth_code(
        &callback_info.auth_code,
        &pending.code_verifier,
        &pending.machine_id,
        &pending.device_id,
        &api_host,
    )?;

    // 4. 规范化 JWT 格式（与既有账号存储约定一致：Cloud-IDE-JWT 前缀）
    let jwt = if access_token.starts_with("Cloud-IDE-JWT ") {
        access_token.clone()
    } else {
        format!("Cloud-IDE-JWT {}", access_token)
    };

    // 5. 解析 JWT 获取 user_id
    let jwt_info = jwt::parse(&jwt);
    let user_id = callback_info
        .user_id
        .clone()
        .or_else(|| jwt_info.user_id.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "无法从回调或 JWT 中获取 user_id".to_string())?;

    // 6. 尝试获取用户名：备注名 > 回调 userInfo > GetUserInfo > user_id 前缀
    let name = account_name
        .or(callback_info.user_name.clone().filter(|s| !s.is_empty()))
        .or_else(|| {
            get_user_info(&access_token)
                .ok()
                .map(|(uid, uname)| if uname.is_empty() { uid } else { uname })
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| {
            // 按字符截取（字节切片在多字节 UTF-8 边界处会 panic）
            let head: String = user_id.chars().take(8).collect();
            format!("账号_{head}")
        });

    // 7. 检查账号是否已存在
    let mut accounts = crate::vault::load_accounts(&state);
    if accounts
        .accounts
        .iter()
        .any(|a| a.user_id.as_deref() == Some(&user_id))
    {
        // 已存在：更新 JWT 和 refresh_token
        let acct = accounts
            .accounts
            .iter_mut()
            .find(|a| a.user_id.as_deref() == Some(&user_id))
            .unwrap();
        acct.jwt = jwt.clone();
        acct.refresh_token = Some(refresh_token.clone());
        acct.updated_at = Some(fs_utils::now_iso());
        crate::vault::save_accounts(&state, &mut accounts)?;

        fs_utils::app_log(
            &state.data_dir,
            &format!("OAuth 登录：更新已有账号 [{}] jwt + refresh_token", name),
        );
    } else {
        // 新账号
        accounts.accounts.push(RawAccount {
            name: name.clone(),
            user_id: Some(user_id.clone()),
            jwt: jwt.clone(),
            refresh_token: Some(refresh_token.clone()),
            added_at: Some(fs_utils::now_iso()),
            updated_at: Some(fs_utils::now_iso()),
            dc_id: None,
        });
        crate::vault::save_accounts(&state, &mut accounts)?;

        // 设置分组
        if let Some(g) = group_id {
            let mut groups: crate::models::GroupsFile =
                fs_utils::read_json(&state.path("groups.json"));
            groups.membership.insert(user_id.clone(), g);
            fs_utils::write_json(&state.path("groups.json"), &groups)?;
        }

        fs_utils::app_log(
            &state.data_dir,
            &format!("OAuth 登录：新增账号 [{}] user_id={}", name, user_id),
        );
    }

    Ok(OAuthLoginResult {
        user_id: user_id.clone(),
        name,
        jwt,
        refresh_token,
        has_refresh_token: true,
    })
}
