//! OAuth 回环监听器 + 登录链路代理豁免（F-74 批次 1/2，源自 issue #10）。
//!
//! 缺口1（回环监听）：redirect_uri 指向的 `127.0.0.1:17388/authorize` 此前本机无人监听，
//! 浏览器完成授权后只会看到「无法访问」，用户得手动复制地址栏 URL 粘贴回应用——链路从未
//! 真正闭环。现在发起 OAuth 登录时启动短生命周期 HTTP 服务：收到回调 → 前端
//! `oauth-callback` 事件自动接续落库 → 向浏览器返回提示页；收到首个回调即自动关闭，
//! 另有 10 分钟存活兜底，避免端口常驻占用。
//!
//! 缺口2（代理豁免）：登录页在系统浏览器打开，若系统代理开启（本软件 MITM 运行中 → CA
//! 未信任撞 SSL；或指向已死端口 → 全部请求无限挂起，两者都会让授权页永远加载不出来），
//! 在 OAuth 流程期间临时关闭系统代理，结束后还原。

use std::sync::Mutex;
use std::time::Duration;

use axum::extract::{RawQuery, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use tauri::{AppHandle, Emitter, Manager};

use crate::fs_utils;
use crate::state::AppState;

/// 与 oauth.rs 的 OAUTH_REDIRECT_URI 端口保持一致
const LOOPBACK_PORT: u16 = 17388;

/// 监听最长存活时间：用户打开登录页后超时未完成（放弃/挂机），自动释放端口
const LOOPBACK_MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);

struct LoopbackServer {
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
}

static LOOPBACK: Mutex<Option<LoopbackServer>> = Mutex::new(None);

/// 系统代理暂停标记：外层 Some = 暂停生效中；内层 Some = 暂停前有启用中的代理（还原用），
/// 内层 None = 本来就没有系统代理（无需还原）。
#[cfg(target_os = "windows")]
static PAUSED_PROXY: Mutex<Option<Option<(bool, String, String)>>> = Mutex::new(None);

/// 启动回环监听（幂等：已在监听时直接成功）。绑定失败（端口被占）同步返回错误，
/// 前端 toast 明示，不让链路静默断裂。
#[tauri::command]
pub fn oauth_loopback_start(app: AppHandle) -> Result<(), String> {
    let mut guard = LOOPBACK.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Ok(());
    }

    let std_listener = std::net::TcpListener::bind(("127.0.0.1", LOOPBACK_PORT))
        .map_err(|e| format!("端口 {} 绑定失败（可能被其他程序占用）: {}", LOOPBACK_PORT, e))?;

    // 关停通道：手动 stop / 收到首个回调 / 10 分钟兜底超时，任一触发即优雅退出
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    // 兜底超时：tokio 未启用 time feature，用 std 线程 sleep 后投递关停信号
    {
        let timeout_tx = shutdown_tx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(LOOPBACK_MAX_LIFETIME);
            let _ = timeout_tx.blocking_send(());
        });
    }

    tauri::async_runtime::spawn(serve(std_listener, app.clone(), shutdown_rx));

    *guard = Some(LoopbackServer { shutdown_tx });
    fs_utils::app_log(
        &app.state::<AppState>().data_dir,
        &format!("OAuth 回环监听已启动: 127.0.0.1:{}", LOOPBACK_PORT),
    );
    Ok(())
}

/// 停止回环监听（Modal 关闭/登录完成时调用；未启动时为无害 no-op）。
/// try_send 非阻塞：命令可能在 tokio 上下文中执行，禁用 blocking_* 系列。
#[tauri::command]
pub fn oauth_loopback_stop() {
    if let Some(server) = LOOPBACK.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = server.shutdown_tx.try_send(());
    }
}

async fn serve(
    std_listener: std::net::TcpListener,
    app: AppHandle,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) {
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("OAuth 回环监听转换失败: {e}");
            *LOOPBACK.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return;
        }
    };

    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let router = Router::new()
        .route("/authorize", get(handle_callback))
        .fallback(get(handle_other))
        .with_state((app, notify.clone()));

    // 首个回调（notify）或手动/超时关停（channel）任一到达即开始优雅停机；
    // with_graceful_shutdown 会等在途响应发送完毕，浏览器能收到提示页
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        tokio::select! {
            _ = notify.notified() => {},
            _ = shutdown_rx.recv() => {},
        }
    });

    if let Err(e) = server.await {
        eprintln!("OAuth 回环监听异常退出: {e}");
    }
    *LOOPBACK.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// GET /authorize：把完整回调 URL 通过事件交给前端（前端自动调 oauth_login 落库），
/// 并向浏览器返回提示页。原始 query 原样透传（oauth_parse_callback 自行解码）。
async fn handle_callback(
    State((app, notify)): State<(AppHandle, std::sync::Arc<tokio::sync::Notify>)>,
    RawQuery(query): RawQuery,
) -> Html<String> {
    let query = query.unwrap_or_default();
    let url = format!("http://127.0.0.1:{LOOPBACK_PORT}/authorize?{query}");
    fs_utils::app_log(
        &app.state::<AppState>().data_dir,
        "OAuth 回环监听：收到授权回调，已通知前端自动接续",
    );
    let _ = app.emit("oauth-callback", serde_json::json!({ "url": url }));
    // 通知优雅停机：响应发出后即关闭监听（「完成即关」，端口不常驻）
    notify.notify_one();

    Html(format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <title>授权完成</title></head>\
         <body style=\"font-family:system-ui,sans-serif;display:flex;align-items:center;\
         justify-content:center;min-height:100vh;margin:0;background:#f4f4f5\">\
         <div style=\"text-align:center;padding:2rem\">\
         <h1 style=\"color:#18181b\">✅ 授权回调已接收</h1>\
         <p style=\"color:#52525b\">请返回 TraeWorkAssistant 应用，登录会自动完成；本页面可以关闭。</p>\
         </div></body></html>"
    ))
}

/// 非 /authorize 路径（如 favicon）：明确 404 提示，不吞请求
async fn handle_other() -> Html<String> {
    Html(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         </head><body><p>OAuth 回调仅接受 /authorize 路径。</p></body></html>".into(),
    )
}

// ---------------- 缺口2：OAuth 期间系统代理豁免 ----------------

/// 暂停系统代理（OAuth 流程开始时调用）。幂等：已在暂停中则跳过。
/// 场景覆盖：本软件 MITM 运行中（CA 未信任 → SSL 报错/资源静默失败）与系统代理指向
/// 已死端口（浏览器请求无限挂起——issue #10「一直处于加载中」的直接来源）。
#[tauri::command]
pub fn oauth_proxy_pause(app: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let mut guard = PAUSED_PROXY.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let saved = super::proxy::get_existing_win_proxy();
        if let Some((_, server, _)) = &saved {
            super::proxy::apply_proxy(false, "", "")?;
            fs_utils::app_log(
                &app.state::<AppState>().data_dir,
                &format!("OAuth 登录：已临时关闭系统代理（原指向 {server}），结束后自动还原"),
            );
        }
        *guard = Some(saved);
    }
    Ok(())
}

/// 还原暂停前的系统代理（OAuth 流程结束/Modal 关闭时调用）
#[tauri::command]
pub fn oauth_proxy_restore(app: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if let Some(saved) = PAUSED_PROXY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            if let Some((true, server, override_)) = saved {
                super::proxy::apply_proxy(true, &server, &override_)?;
                fs_utils::app_log(
                    &app.state::<AppState>().data_dir,
                    "OAuth 登录结束：系统代理已还原",
                );
            }
        }
    }
    let _ = app; // 非 Windows 下消除未用参数告警
    Ok(())
}
