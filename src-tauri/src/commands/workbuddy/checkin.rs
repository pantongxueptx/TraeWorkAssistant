//! WorkBuddy 签到域（原 workbuddy.rs 机械拆分）：M4 签到/成长（F-15/F-17，python NDJSON 管线）、
//! 签到结果（F-15）、每日定时任务（F-16/F-55）、UI 坐标点击兜底（T4.2/F-18）、启动自动补签（F-55）。
//! 函数逻辑零改动，仅将跨子模块引用项提升为 `pub(super)`。

use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::process::Command;
use tauri::{AppHandle, State};

use crate::fs_utils;
use crate::state::AppState;

use super::common::{checkin_results_path, load_settings, push_notify, spawn_wb_script};

// ── M4 签到（F-15，python NDJSON 管线）─────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct WbCheckinOpts {
    #[serde(default)]
    pub user_ids: Option<Vec<String>>,
    #[serde(default)]
    pub skip_checked_in: bool,
    #[serde(default)]
    pub skip_expired: bool,
    #[serde(default)]
    pub lazy_hours: Option<i64>,
}

/// 签到/成长全局轮次锁（审查 P1）：python 签到/成长管线共享 uid 文件锁与结果落盘，
/// 并发轮次会互相踩踏——tokio Mutex try_lock 拿不到即拒绝，不排队不阻塞。
static WB_ROUND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 入口尝试获取轮次锁；guard 移交 spawn_wb_script 工作线程并持有至脚本退出
///（RAII：正常结束与 panic 展开均可靠释放，防泄漏）。
fn try_acquire_wb_round() -> Result<tokio::sync::MutexGuard<'static, ()>, String> {
    WB_ROUND_LOCK
        .try_lock()
        .map_err(|_| "已有签到/成长任务在执行中，请等待当前轮次完成".to_string())
}

/// 启动 WorkBuddy 签到（python workbuddy_checkin.py --json-stream），
/// NDJSON → `wb-checkin-progress` 事件（独立管线，避免与 Trae checkin 状态串扰）。
#[tauri::command(async)]
pub fn workbuddy_checkin_start(app: AppHandle, state: State<AppState>, opts: WbCheckinOpts) -> Result<(), String> {
    let round = try_acquire_wb_round()?;
    let mut args: Vec<String> = vec!["--json-stream".into()];
    if opts.skip_checked_in {
        args.push("--skip-checked".into());
    }
    if opts.skip_expired {
        args.push("--skip-expired".into());
    }
    if let Some(lh) = opts.lazy_hours {
        args.push("--lazy-hours".into());
        args.push(lh.to_string());
    }
    for uid in opts.user_ids.unwrap_or_default() {
        args.push("--uid".into());
        args.push(uid);
    }
    spawn_wb_script(app, &state, "workbuddy_checkin.py", &args, "wb-checkin-progress", round)
}

/// 成长中心执行（F-17，批次2 消费；批次1 端点已就绪时 python 会按开关执行）
#[tauri::command(async)]
pub fn workbuddy_growth_run(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let round = try_acquire_wb_round()?;
    let s = load_settings(&state);
    let mut args: Vec<String> = vec!["--growth".into()];
    if s.growth_travel { args.push("--growth-travel".into()); }
    if s.growth_lottery { args.push("--growth-lottery".into()); }
    if s.growth_tasks { args.push("--growth-tasks".into()); }
    spawn_wb_script(app, &state, "workbuddy_checkin.py", &args, "wb-checkin-progress", round)
}

// ── 签到结果 / 定时任务（F-15/F-16/F-55）───────────────────────────────────

#[derive(Serialize, Clone)]
pub struct WbCheckinRecord {
    pub date: String,
    pub time: String,
    pub user_id: String,
    pub name: String,
    pub status: String,
    pub message: String,
    /// 签到获得积分（接口返回或前后余额差值兜底；无则为 None）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<f64>,
}

/// 签到日志（90 天存储，UI 默认展示 30 天）
#[tauri::command]
pub fn workbuddy_checkin_results(state: State<AppState>, days: Option<i64>) -> Result<Vec<WbCheckinRecord>, String> {
    let days = days.unwrap_or(30).clamp(1, 90);
    let cutoff = (chrono::Local::now().date_naive() - chrono::Duration::days(days))
        .format("%Y-%m-%d")
        .to_string();
    let raw: serde_json::Value = fs_utils::read_json(&checkin_results_path(&state));
    let mut out = Vec::new();
    if let Some(arr) = raw.get("results").and_then(|v| v.as_array()) {
        for r in arr {
            let date = r.get("date").and_then(|v| v.as_str()).unwrap_or("");
            if date < cutoff.as_str() {
                continue;
            }
            out.push(WbCheckinRecord {
                date: date.into(),
                time: r.get("time").and_then(|v| v.as_str()).unwrap_or("").into(),
                user_id: r.get("user_id").and_then(|v| v.as_str()).unwrap_or("").into(),
                name: r.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
                status: r.get("status").and_then(|v| v.as_str()).unwrap_or("").into(),
                message: r.get("message").and_then(|v| v.as_str()).unwrap_or("").into(),
                reward: r.get("reward").and_then(|v| v.as_f64()),
            });
        }
    }
    out.reverse(); // 新→旧
    Ok(out)
}

/// 每日签到定时任务（F-16 双时段：每个时间一个任务，后缀 _HHMM）
const WB_CHECKIN_TASK_PREFIX: &str = "AIWorkAssistant_WorkBuddyCheckin";
const WB_RENEW_TASK_NAME: &str = "AIWorkAssistant_WorkBuddyRenew";

fn build_wb_task_tr(state: &AppState, script_args: &[&str]) -> String {
    let py = state.python_exe.replace('\\', "/");
    let script = state.python_dir.join("workbuddy_checkin.py").to_string_lossy().replace('\\', "/");
    let data_dir = state.data_dir.to_string_lossy().to_string();
    let args = script_args.join(" ");
    format!("cmd /c set \"AIWORKDATA_DIR={}\" && \"{}\" \"{}\" {}", data_dir, py, script, args)
}

fn run_schtasks(args: &[&str]) -> Result<(bool, String, String), String> {
    crate::commands::misc::run_schtasks(args)
}

fn task_exists(name: &str) -> bool {
    run_schtasks(&["/Query", "/TN", name, "/FO", "LIST"]).map(|(ok, _, _)| ok).unwrap_or(false)
}

/// 解析 `schtasks /Query /FO CSV /NH` 的输出为任务名列表。
///
/// **不按固定列号取值**：`/FO CSV` 的列序在不同 schtasks 版本/系统上并不一致。
/// 实测本机（Win11 中文，`schtasks /Query /FO CSV`）表头为
/// `"任务名","下次运行时间","模式"`——**没有 HostName 列**；原实现按注释假设的
/// `HostName, TaskName, ...` 取第 2 列，实际拿到的是「下次运行时间」，
/// 于是按前缀枚举永远为空：任务注册成功（`schtasks /Create` 返回 0），
/// 界面却始终显示「未注册」，点「注册」也看不到状态变化。
///
/// 改为按**内容特征**识别：任务名是唯一以 `\` 开头的字段
/// （根目录 `\Name`、子目录 `\Folder\Name`），与列序、系统语言均无关。
/// 带引号字段与根目录前缀 `\` 需剥离（本仓任务名不含逗号，按逗号切分安全）。
fn parse_task_names_csv(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            line.split(',')
                .map(|f| f.trim())
                .find(|f| f.starts_with("\"\\"))
                .map(|f| f.trim_matches('"').trim_start_matches('\\').to_string())
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// 枚举当前用户可见的计划任务名（审查 P2）：`schtasks /Query /FO CSV /NH`。
fn list_task_names() -> Vec<String> {
    let Ok((_, stdout, _)) = run_schtasks(&["/Query", "/FO", "CSV", "/NH"]) else {
        return vec![];
    };
    parse_task_names_csv(&stdout)
}

/// 按任务名前缀枚举本功能全部签到任务（兼容任意 _HHMM 后缀，不再硬编码 _0900/_2100/_1200）
fn wb_checkin_task_names() -> Vec<String> {
    let prefix = format!("{WB_CHECKIN_TASK_PREFIX}_");
    list_task_names()
        .into_iter()
        .filter(|n| n.starts_with(&prefix))
        .collect()
}

// ── 任务设置放宽（F-16 增强）───────────────────────────────────────────────
// schtasks /Create **没有**对应开关，实测（2026-09-15 本机 Win11）注册出的任务为：
//   <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>   ← 用电池时不启动
//   <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>           ← 运行中切电池被中断
//   <StartWhenAvailable>false</StartWhenAvailable>                  ← 错过触发时刻不补跑
// 对签到（每天一次、错过即白丢）过于苛刻：笔记本拔电、或到点时机器在睡眠/关机，
// 当天直接漏签且无任何提示。故注册后把这三项放宽。
// 实现走「/Query /XML 导出 → 字符串替换 → /Create /XML 覆盖」的 XML 往返（本仓既有做法，
// 见 misc::legacy_task_start_time），不引入 PowerShell / Set-ScheduledTask 依赖。
/// 需放宽的设置项：(标签名, schtasks 默认值, 目标值)
const WB_TASK_SETTINGS_RELAX: [(&str, &str, &str); 3] = [
    ("StartWhenAvailable", "false", "true"),
    ("DisallowStartIfOnBatteries", "true", "false"),
    ("StopIfGoingOnBatteries", "true", "false"),
];

/// 把 `<Tag>from</Tag>` 替换为 `<Tag>to</Tag>`（仅首个匹配）。
/// - 已达标（值就是 `to`）或标签存在但值不同：标签存在时不动第二处，靠 `contains` 判断幂等；
/// - 标签整体缺失（个别系统导出会省略默认项）：插到 `<Settings>` 之后；
/// - 连 `<Settings>` 都没有：原样返回，由调用方判定无需覆盖。
/// 这三个标签只出现在 `<Settings>` 段（Trigger/Action 段无同名标签），故替换不会误伤。
fn patch_task_setting(xml: &str, tag: &str, from: &str, to: &str) -> String {
    let old = format!("<{tag}>{from}</{tag}>");
    if xml.contains(&old) {
        return xml.replacen(&old, &format!("<{tag}>{to}</{tag}>"), 1);
    }
    // 标签已在目标值（重复注册的幂等路径）：无需改动
    if xml.contains(&format!("<{tag}>")) {
        return xml.to_string();
    }
    match xml.find("<Settings>") {
        Some(pos) => {
            let at = pos + "<Settings>".len();
            let mut out = String::with_capacity(xml.len() + tag.len() * 2 + 12);
            out.push_str(&xml[..at]);
            out.push_str(&format!("<{tag}>{to}</{tag}>"));
            out.push_str(&xml[at..]);
            out
        }
        None => xml.to_string(),
    }
}

/// 按 `WB_TASK_SETTINGS_RELAX` 依次放宽整份任务 XML。
fn relax_task_settings_xml(xml: &str) -> String {
    let mut out = xml.to_string();
    for (tag, from, to) in WB_TASK_SETTINGS_RELAX {
        out = patch_task_setting(&out, tag, from, to);
    }
    out
}

/// 解码 `schtasks /Query /XML` 输出：UTF-16LE（带 BOM）→ String；
/// 非 UTF-16 时按 UTF-8 容错（与 misc::legacy_task_start_time 同一约定）。
fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// 编码为 UTF-16LE + BOM（`schtasks /Create /XML` 接受 UTF-16 与 UTF-8-BOM；
/// 沿用导出时的 UTF-16，避免中文任务名/描述在回写时丢失）。
fn encode_task_xml(xml: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + xml.len() * 2);
    out.extend_from_slice(&[0xFF, 0xFE]);
    for u in xml.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// 对已注册的单个任务应用设置放宽。失败仅表示「设置未放宽」，任务本身仍在，
/// 调用方不应据此判定注册失败（因此 register 侧只记警告）。
fn apply_relaxed_task_settings(name: &str) -> Result<(), String> {
    let (ok, raw, stderr) = crate::commands::misc::run_schtasks_raw(&["/Query", "/TN", name, "/XML"])?;
    if !ok {
        return Err(format!("导出任务 XML 失败: {}", stderr.trim()));
    }
    let xml = decode_task_xml(&raw);
    if xml.trim().is_empty() {
        return Err("导出任务 XML 为空".to_string());
    }
    let patched = relax_task_settings_xml(&xml);
    if patched == xml {
        return Ok(()); // 已达标（幂等）
    }
    let tmp = std::env::temp_dir().join(format!("aiwork_task_{name}.xml"));
    std::fs::write(&tmp, encode_task_xml(&patched))
        .map_err(|e| format!("写临时任务 XML 失败: {e}"))?;
    let xml_arg = tmp.to_string_lossy().to_string();
    let res = crate::commands::misc::run_schtasks(&["/Create", "/TN", name, "/XML", &xml_arg, "/F"]);
    let _ = std::fs::remove_file(&tmp);
    let (ok2, _, stderr2) = res?;
    if !ok2 {
        return Err(format!("覆盖任务设置失败: {}", stderr2.trim()));
    }
    Ok(())
}

/// 注册 WorkBuddy 每日签到任务（每个时间一个 `_HHMM` 任务）。
///
/// 返回值：**设置放宽的警告列表**（空数组 = 完全成功）。
/// 之所以不用 `Result<(), _>`：任务创建成功后「放宽设置」仍可能失败，
/// 但任务本身已可用，不应让前端把整体判为注册失败——故把这类问题作为警告回传。
#[tauri::command(async)]
pub fn workbuddy_checkin_task_register(
    state: State<AppState>,
    times: Vec<String>,
) -> Result<Vec<String>, String> {
    if times.is_empty() {
        return Err("至少需要一个触发时间（如 09:00 / 21:00）".into());
    }
    // 审查修复（命令注入）：times 逐项严格校验后再进 schtasks（与 misc::task_register 同 sink）
    for t in &times {
        crate::commands::misc::validate_hhmm(t)?;
    }
    let tr = build_wb_task_tr(&state, &["--json-stream", "--skip-checked"]);
    // 先清理旧实例（按任务名前缀枚举，兼容历史任意 HHMM 后缀），保证重注册幂等
    for name in wb_checkin_task_names() {
        let _ = run_schtasks(&["/Delete", "/TN", &name, "/F"]);
    }
    let mut warnings: Vec<String> = Vec::new();
    for t in &times {
        let hhmm = t.replace(':', "");
        let name = format!("{WB_CHECKIN_TASK_PREFIX}_{hhmm}");
        let (ok, _, stderr) = run_schtasks(&[
            "/Create", "/TN", &name, "/TR", &tr, "/SC", "DAILY", "/ST", t, "/F",
        ])?;
        if !ok {
            return Err(format!("注册任务 {t} 失败: {}", stderr.trim()));
        }
        // 放宽 schtasks 默认的苛刻设置（见 WB_TASK_SETTINGS_RELAX 注释）：
        // 失败只记警告——任务已创建并会按点执行，仅少了「错过补跑/允许电池」这两点韧性
        if let Err(e) = apply_relaxed_task_settings(&name) {
            warnings.push(format!("{t} 的设置放宽失败（任务已注册，按默认设置运行）: {e}"));
        }
    }
    if !warnings.is_empty() {
        fs_utils::app_log(
            &state.data_dir,
            &format!("WorkBuddy 签到任务设置放宽警告: {}", warnings.join("；")),
        );
    }
    Ok(warnings)
}

/// 任务名后缀 `_HHMM` → 展示用 `HH:MM`。
/// 原实现用 `replace('_', ":")`，但任务名是按 `format!("{PREFIX}_{hhmm}")` 生成的
/// （`hhmm` 已去掉冒号），后缀里没有下划线，该替换是空操作——界面会显示
/// 「已注册：0900、2100」。非 4 位纯数字时原样返回，兼容历史自定义命名。
fn hhmm_suffix_to_time(suffix: &str) -> String {
    if suffix.len() == 4 && suffix.chars().all(|c| c.is_ascii_digit()) {
        format!("{}:{}", &suffix[..2], &suffix[2..])
    } else {
        suffix.replace('_', ":")
    }
}

#[tauri::command(async)]
pub fn workbuddy_checkin_task_status() -> Result<Vec<String>, String> {
    let prefix = format!("{WB_CHECKIN_TASK_PREFIX}_");
    Ok(wb_checkin_task_names()
        .iter()
        .map(|name| hhmm_suffix_to_time(name.trim_start_matches(&prefix)))
        .collect())
}

#[tauri::command(async)]
pub fn workbuddy_checkin_task_unregister() -> Result<(), String> {
    for name in wb_checkin_task_names() {
        let _ = run_schtasks(&["/Delete", "/TN", &name, "/F"]);
    }
    Ok(())
}

/// token 每周兜底续期任务（F-09；python --renew-only 惰性刷新）
#[tauri::command(async)]
pub fn workbuddy_renew_task_register(state: State<AppState>, day: String) -> Result<(), String> {
    // day: MON..SUN（schtasks /SC WEEKLY /D）；默认 SUN。
    // 审查修复（命令注入）：白名单校验（此前仅大写化，"mon&calc" → "MON&CALC" 仍可注入）
    let d = if day.is_empty() { "SUN".to_string() } else { day.to_uppercase() };
    if !["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"].contains(&d.as_str()) {
        return Err(format!("星期无效: {day}（应为 MON..SUN）"));
    }
    let tr = build_wb_task_tr(&state, &["--renew-only"]);
    let (ok, _, stderr) = run_schtasks(&[
        "/Create", "/TN", WB_RENEW_TASK_NAME, "/TR", &tr, "/SC", "WEEKLY", "/D", &d, "/ST", "10:30", "/F",
    ])?;
    if !ok {
        return Err(format!("注册续期任务失败: {}", stderr.trim()));
    }
    Ok(())
}

#[tauri::command]
pub fn workbuddy_renew_task_status() -> bool {
    task_exists(WB_RENEW_TASK_NAME)
}

#[tauri::command(async)]
pub fn workbuddy_renew_task_unregister() -> Result<(), String> {
    let _ = run_schtasks(&["/Delete", "/TN", WB_RENEW_TASK_NAME, "/F"]);
    Ok(())
}

// ── UI 坐标点击签到兜底（T4.2/F-18）────────────────────────────────────────
// 无 API 可用时的最后手段：仅手动触发、默认关闭（ui_click_enabled）；
// 坐标由用户「取点」预配置；单次执行只单击一次，不循环连点；零 token 输出。

#[tauri::command]
pub fn workbuddy_ui_click_capture(state: State<AppState>) -> Result<serde_json::Value, String> {
    run_ui_click_script(&state, vec!["--capture".to_string()])
}

#[tauri::command]
pub fn workbuddy_ui_click_checkin(state: State<AppState>) -> Result<serde_json::Value, String> {
    let s = load_settings(&state);
    if !s.ui_click_enabled {
        return Err("UI 坐标点击兜底未启用：请在设置中显式开启（F-18 仅作 API 不可用时的最后手段）".to_string());
    }
    if s.ui_click_x <= 0 || s.ui_click_y <= 0 {
        return Err("签到按钮坐标未配置：请先在客户端打开签到页，再用「取点」记录按钮位置".to_string());
    }
    run_ui_click_script(
        &state,
        vec![
            "--click".to_string(),
            "--x".to_string(),
            s.ui_click_x.to_string(),
            "--y".to_string(),
            s.ui_click_y.to_string(),
        ],
    )
}

fn run_ui_click_script(state: &AppState, args: Vec<String>) -> Result<serde_json::Value, String> {
    let script_path = state.python_dir.join("workbuddy_ui_click.py");
    if !script_path.exists() {
        return Err(format!("找不到脚本: {}", script_path.display()));
    }
    let out = Command::new(&state.python_exe)
        .arg(&script_path)
        .args(&args)
        .creation_flags(0x08000000)
        .env("PYTHONIOENCODING", "utf-8")
        .output()
        .map_err(|e| format!("UI 点击执行失败: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .ok_or_else(|| format!("UI 点击脚本输出无法解析: {}", stdout.trim().chars().take(120).collect::<String>()))
}

// ── 启动自动补签（F-55）────────────────────────────────────────────────────

/// 启动自动补签核心（F-55，main.rs 启动线程调用）：
/// 复用签到脚本 --json-stream --skip-checked（未签自动补签），静默执行零打扰。
pub fn startup_auto_checkin(app: &AppHandle, state: &AppState) {
    let s = load_settings(state);
    if !s.auto_checkin {
        return;
    }
    let app2 = app.clone();
    let data_dir = state.data_dir.clone();
    let python_dir = state.python_dir.clone();
    let python_exe = state.python_exe.clone();
    std::thread::spawn(move || {
        // 与 Trae 静默签到同款延迟 60s，避开启动高峰
        std::thread::sleep(std::time::Duration::from_secs(60));
        let script = python_dir.join("workbuddy_checkin.py");
        if !script.exists() {
            fs_utils::app_log(&data_dir, "WorkBuddy 启动补签：脚本不存在，跳过");
            return;
        }
        fs_utils::app_log(&data_dir, "WorkBuddy 启动补签：开始核验签到状态");
        match Command::new(&python_exe)
            .arg(&script)
            .args(["--json-stream", "--skip-checked"])
            .creation_flags(0x08000000)
            .env("AIWORKDATA_DIR", &data_dir)
            .env("PYTHONIOENCODING", "utf-8")
            .output()
        {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let done = stdout
                    .lines()
                    .rev()
                    .find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
                    .filter(|v| v.get("type") == Some(&serde_json::json!("done")));
                match done {
                    Some(d) => {
                        let msg = format!(
                            "WorkBuddy 启动补签完成: 成功 {}，已签 {}，失败 {}",
                            d.get("ok").and_then(|v| v.as_i64()).unwrap_or(0),
                            d.get("already").and_then(|v| v.as_i64()).unwrap_or(0),
                            d.get("failed").and_then(|v| v.as_i64()).unwrap_or(0),
                        );
                        fs_utils::app_log(&data_dir, &msg);
                        let failed = d.get("failed").and_then(|v| v.as_i64()).unwrap_or(0);
                        if failed > 0 {
                            push_notify(
                                Some(&app2),
                                &data_dir,
                                "WorkBuddy 签到提醒",
                                &format!("启动补签有 {failed} 个账号失败，请在签到与成长页查看"),
                            );
                        }
                    }
                    None => fs_utils::app_log(&data_dir, "WorkBuddy 启动补签：无有效结果输出"),
                }
            }
                    Err(e) => fs_utils::app_log(&data_dir, &format!("WorkBuddy 启动补签失败: {e}")),
        }
    });
}

// ── 托盘一键签到（Trae 之外的两个阶段由 main.rs 托盘线程调用）──────────────

/// 托盘一键签到 WorkBuddy 部分：签到 → 成长计划 同步串行执行（同脚本两阶段，
/// 串行避免 WB_ROUND_LOCK 并发互斥拒绝），各阶段完成发系统通知。
/// Trae 签到由 main.rs 复用 start_checkin_core 并行触发，互不阻塞。
pub fn tray_checkin_all(app: &AppHandle, state: &AppState) {
    let s = load_settings(state);
    let script = state.python_dir.join("workbuddy_checkin.py");
    if !script.exists() {
        fs_utils::app_log(&state.data_dir, "托盘一键签到：WB 脚本不存在，跳过 WorkBuddy 部分");
        return;
    }
    let growth_args = {
        let mut a = vec!["--growth".to_string()];
        if s.growth_travel { a.push("--growth-travel".into()); }
        if s.growth_lottery { a.push("--growth-lottery".into()); }
        if s.growth_tasks { a.push("--growth-tasks".into()); }
        a
    };
    let stages = [
        ("签到", vec!["--json-stream".to_string(), "--skip-checked".to_string()]),
        ("成长计划", growth_args),
    ];
    for (name, args) in stages {
        let result = Command::new(&state.python_exe)
            .arg(&script)
            .args(&args)
            .creation_flags(0x08000000)
            .env("AIWORKDATA_DIR", &state.data_dir)
            .env("PYTHONIOENCODING", "utf-8")
            .output();
        match result {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // 取最后一条可解析 NDJSON；仅 type=done 视为有效轮次结果
                let done = stdout
                    .lines()
                    .rev()
                    .find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
                    .filter(|v| v.get("type") == Some(&serde_json::json!("done")));
                match done {
                    Some(d) => {
                        // 计数器仅签到阶段输出齐全；成长阶段缺字段时降级为「完成」
                        let summary = match (
                            d.get("ok").and_then(|v| v.as_i64()),
                            d.get("already").and_then(|v| v.as_i64()),
                            d.get("failed").and_then(|v| v.as_i64()),
                        ) {
                            (Some(o), Some(a), Some(f)) => format!("成功 {o}，已签 {a}，失败 {f}"),
                            _ => "完成".to_string(),
                        };
                        let msg = format!("WorkBuddy {name}: {summary}");
                        fs_utils::app_log(&state.data_dir, &msg);
                        push_notify(Some(app), &state.data_dir, "一键签到", &msg);
                    }
                    None => {
                        fs_utils::app_log(
                            &state.data_dir,
                            &format!("托盘一键签到：WorkBuddy {name} 无有效结果输出"),
                        );
                    }
                }
            }
            Err(e) => {
                let msg = format!("WorkBuddy {name}失败: {e}");
                fs_utils::app_log(&state.data_dir, &msg);
                push_notify(Some(app), &state.data_dir, "一键签到", &msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_task_xml, encode_task_xml, hhmm_suffix_to_time, parse_task_names_csv,
        patch_task_setting, relax_task_settings_xml,
    };

    /// 回归（2026-09-15 本机实测）：`schtasks /Query /FO CSV /NH` 实际**无 HostName 列**，
    /// 表头为「任务名,下次运行时间,模式」。按固定第 2 列取值会拿到「下次运行时间」，
    /// 导致已注册任务被枚举为空、界面误显示「未注册」。
    #[test]
    fn parse_task_names_without_hostname_column() {
        let csv = "\"\\AIWorkAssistant_DailyCheckin\",\"2026/9/16 10:00:00\",\"就绪\"\n\
                   \"\\AIWorkAssistant_WorkBuddyCheckin_0900\",\"2026/9/16 9:00:00\",\"就绪\"\n\
                   \"\\AIWorkAssistant_WorkBuddyCheckin_2100\",\"2026/9/15 21:00:00\",\"就绪\"\n";
        assert_eq!(
            parse_task_names_csv(csv),
            vec![
                "AIWorkAssistant_DailyCheckin",
                "AIWorkAssistant_WorkBuddyCheckin_0900",
                "AIWorkAssistant_WorkBuddyCheckin_2100",
            ]
        );
    }

    /// 兼容带 HostName 列的历史列序：HostName 不以 `\` 开头，不会被误判为任务名。
    #[test]
    fn parse_task_names_with_hostname_column() {
        let csv = "\"PC-01\",\"\\TaskA\",\"N/A\",\"Ready\"\n";
        assert_eq!(parse_task_names_csv(csv), vec!["TaskA"]);
    }

    /// 子目录任务保留目录前缀；空行与无 `\` 字段的行（如状态行）被丢弃。
    #[test]
    fn parse_task_names_keeps_folder_prefix_and_skips_noise() {
        let csv = "\"\\Microsoft\\Office\\TaskB\",\"2026/9/16 10:00:00\",\"就绪\"\n\n";
        assert_eq!(
            parse_task_names_csv(csv),
            vec!["Microsoft\\Office\\TaskB"]
        );
    }

    /// 回归：`_HHMM` 后缀必须还原为 `HH:MM`（原 `replace('_', ":")` 是空操作，
    /// 界面会显示「已注册：0900、2100」）。
    #[test]
    fn hhmm_suffix_to_time_formats_colon() {
        assert_eq!(hhmm_suffix_to_time("0900"), "09:00");
        assert_eq!(hhmm_suffix_to_time("2100"), "21:00");
    }

    /// 非标准后缀原样返回（不 panic、不越界）。
    #[test]
    fn hhmm_suffix_to_time_passthrough_unknown() {
        assert_eq!(hhmm_suffix_to_time("09_00"), "09:00"); // 历史形态：下划线分隔
        assert_eq!(hhmm_suffix_to_time("abc"), "abc");
        assert_eq!(hhmm_suffix_to_time(""), "");
    }

    /// 本机实测（2026-09-15）`schtasks /Query /XML` 导出的 `<Settings>` 段（节选）。
    /// 这三项默认值即「用电池不启动 / 切电池中断 / 错过不补跑」，是签到漏跑的根因。
    const SAMPLE_SETTINGS: &str = r#"<Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
  </Settings>"#;

    /// 回归：三项默认值必须被放宽，且不得误伤同段落里的其它设置。
    #[test]
    fn relax_settings_rewrites_three_defaults() {
        let out = relax_task_settings_xml(SAMPLE_SETTINGS);
        assert!(out.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(out.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(out.contains("<StartWhenAvailable>true</StartWhenAvailable>"));
        // 旧默认值必须消失（防止只插入不替换的实现）
        assert!(!out.contains("<StartWhenAvailable>false</StartWhenAvailable>"));
        assert!(!out.contains("<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>"));
        // 其它设置原样保留
        assert!(out.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(out.contains("<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"));
        assert!(out.contains("<Enabled>true</Enabled>"));
    }

    /// 幂等：重复注册时对已放宽的 XML 再跑一次，结果不变（不会反复覆盖任务）。
    #[test]
    fn relax_settings_is_idempotent() {
        let once = relax_task_settings_xml(SAMPLE_SETTINGS);
        assert_eq!(relax_task_settings_xml(&once), once);
    }

    /// 少数系统导出会省略可选设置项：标签缺失时插到 `<Settings>` 之后，其余内容不动。
    #[test]
    fn patch_absent_tag_inserts_into_settings() {
        let xml = "<Task><Settings><Enabled>true</Enabled></Settings></Task>";
        assert_eq!(
            patch_task_setting(xml, "StartWhenAvailable", "false", "true"),
            "<Task><Settings><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled></Settings></Task>"
        );
    }

    /// 连 `<Settings>` 都没有（异常/残缺 XML）：原样返回，不掷不越界。
    #[test]
    fn patch_without_settings_is_noop() {
        let xml = "<Task/>";
        assert_eq!(patch_task_setting(xml, "StartWhenAvailable", "false", "true"), xml);
        assert_eq!(relax_task_settings_xml(xml), xml);
    }

    /// XML 往返（UTF-16LE + BOM）：中文描述不得丢失或乱码。
    #[test]
    fn task_xml_roundtrip_keeps_unicode() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
                   <Task><Description>每日签到</Description></Task>";
        let bytes = encode_task_xml(xml);
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(decode_task_xml(&bytes), xml);
    }

    /// 非 UTF-16（无 BOM）输入按 UTF-8 容错解码，不 panic。
    #[test]
    fn decode_task_xml_falls_back_to_utf8() {
        assert_eq!(decode_task_xml(b"<Task/>"), "<Task/>");
        assert_eq!(decode_task_xml(&[]), "");
    }
}
