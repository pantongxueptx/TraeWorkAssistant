#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae OAuth 真实协议验证脚本（F-74 批次3 前置实验）。

对齐 Trae IDE (out/main.js koe 流程) 的登录参数：
  login_version=1 & auth_from=solo & login_channel=native_ide & auth_type=local
  & client_id=en1oxy7wnw8j9n & redirect=0 & code_challenge(S256) ...
回调 http://127.0.0.1:17389/authorize 带 userInfo / authCodeInfo / codeVerifier，
POST /trae/api/v3/oauth/ExchangeToken {ClientID, AuthCode, CodeVerifier, DeviceInfo} 换 token。

v2 修正（2026-10-13 实测对齐 IDE out/main.js 的 Are 类）：
  - DeviceInfo 必须含 DevicePublicKey（ECDSA P-256 公钥 PEM，IDE 按 DeviceID 持久化密钥对）
  - 请求头 {"Content-Type":"application/json","x-cloudide-token":""}
  - IDEVersion 用真实 IDE 版本（不再写死 1.0.0）
  - host 优先取回调 query 里的 host 字段（服务端指定），打印 4xx 响应体便于诊断

用法：python scripts/trae_oauth_probe.py
浏览器会自动打开授权页，完成登录后本脚本自动收尾并打印结果。
"""
import base64
import hashlib
import json
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import webbrowser

PORT = 17389  # 避开正在运行的应用占用的 17388
CLIENT_ID = "en1oxy7wnw8j9n"
IDE_VERSION = "1.107.1"
HOSTS = ["https://api.trae.com.cn", "https://api.trae.cn"]


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def device_keypair_pem() -> tuple[str, str]:
    """ECDSA P-256 密钥对，返回 (公钥SPKI PEM, 私钥PKCS8 PEM)"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return pub_pem, priv_pem


def main():
    verifier = b64url(secrets.token_bytes(48))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    machine_id = secrets.token_hex(16)
    device_id = "".join(secrets.choice("0123456789") for _ in range(16))
    trace_id = secrets.token_hex(8)

    params = {
        "login_version": "1",
        "auth_from": "solo",
        "login_channel": "native_ide",
        "plugin_version": IDE_VERSION,
        "auth_type": "local",
        "client_id": CLIENT_ID,
        "redirect": "0",
        "login_trace_id": trace_id,
        "auth_callback_url": f"http://127.0.0.1:{PORT}/authorize",
        "machine_id": machine_id,
        "device_id": device_id,
        "x_device_id": device_id,
        "x_machine_id": machine_id,
        "x_device_brand": "",
        "x_device_type": "Windows",
        "x_os_version": "Windows 10",
        "x_app_version": IDE_VERSION,
        "x_app_type": "solo",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "hide_saas_login": "true",
    }
    url = "https://www.trae.cn/authorization?" + urllib.parse.urlencode(params)
    print("[probe] 授权 URL:")
    print(url)
    print("[probe] 即将在浏览器打开，请在页面完成登录…（监听 127.0.0.1:%d）" % PORT)

    result = {}

    class H(http.server.BaseHTTPRequestHandler if False else object):
        pass

    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            if u.path != "/authorize":
                self.send_response(404)
                self.end_headers()
                return
            result.update(dict(urllib.parse.parse_qsl(u.query)))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("✅ 已收到回调，请回到终端查看结果（本页可关闭）".encode())

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webbrowser.open(url)

    deadline = time.time() + 600
    while time.time() < deadline and "authCodeInfo" not in result and "refreshToken" not in result:
        time.sleep(0.3)
    server.shutdown()

    if not result:
        print("[probe] 5 分钟内未收到回调")
        return

    print("[probe] 回调 query keys:", sorted(result.keys()))
    for k, v in result.items():
        print(f"  {k} = {v[:200]}")

    auth_code, code_verifier = None, None
    if result.get("authCodeInfo"):
        try:
            info = json.loads(result["authCodeInfo"])
            auth_code = info.get("AuthCode")
        except Exception as e:
            print("[probe] authCodeInfo 解析失败:", e)
    # PKCE：verifier 是发起方本地保存的（IDE saveCodeVerifier），回调不带
    code_verifier = verifier
    if not auth_code:
        print("[probe] 回调未带 AuthCode（可能走了旧 refreshToken 流程）")
        return

    pub_pem, priv_pem = device_keypair_pem()
    print("[probe] DevicePublicKey PEM:\n" + pub_pem)

    body = {
        "ClientID": CLIENT_ID,
        "AuthCode": auth_code,
        "CodeVerifier": code_verifier,
        "DeviceInfo": {
            "DeviceID": device_id,
            "MachineID": machine_id,
            "PlatformCode": "SOLO_PC",
            "DeviceType": "PC",
            "DeviceName": socket.gethostname(),
            "DeviceModel": "",
            "ClientVersion": IDE_VERSION,
            "DevicePublicKey": pub_pem,
            "DeviceBrand": "",
            "DeviceCPU": "",
            "OSInfo": "Windows",
            "OSVersion": "10",
        },
        "IDEVersion": IDE_VERSION,
    }
    # host 优先用回调里服务端指定的（实测回调 host=https://api.trae.com.cn）
    cb_host = result.get("host")
    hosts = ([cb_host] if cb_host else []) + [h for h in HOSTS if h != cb_host]
    for host in hosts:
        req = urllib.request.Request(
            host + "/trae/api/v3/oauth/ExchangeToken",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "x-cloudide-token": ""},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            print(f"[probe] ExchangeToken @ {host} =>")
            print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
            return
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            print(f"[probe] {host} HTTP {e.code}: {err_body[:1200]}")
        except Exception as e:
            print(f"[probe] {host} 失败: {e}")


if __name__ == "__main__":
    main()
