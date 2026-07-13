#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 DrissionPage_example.py, openai_register.py, batch_open_nsfw.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import time
import os
import sys
import signal
import gc
import queue
import secrets
import struct
import random
import re
import string
import json

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.errors import PageDisconnectedError
from curl_cffi import requests

# SSO → CLIProxyAPI(CPA) 扁平格式转换（复用 sso_to_auth_json 的 device-flow + 写入器）
import sso_to_auth_json as _s2cpa


CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
MEMORY_CLEANUP_INTERVAL = 5

UI_BG = "#242424"
UI_PANEL_BG = "#2b2b2b"
UI_FG = "#f2f2f2"
UI_MUTED_FG = "#b8b8b8"
UI_ENTRY_BG = "#333333"
UI_BUTTON_BG = "#3a3a3a"
UI_ACTIVE_BG = "#4a6078"

DEFAULT_CONFIG = {
    "duckmail_api_key": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_custom_auth": "",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/api/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/mails",
    "proxy": "http://127.0.0.1:7890",
    "enable_nsfw": True,
    "register_count": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    # CLIProxyAPI(CPA) 直出：注册拿到 SSO 后自动 device-flow 换 token 并写成 CPA 扁平格式
    "cpa_auto_add": False,
    "cpa_auth_dir": "",
    # 远程 CPA：通过 Management API POST /v0/management/auth-files 上传
    "cpa_remote_url": "",
    "cpa_management_key": "",
    "outlook_email_plus_api_base": "",
    "outlook_email_plus_api_key": "",
    "outlook_email_plus_caller_id": "grok-register",
    "outlook_email_plus_pool_provider": "",
    "outlook_email_plus_project_key": "",
    "outlook_email_plus_email_domain": "",
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0


class RegistrationCancelled(Exception):
    pass


class AccountRetryNeeded(Exception):
    pass


def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            config = DEFAULT_CONFIG.copy()
    return config


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()

EXTENSION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "turnstilePatch")
)


DUCKMAIL_API_BASE = "https://api.duckmail.sbs"


def get_proxies():
    proxy = config.get("proxy", "")
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")


def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_custom_auth():
    """全局访问密码（cloudflare_temp_email 的 PASSWORDS）。

    开启后 Worker 会对除 /open_api、/telegram 外的所有路径校验 x-custom-auth 头，
    与 cloudflare_auth_mode 正交叠加，需要在每个请求上单独注入。
    """
    return str(config.get("cloudflare_custom_auth", "") or "").strip()


def cloudflare_apply_custom_auth(headers):
    """给请求头注入全局访问密码，若未配置则原样返回。"""
    custom_auth = get_cloudflare_custom_auth()
    if custom_auth:
        headers["x-custom-auth"] = custom_auth
    return headers


def get_cloudflare_path(key, default_path):
    raw = str(config.get(key, default_path) or default_path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def cloudflare_build_headers(content_type=False):
    headers = {"Content-Type": "application/json"} if content_type else {}
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key:
        if mode == "x-api-key":
            headers["X-API-Key"] = key
        elif mode == "x-admin-auth":
            headers["x-admin-auth"] = key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {key}"
    cloudflare_apply_custom_auth(headers)
    return headers


def cloudflare_apply_auth_params(params=None):
    merged = dict(params or {})
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key and mode == "query-key":
        merged["key"] = key
    return merged


def cloudflare_next_default_domain():
    """按配置轮换选择 Cloudflare 临时邮箱域名。"""
    global _cf_domain_index
    domains = [x.strip() for x in str(config.get("defaultDomains", "") or "").split(",") if x.strip()]
    if not domains:
        return ""
    domain = domains[_cf_domain_index % len(domains)]
    _cf_domain_index += 1
    return domain


def cloudflare_is_admin_create_path(path):
    """判断当前创建邮箱路径是否为 cloudflare_temp_email 管理员创建接口。"""
    return str(path or "").rstrip("/").lower() == "/admin/new_address"


def _pick_list_payload(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")
        if isinstance(data.get("hydra:member"), list):
            return data.get("hydra:member")
        if isinstance(data.get("data"), list):
            return data.get("data")
        if isinstance(data.get("messages"), list):
            return data.get("messages")
        if isinstance(data.get("data"), dict):
            nested = data.get("data")
            if isinstance(nested.get("messages"), list):
                return nested.get("messages")
    return []


def cloudflare_create_temp_address(api_base):
    """适配 cloudflare_temp_email 新建地址接口并兼容 admin 创建模式。"""
    path = get_cloudflare_path("cloudflare_path_accounts", "/api/new_address")
    url = f"{api_base}{path}"
    domain = cloudflare_next_default_domain()
    is_admin_create = cloudflare_is_admin_create_path(path)
    if is_admin_create:
        payload = {"name": generate_username(10), "enablePrefix": True}
        if domain:
            payload["domain"] = domain
        headers = cloudflare_build_headers(content_type=True)
    else:
        payload = {}
        if domain:
            payload["domain"] = domain
        headers = cloudflare_apply_custom_auth({"Content-Type": "application/json"})
    resp = http_post(url, json=payload, headers=headers)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare {path} 返回非JSON: {resp.text[:300]}")
    address = data.get("address")
    jwt = data.get("jwt")
    if not address or not jwt:
        raise Exception(f"Cloudflare {path} 缺少 address/jwt: {data}")
    return address, jwt


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def add_sso_to_cpa(raw_token, email="", log_callback=None):
    """SSO → device-flow 换 token → 写入本地 CPA auth 目录和/或远程 CPA。

    SSO 本身不是 CPA 认的凭据；必须先用 device flow 换到 access/refresh token，
    再写成 CPA 的 xai-<email>.json（type=xai + cli-chat-proxy base_url + grok-cli headers）。

    - 本地：写入 cpa_auth_dir，CPA 监听热加载
    - 远程：POST Management API /v0/management/auth-files（cpa_remote_url + cpa_management_key）
    """
    if not config.get("cpa_auto_add", False):
        return
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(config.get("cpa_remote_url", "") or "").strip()
    management_key = str(config.get("cpa_management_key", "") or "").strip()
    if not auth_dir and not remote_url:
        if log_callback:
            log_callback("[Debug] 已开启 CPA 直出但未配置 cpa_auth_dir 或 cpa_remote_url，跳过")
        return
    if remote_url and not management_key:
        if log_callback:
            log_callback("[Debug] 已配置 cpa_remote_url 但未配置 cpa_management_key，跳过远程上传")
        remote_url = ""
    if not auth_dir and not remote_url:
        return
    sso = _normalize_sso_token(raw_token)
    if not sso:
        return
    proxy = str(config.get("proxy", "") or "").strip()

    def _cpa_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    try:
        _cpa_log("SSO → device-flow 换 token ...")
        token = _s2cpa.sso_to_token(sso, proxy=proxy, log=_cpa_log)
        if not token:
            _cpa_log("device-flow 换 token 失败，跳过")
            return
        record = _s2cpa.token_to_cpa_record(token, email=email)
        if auth_dir:
            try:
                path = _s2cpa.write_cpa_auth(_s2cpa.Path(auth_dir), record)
                _cpa_log(f"已写入本地 {path}")
            except Exception as local_exc:
                _cpa_log(f"本地写入失败: {local_exc}")
        if remote_url:
            try:
                name = _s2cpa.upload_cpa_auth_remote(remote_url, management_key, record)
                _cpa_log(f"已上传远程 {remote_url.rstrip('/')}/.../{name}")
            except Exception as remote_exc:
                _cpa_log(f"远程上传失败: {remote_exc}")
    except Exception as exc:
        _cpa_log(f"直出失败: {exc}")


def create_browser_options():
    options = ChromiumOptions()
    options.auto_port()
    options.set_timeouts(base=1)
    if os.path.exists(EXTENSION_PATH):
        options.add_extension(EXTENSION_PATH)
    return options


def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    try:
        return requests.get(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        # 代理不可用时自动回退为直连，避免整个流程直接失败
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.get(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_post(url, **kwargs):
    try:
        return requests.post(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.post(url, **_build_request_kwargs(**retry_kwargs))
        raise


def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("用户停止注册")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = time.time() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def get_domains(api_key=None):
    headers = {}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = http_get(f"{DUCKMAIL_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def create_account(address, password, api_key=None, expires_in=0):
    headers = {"Content-Type": "application/json"}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = {"address": address, "password": password, "expiresIn": expires_in}
    resp = http_post(f"{DUCKMAIL_API_BASE}/accounts", json=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_token(address, password):
    data = {"address": address, "password": password}
    resp = http_post(f"{DUCKMAIL_API_BASE}/token", json=data)
    resp.raise_for_status()
    return resp.json().get("token")


def get_messages(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def get_message_detail(token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_domains(api_base, api_key=None):
    headers = cloudflare_build_headers(content_type=False)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_domains", "/domains")
    params = cloudflare_apply_auth_params()
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    return _pick_list_payload(resp.json())


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    payload = {"address": address, "password": password, "expiresIn": expires_in}
    path = get_cloudflare_path("cloudflare_path_accounts", "/accounts")
    params = cloudflare_apply_auth_params()
    resp = http_post(f"{api_base}{path}", json=payload, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_token(api_base, address, password, api_key=None):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_token", "/token")
    resp = http_post(
        f"{api_base}{path}",
        json={"address": address, "password": password},
        headers=headers,
        params=cloudflare_apply_auth_params(),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("token"):
            return data.get("token")
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            return data["data"].get("token")
    return None


def cloudflare_get_messages(api_base, token):
    headers = cloudflare_apply_custom_auth({"Authorization": f"Bearer {token}"})
    path = get_cloudflare_path("cloudflare_path_messages", "/messages")
    params = {"limit": 20, "offset": 0}
    params = cloudflare_apply_auth_params(params)
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare messages 返回非JSON: {resp.text[:300]}")
    return _pick_list_payload(data)


def cloudflare_get_message_detail(api_base, token, message_id):
    headers = cloudflare_apply_custom_auth({"Authorization": f"Bearer {token}"})
    candidates = [
        f"{api_base}/api/mail/{message_id}",
        f"{api_base}{get_cloudflare_path('cloudflare_path_messages', '/messages')}/{message_id}",
    ]
    last_err = None
    for url in candidates:
        try:
            resp = http_get(
                url,
                headers=headers,
                params=cloudflare_apply_auth_params(),
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data
        except Exception as exc:
            last_err = exc
            continue
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


YYDS_API_BASE = "https://maliapi.215.im/v1"


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def yyds_get_domains(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []) if data.get("success") else []


def yyds_create_account(address=None, domain=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    payload = {}
    if address:
        payload["address"] = address
    if domain:
        payload["domain"] = domain
    elif key or token:
        payload["autoDomainStrategy"] = "prefer_owned"
    resp = http_post(f"{YYDS_API_BASE}/accounts", json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 创建邮箱失败: {data}")


def yyds_get_token(address, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_post(
        f"{YYDS_API_BASE}/token", json={"address": address}, headers=headers
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("token")
    raise Exception(f"YYDS 获取token失败: {data}")


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(
        f"{YYDS_API_BASE}/messages",
        params={"address": address},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("messages", [])
    return []


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 获取邮件详情失败: {data}")


def yyds_generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def yyds_pick_domain(api_key=None, jwt=None):
    domains = yyds_get_domains(api_key=api_key, jwt=jwt)
    if not domains:
        raise Exception("YYDS 没有返回任何可用域名")
    private = [d for d in domains if d.get("isVerified") and not d.get("isPublic")]
    if private:
        return private[0]["domain"]
    public = [d for d in domains if d.get("isVerified") and d.get("isPublic")]
    if public:
        return public[0]["domain"]
    verified = [d for d in domains if d.get("isVerified")]
    if verified:
        return verified[0]["domain"]
    raise Exception("YYDS 无已验证域名可用")


def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        address=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def yyds_get_oai_code(
    token,
    address,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    jwt=None,
    cancel_callback=None,
):
    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = yyds_get_messages(address, token=token, jwt=jwt)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] YYDS 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            to_addrs = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if address.lower() not in to_addrs:
                continue
            try:
                detail = yyds_get_message_detail(msg_id, token=token, jwt=jwt)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] YYDS 获取邮件详情失败: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] YYDS 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] YYDS 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"YYDS 在 {timeout}s 内未收到验证码邮件")


# ===== outlookEmailPlus (outlookEmailPlus) 临时邮箱池接入 =====
# 接入对象：本地或自建的 outlookEmailPlus 服务，对外暴露 /api/external/* 接口
# 鉴权方式：X-API-Key
# 流程：claim-random 领取邮箱 -> wait-message 等待新邮件 -> 本地提取验证码
#       -> 注册成功 claim-complete(success) / 失败放弃 claim-release
_outlook_email_plus_pending_claim = None  # {"account_id","claim_token","caller_id","task_id","email"}
_outlook_email_plus_task_counter = 0


def get_outlook_email_plus_api_key():
    return str(config.get("outlook_email_plus_api_key", "") or "").strip()


def get_outlook_email_plus_api_base():
    return str(config.get("outlook_email_plus_api_base", "") or "").rstrip("/")


def get_outlook_email_plus_caller_id():
    cid = str(config.get("outlook_email_plus_caller_id", "") or "").strip()
    return cid or "grok-register"


def outlook_email_plus_build_headers(content_type=False):
    headers = {}
    if content_type:
        headers["Content-Type"] = "application/json"
    key = get_outlook_email_plus_api_key()
    if key:
        headers["X-API-Key"] = key
    return headers


def _outlook_email_plus_next_task_id():
    global _outlook_email_plus_task_counter
    _outlook_email_plus_task_counter += 1
    return f"grok-{int(time.time())}-{_outlook_email_plus_task_counter:04d}"


def _outlook_email_plus_external_url(path):
    base = get_outlook_email_plus_api_base()
    if not base:
        raise Exception("outlookEmailPlus API Base 未配置")
    p = str(path or "")
    if not p.startswith("/"):
        p = "/" + p
    return f"{base}{p}"


def outlook_email_plus_release_pending(reason="released", log_callback=None):
    """释放当前未完成的领取租约。无挂起租约时为空操作。"""
    global _outlook_email_plus_pending_claim
    claim = _outlook_email_plus_pending_claim
    if not claim:
        return
    _outlook_email_plus_pending_claim = None
    api_base = get_outlook_email_plus_api_base()
    if not api_base or not get_outlook_email_plus_api_key():
        return
    payload = {
        "account_id": claim.get("account_id"),
        "claim_token": claim.get("claim_token"),
        "caller_id": claim.get("caller_id"),
        "task_id": claim.get("task_id"),
        "reason": str(reason or "released")[:200],
    }
    try:
        resp = http_post(
            _outlook_email_plus_external_url("/api/external/pool/claim-release"),
            json=payload,
            headers=outlook_email_plus_build_headers(content_type=True),
            timeout=20,
        )
        if log_callback:
            ok = False
            try:
                ok = bool(resp.json().get("success"))
            except Exception:
                ok = 200 <= resp.status_code < 300
            log_callback(
                f"[Debug] outlookEmailPlus claim-release({reason}) success={ok} status={resp.status_code}"
            )
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] outlookEmailPlus claim-release 失败: {exc}")


def outlook_email_plus_complete_pending(result, detail="", log_callback=None):
    """回传领取结果。无挂起租约时为空操作。"""
    global _outlook_email_plus_pending_claim
    claim = _outlook_email_plus_pending_claim
    if not claim:
        return
    _outlook_email_plus_pending_claim = None
    api_base = get_outlook_email_plus_api_base()
    if not api_base or not get_outlook_email_plus_api_key():
        return
    payload = {
        "account_id": claim.get("account_id"),
        "claim_token": claim.get("claim_token"),
        "caller_id": claim.get("caller_id"),
        "task_id": claim.get("task_id"),
        "result": str(result or "success"),
        "detail": str(detail or "")[:500],
    }
    try:
        resp = http_post(
            _outlook_email_plus_external_url("/api/external/pool/claim-complete"),
            json=payload,
            headers=outlook_email_plus_build_headers(content_type=True),
            timeout=20,
        )
        if log_callback:
            ok = False
            pool_status = ""
            try:
                data = resp.json()
                ok = bool(data.get("success"))
                pool_status = str((data.get("data") or {}).get("pool_status") or "")
            except Exception:
                ok = 200 <= resp.status_code < 300
            log_callback(
                f"[Debug] outlookEmailPlus claim-complete({result}) success={ok} pool_status={pool_status}"
            )
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] outlookEmailPlus claim-complete 失败: {exc}")


def outlook_email_plus_get_email_and_token():
    """从 outlookEmailPlus 邮箱池领取一个邮箱。
    返回 (email, dev_token)，其中 dev_token 为挂起领取上下文的 JSON 串，
    供回写 release/complete 时还原 caller_id/task_id/account_id/claim_token。
    """
    global _outlook_email_plus_pending_claim
    # 上一轮未被回写的领取在这里兜底释放，避免池中账号长期停留在 claimed
    outlook_email_plus_release_pending(reason="verification_retry")
    if not get_outlook_email_plus_api_base():
        raise Exception("outlookEmailPlus API Base 未配置")
    if not get_outlook_email_plus_api_key():
        raise Exception("outlookEmailPlus API Key 未配置")

    task_id = _outlook_email_plus_next_task_id()
    payload = {
        "caller_id": get_outlook_email_plus_caller_id(),
        "task_id": task_id,
    }
    pool_provider = str(config.get("outlook_email_plus_pool_provider", "") or "").strip()
    if pool_provider:
        payload["provider"] = pool_provider
    project_key = str(config.get("outlook_email_plus_project_key", "") or "").strip()
    if project_key:
        payload["project_key"] = project_key
    email_domain = str(config.get("outlook_email_plus_email_domain", "") or "").strip()
    if email_domain and (pool_provider == "cloudflare_temp_mail"):
        payload["email_domain"] = email_domain

    resp = http_post(
        _outlook_email_plus_external_url("/api/external/pool/claim-random"),
        json=payload,
        headers=outlook_email_plus_build_headers(content_type=True),
        timeout=30,
    )
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"outlookEmailPlus claim-random 返回非JSON: {response_preview(resp)}")
    if not data.get("success"):
        code = str(data.get("code") or "")
        msg = str(data.get("message") or "")
        if code == "no_available_account":
            raise Exception("outlookEmailPlus 池中没有可用邮箱")
        raise Exception(f"outlookEmailPlus 领取失败: {code or 'UNKNOWN'} {msg}")
    claim_data = data.get("data") or {}
    email = str(claim_data.get("email") or "").strip()
    if not email:
        raise Exception(f"outlookEmailPlus 领取响应缺少 email: {data}")
    _outlook_email_plus_pending_claim = {
        "account_id": claim_data.get("account_id"),
        "claim_token": claim_data.get("claim_token"),
        "caller_id": get_outlook_email_plus_caller_id(),
        "task_id": task_id,
        "email": email,
    }
    dev_token = json.dumps(
        {
            "account_id": claim_data.get("account_id"),
            "claim_token": claim_data.get("claim_token"),
            "caller_id": get_outlook_email_plus_caller_id(),
            "task_id": task_id,
            "email": email,
        },
        ensure_ascii=False,
    )
    print(f"[*] 已领取 outlookEmailPlus 邮箱: {email}")
    return email, dev_token


def outlook_email_plus_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    """通过 outlookEmailPlus 的 wait-message 接口等待新邮件并提取验证码。

    wait-message 的同步语义：只返回请求发起后才出现的匹配邮件，
    因此天然规避了“拿到旧邮件里的过期验证码”这一风险。

    兜底：wait-message 的 sync 模式存在时序窗口——邮件若在两次请求
    之间的空隙到达，会永远错过。因此每轮 wait-message 返回 404 后，
    再用 GET /api/external/messages 拉取该邮箱的邮件列表，检查是否有
    timestamp >= started_at 的新邮件，有则提取验证码。
    """
    api_base = get_outlook_email_plus_api_base()
    if not api_base:
        raise Exception("outlookEmailPlus API Base 未配置")
    headers = outlook_email_plus_build_headers()
    started_at = time.time() - 5  # 5 秒缓冲，吸收时钟漂移
    deadline = time.time() + timeout
    next_resend_at = time.time() + 35
    wait_seconds = 25
    round_no = 0
    checked_msg_ids = set()  # 已通过兜底检查过的 message ID
    if log_callback:
        log_callback(
            f"[Debug] outlookEmailPlus 拉取验证码开始: email={email} "
            f"timeout={timeout}s wait_seconds={wait_seconds} poll_interval={poll_interval}s "
            f"api_base={api_base}"
        )
    while time.time() < deadline:
        round_no += 1
        remaining = int(deadline - time.time())
        raise_if_cancelled(cancel_callback)
        # 在每一轮等待前触发重新发送验证码（页面端逻辑），与其它 provider 保持一致节奏
        if resend_callback and time.time() >= next_resend_at:
            if log_callback:
                log_callback(f"[Debug] outlookEmailPlus 第{round_no}轮 触发重新发送验证码")
            try:
                resend_callback()
                if log_callback:
                    log_callback(f"[*] outlookEmailPlus 第{round_no}轮 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] outlookEmailPlus 第{round_no}轮 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35

        # 若本次领取已被外部 release/complete，则停止轮询
        if _outlook_email_plus_pending_claim is None and dev_token:
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 领取已回传，停止等待验证码"
                )
            break

        params = {
            "email": email,
            "timeout_seconds": wait_seconds,
            "poll_interval": poll_interval,
            "mode": "sync",
        }
        wait_url = _outlook_email_plus_external_url("/api/external/wait-message")
        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 等待新邮件 "
                f"剩余={remaining}s wait_seconds={wait_seconds} url={wait_url}"
            )
        try:
            resp = http_get(
                wait_url,
                headers=headers,
                params=params,
                timeout=wait_seconds + 15,
            )
        except Exception as exc:
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 wait-message 请求异常: {exc}"
                )
            sleep_with_cancel(poll_interval, cancel_callback)
            continue

        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 wait-message 响应 "
                f"status={resp.status_code} len={len(resp.text or '')}"
            )
        if resp.status_code == 404:
            # 服务端本轮未等到新邮件；用 message-list 兜底检查
            fallback_code = _outlook_email_plus_fallback_list_messages(
                email, started_at, headers, round_no, checked_msg_ids, log_callback
            )
            if fallback_code:
                return fallback_code
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 本轮未等到新邮件(404)，继续下一轮"
                )
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        try:
            data = resp.json()
        except Exception:
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 wait-message 非JSON: {response_preview(resp)}"
                )
            sleep_with_cancel(poll_interval, cancel_callback)
            continue

        if not data.get("success"):
            code = str(data.get("code") or "")
            # 池租约已失效：立即放弃等待
            if code in ("NOT_CLAIMED", "TOKEN_MISMATCH", "CALLER_MISMATCH", "ACCOUNT_NOT_FOUND"):
                if log_callback:
                    log_callback(
                        f"[Debug] outlookEmailPlus 第{round_no}轮 领取已失效: {code} msg={data.get('message')}"
                    )
                break
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 wait-message 失败: {code} {data.get('message')}"
                )
            # 非 404 的失败也走兜底
            fallback_code = _outlook_email_plus_fallback_list_messages(
                email, started_at, headers, round_no, checked_msg_ids, log_callback
            )
            if fallback_code:
                return fallback_code
            sleep_with_cancel(poll_interval, cancel_callback)
            continue

        msg = data.get("data") or {}
        subject = str(msg.get("subject") or "")
        msg_id = msg.get("id") or msg.get("messageId") or msg.get("uid") or ""
        parts = []
        used_fields = []
        for field in ("content", "html_content", "body_preview", "snippet", "text", "raw_content"):
            value = msg.get(field)
            if isinstance(value, str) and value.strip():
                parts.append(value)
                used_fields.append(f"{field}:{len(value)}")
            elif isinstance(value, list):
                for v in value:
                    if isinstance(v, str) and v.strip():
                        parts.append(v)
                        used_fields.append(f"{field}[{len(v)}]")
        combined = "\n".join(parts)
        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 收到邮件: id={msg_id} "
                f"subject={subject} fields=[{','.join(used_fields)}] combined_len={len(combined)}"
            )
        code = extract_verification_code(combined, subject)
        if code:
            if log_callback:
                log_callback(
                    f"[*] outlookEmailPlus 第{round_no}轮 从邮件中提取到验证码: {code}"
                )
            return code
        # 命中新邮件但未能提取出验证码：转下一轮，等待可能的重发邮件
        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 邮件已解析但未提取到验证码，"
                f"继续等待重发 preview={response_preview(resp, 120)}"
            )
        sleep_with_cancel(poll_interval, cancel_callback)
    if log_callback:
        log_callback(
            f"[Debug] outlookEmailPlus 拉取验证码结束: 共{round_no}轮 超时={timeout}s 未收到验证码"
        )
    raise Exception(f"outlookEmailPlus 在 {timeout}s 内未收到验证码邮件")


def _outlook_email_plus_fallback_list_messages(
    email, started_at, headers, round_no, checked_msg_ids, log_callback=None
):
    """wait-message 漏检时的兜底：GET /api/external/messages 拉取邮件列表，
    检查 timestamp >= started_at 的新邮件并提取验证码。

    返回提取到的验证码字符串，或 None。
    """
    try:
        resp = http_get(
            _outlook_email_plus_external_url("/api/external/messages"),
            headers=headers,
            params={"email": email, "limit": "20"},
            timeout=15,
        )
        if resp.status_code >= 400:
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 兜底 messages-list 失败 "
                    f"HTTP {resp.status_code}"
                )
            return None
        data = resp.json()
        if not data.get("success", True) and data.get("code"):
            if log_callback:
                log_callback(
                    f"[Debug] outlookEmailPlus 第{round_no}轮 兜底 messages-list "
                    f"code={data.get('code')} msg={data.get('message')}"
                )
            return None
        emails = (data.get("data") or {}).get("emails") or []
        new_msgs = []
        for m in emails:
            msg_id = str(m.get("id") or "")
            ts = m.get("timestamp") or 0
            try:
                ts = float(ts)
            except Exception:
                ts = 0
            if msg_id and msg_id in checked_msg_ids:
                continue
            if ts and ts >= started_at:
                new_msgs.append(m)
            elif not ts:
                # 没有 timestamp 字段也纳入检查，避免漏码
                new_msgs.append(m)
            if msg_id:
                checked_msg_ids.add(msg_id)
        if not new_msgs:
            return None
        if log_callback:
            subjects = [str(m.get("subject") or "")[:60] for m in new_msgs]
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 兜底发现 {len(new_msgs)} 封新邮件: "
                f"subjects={subjects}"
            )
        for m in new_msgs:
            subject = str(m.get("subject") or "")
            parts = []
            for field in ("content", "content_preview", "html_content", "body_preview", "snippet", "text", "raw_content"):
                value = m.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            combined = "\n".join(parts)
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(
                        f"[*] outlookEmailPlus 第{round_no}轮 兜底从邮件中提取到验证码: {code} "
                        f"subject={subject}"
                    )
                return code
        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 兜底 {len(new_msgs)} 封新邮件均未提取到验证码"
            )
    except Exception as exc:
        if log_callback:
            log_callback(
                f"[Debug] outlookEmailPlus 第{round_no}轮 兜底 messages-list 异常: {exc}"
            )
    return None


def generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def pick_domain(api_key=None):
    domains = get_domains(api_key=api_key)
    if not domains:
        raise Exception("DuckMail 没有返回任何可用域名")
    private = [d for d in domains if d.get("ownerId")]
    verified_private = [d for d in private if d.get("isVerified")]
    if verified_private:
        return verified_private[0]["domain"]
    public = [d for d in domains if d.get("isVerified")]
    if public:
        return public[0]["domain"]
    raise Exception("DuckMail 无已验证域名可用")


def get_email_provider():
    return str(config.get("email_provider", "duckmail") or "duckmail").lower()


def release_email_provider_claim(reason="released", log_callback=None):
    """邮箱 provider 释放当前占用。仅 outlook_email_plus 有池语义，其余为空操作。"""
    if get_email_provider() == "outlook_email_plus":
        outlook_email_plus_release_pending(reason=reason, log_callback=log_callback)


def complete_email_provider_claim(result="success", detail="", log_callback=None):
    """邮箱 provider 回传任务结果。仅 outlook_email_plus 有池语义，其余为空操作。"""
    if get_email_provider() == "outlook_email_plus":
        outlook_email_plus_complete_pending(result=result, detail=detail, log_callback=log_callback)


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    if provider == "outlook_email_plus":
        return outlook_email_plus_get_email_and_token()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            # cloudflare_temp_email 专用模式
            return cloudflare_create_temp_address(api_base)
        except Exception as primary_exc:
            # 兜底回退到 Mail.tm 风格
            key = api_key or get_cloudflare_api_key()
            domains = cloudflare_get_domains(api_base, api_key=key)
            if not domains:
                raise Exception(f"Cloudflare 创建邮箱失败: {primary_exc}")
            verified = [d for d in domains if d.get("isVerified")]
            target = verified[0] if verified else domains[0]
            domain = target.get("domain")
            if not domain:
                raise Exception("Cloudflare 域名数据格式错误，缺少 domain 字段")
            username = generate_username(10)
            address = f"{username}@{domain}"
            password = secrets.token_urlsafe(12)
            cloudflare_create_account(
                api_base, address, password, api_key=key, expires_in=0
            )
            token = cloudflare_get_token(api_base, address, password, api_key=key)
            if not token:
                raise Exception("获取 Cloudflare 邮箱 token 失败")
            return address, token
    key = api_key or get_duckmail_api_key()
    domain = pick_domain(api_key=key)
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(address, password, api_key=key, expires_in=0)
    token = get_token(address, password)
    if not token:
        raise Exception("获取 DuckMail token 失败")
    return address, token


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    provider = get_email_provider()
    if provider == "outlook_email_plus":
        return outlook_email_plus_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def extract_verification_code(text, subject=""):
    if subject:
        match = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    patterns = [
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    deadline = time.time() + timeout
    seen_ids = set()
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if email.lower() not in recipients:
                continue
            try:
                detail = get_message_detail(dev_token, msg_id)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 获取邮件详情失败: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] 从邮件中提取到验证码: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"在 {timeout}s 内未收到验证码邮件")


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    api_base = get_cloudflare_api_base()
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    deadline = time.time() + timeout
    # 同一封邮件正文可能延迟可读，允许多次重试解析，避免偶发漏码
    seen_attempts = {}
    next_resend_at = time.time() + 35
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            messages = cloudflare_get_messages(api_base, dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}")

        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            msg_addr = str(msg.get("address", "")).lower()
            # 优先匹配目标邮箱；若结构不一致也允许继续解析，避免接口字段漂移导致漏码
            address_matched = True
            if recipients:
                address_matched = email.lower() in recipients
            elif msg_addr:
                address_matched = msg_addr == email.lower()
            if not address_matched and log_callback:
                log_callback(f"[Debug] 跳过疑似非目标邮件 id={msg_id} address={msg_addr} to={recipients}")
                continue
            parts = []
            # 先直接从列表项取内容，避免 detail 接口差异导致漏码
            for field in ("text", "raw", "content", "intro", "body", "snippet"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_list = msg.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            # 再尝试 detail 接口补全内容
            try:
                detail = cloudflare_get_message_detail(api_base, dev_token, msg_id)
                for field in ("text", "raw", "content", "intro", "body", "snippet"):
                    value = detail.get(field)
                    if isinstance(value, str) and value.strip():
                        combined += "\n" + value
                html_list2 = detail.get("html") or []
                if isinstance(html_list2, str):
                    html_list2 = [html_list2]
                for h in html_list2:
                    combined += "\n" + re.sub(r"<[^>]+>", " ", h)
                if not subject:
                    subject = str(detail.get("subject", "") or "")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            if log_callback:
                log_callback(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def response_preview(res, limit=200):
    """安全预览 HTTP 响应体；gRPC/二进制内容不直接当文本打印。"""
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(getattr(res, "headers", {}) or {}).items()}
        content_type = headers.get("content-type", "")
        raw = getattr(res, "content", None)
        if raw is None:
            try:
                raw = (res.text or "").encode("utf-8", errors="replace")
            except Exception:
                raw = b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8", errors="replace")
        raw = bytes(raw)

        # gRPC / protobuf 常见 content-type 或正文以不可打印字节为主
        is_binaryish = (
            "grpc" in content_type
            or "protobuf" in content_type
            or "octet-stream" in content_type
            or (raw[:1] in (b"\x00", b"\x01") and b"grpc-status" in raw)
        )
        if is_binaryish or (raw and sum(1 for b in raw[:64] if b < 9 or (13 < b < 32)) > 8):
            # 尽量抽出可读的 trailer 片段（如 grpc-status:0）
            readable = re.findall(rb"[ -~]{3,}", raw)
            text = " ".join(part.decode("ascii", errors="ignore") for part in readable)
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                text = f"<binary {len(raw)} bytes>"
            return text[:limit]

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]
    except Exception:
        return ""


def is_cloudflare_block_response(res):
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(res.headers).items()}
        text = str(res.text or "").lower()
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        return (
            res.status_code in (403, 429, 503)
            and (
                "cloudflare" in server
                or "cloudflare" in text
                or "cf-error" in text
                or "__cf_chl" in text
                or "text/html" in content_type
            )
        )
    except Exception:
        return False


def set_birth_date(session, log_callback=None):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_birth_date 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_birth_date HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_tos_accepted 被 accounts.x.ai 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_tos_accepted HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] update_nsfw status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "update_nsfw_settings 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"update_nsfw_settings HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"


def enable_nsfw_for_token(token, cf_clearance="", user_agent="", log_callback=None):
    proxies = get_proxies()
    # cf_clearance 与签发它的浏览器 UA 严格绑定，优先用注册浏览器的真实 UA
    ua = user_agent or get_user_agent()
    try:
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            cookie_parts = [f"sso={token}", f"sso-rw={token}"]
            if cf_clearance:
                cookie_parts.append(f"cf_clearance={cf_clearance}")
            session.headers.update(
                {
                    "user-agent": ua,
                    "cookie": "; ".join(cookie_parts),
                }
            )
            ok, message = set_tos_accepted(session, log_callback)
            if not ok:
                return False, message
            ok, message = set_birth_date(session, log_callback)
            if not ok:
                return False, message
            ok, message = update_nsfw_settings(session, log_callback)
            if not ok:
                return False, message
            return True, "成功开启 NSFW"
    except Exception as e:
        return False, f"异常: {str(e)}"


SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"

browser = None
page = None


def setup_light_theme(root):
    try:
        root.option_add("*Background", UI_BG)
        root.option_add("*Foreground", UI_FG)
        root.option_add("*selectBackground", UI_ACTIVE_BG)
        root.option_add("*selectForeground", UI_FG)
        root.option_add("*insertBackground", UI_FG)
        root.option_add("*Entry.Background", UI_ENTRY_BG)
        root.option_add("*Text.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Foreground", UI_FG)
        style = ttk.Style(root)
        available = set(style.theme_names())
        if "clam" in available:
            style.theme_use("clam")
        elif "default" in available:
            style.theme_use("default")
        root.configure(bg=UI_BG)
        style.configure(".", background=UI_BG, foreground=UI_FG, fieldbackground=UI_ENTRY_BG)
        style.configure("TFrame", background=UI_BG)
        style.configure("TLabelframe", background=UI_BG, foreground=UI_FG)
        style.configure("TLabelframe.Label", background=UI_BG, foreground=UI_FG)
        style.configure("TLabel", background=UI_BG, foreground=UI_FG)
        style.configure("TCheckbutton", background=UI_BG, foreground=UI_FG)
        style.configure("TButton", background=UI_BUTTON_BG, foreground=UI_FG)
        style.configure("TEntry", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TCombobox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TSpinbox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
    except Exception:
        pass


def tk_label(parent, text="", **kwargs):
    return tk.Label(parent, text=text, bg=kwargs.pop("bg", UI_BG), fg=kwargs.pop("fg", UI_FG), **kwargs)


def tk_entry(parent, textvariable=None, width=30, **kwargs):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        insertbackground=UI_FG,
        disabledbackground="#2f2f2f",
        disabledforeground=UI_MUTED_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
        **kwargs,
    )


def tk_button(parent, text="", command=None, state=tk.NORMAL, **kwargs):
    return tk.Button(
        parent,
        text=text,
        command=command,
        state=state,
        bg=UI_BUTTON_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        disabledforeground="#777777",
        relief=tk.RAISED,
        padx=10,
        pady=3,
        **kwargs,
    )


def tk_checkbutton(parent, text="", variable=None, **kwargs):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=UI_BG,
        fg=UI_FG,
        activebackground=UI_BG,
        activeforeground=UI_FG,
        selectcolor="#3d7be0",
        **kwargs,
    )


def tk_option_menu(parent, variable, values, width=12):
    menu = tk.OptionMenu(parent, variable, *values)
    menu.configure(
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
    )
    menu["menu"].configure(bg=UI_ENTRY_BG, fg=UI_FG, activebackground=UI_ACTIVE_BG, activeforeground=UI_FG)
    return menu


def start_browser(log_callback=None):
    global browser, page
    last_exc = None
    for attempt in range(1, 5):
        try:
            browser = Chromium(create_browser_options())
            tabs = browser.get_tabs()
            page = tabs[-1] if tabs else browser.new_tab()
            if log_callback and getattr(browser, "user_data_path", None):
                log_callback(f"[Debug] 当前浏览器资料目录: {browser.user_data_path}")
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return browser, page
        except Exception as exc:
            last_exc = exc
            if log_callback:
                log_callback(f"[Debug] 浏览器启动失败(第{attempt}/4次): {exc}")
            try:
                if browser is not None:
                    browser.quit(del_data=True)
            except Exception:
                pass
            browser = None
            page = None
            time.sleep(min(1.5 * attempt, 4))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser():
    global browser, page
    current = browser
    browser = None
    page = None
    if current is None:
        return
    try:
        current.quit(del_data=True)
    except BaseException:
        # KeyboardInterrupt 继承 BaseException，清理阶段必须吞掉，避免 Ctrl+C 刷 traceback
        pass


def restart_browser(log_callback=None):
    stop_browser()
    return start_browser(log_callback=log_callback)


def cleanup_runtime_memory(log_callback=None, reason="定期清理"):
    try:
        if log_callback:
            log_callback(f"[*] {reason}: 关闭浏览器并清理内存")
        stop_browser()
        collected = gc.collect()
        if log_callback:
            log_callback(f"[*] Python GC 已回收对象数: {collected}")
    except BaseException:
        # 退出清理中再收到 Ctrl+C 时静默结束，不向外抛
        try:
            stop_browser()
        except BaseException:
            pass


def refresh_active_page():
    global browser, page
    if browser is None:
        restart_browser()
    try:
        tabs = browser.get_tabs()
        if tabs:
            page = tabs[-1]
        else:
            page = browser.new_tab()
    except Exception:
        restart_browser()
    return page


def extract_cf_clearance_and_ua(log_callback=None):
    """从注册浏览器提取 grok.com 的 cf_clearance 及其绑定的真实 UA。

    注册流程能拿到 sso 说明浏览器已通过 grok.com 的 Cloudflare 盾，
    此刻 cf_clearance 就在浏览器 cookie 里，配合真实 UA 可用于后续 NSFW 请求。

    返回:
      - (cf_clearance str, user_agent str)：任一取不到则为空字符串
    """
    cf_clearance = ""
    user_agent = ""
    try:
        active = refresh_active_page()
        if active is None:
            return "", ""
        cookies = active.cookies(all_domains=True, all_info=True) or []
        for item in cookies:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                value = str(item.get("value", "")).strip()
            else:
                name = str(getattr(item, "name", "")).strip()
                value = str(getattr(item, "value", "")).strip()
            if name == "cf_clearance" and value:
                cf_clearance = value
                break
        try:
            ua = active.run_js("return navigator.userAgent;")
            if ua:
                user_agent = str(ua).strip()
        except Exception:
            pass
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 提取 cf_clearance 失败: {exc}")
    return cf_clearance, user_agent


def click_email_signup_button(timeout=10, log_callback=None, cancel_callback=None):
    global page
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if log_callback:
            log_callback("[Debug] 尝试查找“使用邮箱注册”按钮...")

        clicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    if (compact.includes('使用邮箱注册')) return 100;
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
const target = candidates[0]?.node || null;
if (!target) {
    return false;
}
target.click();
return candidates[0].text || true;
        """)

        if clicked:
            if log_callback:
                detail = f": {clicked}" if isinstance(clicked, str) else ""
                log_callback(f"[*] 已点击「使用邮箱注册」按钮{detail}")
            sleep_with_cancel(2, cancel_callback)
            return True

        if log_callback:
            current_url = page.url if page else "none"
            log_callback(f"[Debug] 当前URL: {current_url}")

        sleep_with_cancel(1, cancel_callback)

    if log_callback:
        page_html = page.html[:500] if page else "no page"
        log_callback(f"[Debug] 页面内容片段: {page_html}")

    raise Exception("未找到「使用邮箱注册」按钮")


def open_signup_page(log_callback=None, cancel_callback=None):
    global browser, page
    raise_if_cancelled(cancel_callback)
    if browser is None:
        start_browser()
        if log_callback:
            log_callback("[*] 浏览器已启动")
    try:
        page = browser.get_tab(0)
        page.get(SIGNUP_URL)
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        try:
            page = browser.new_tab(SIGNUP_URL)
        except Exception as e2:
            if log_callback:
                log_callback(f"[Debug] 创建新标签页异常: {e2}")
            restart_browser()
            page = browser.new_tab(SIGNUP_URL)
    page.wait.doc_loaded()
    sleep_with_cancel(2, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {page.url}")
    click_email_signup_button(
        log_callback=log_callback, cancel_callback=cancel_callback
    )


def has_profile_form(log_callback=None):
    refresh_active_page()
    try:
        return bool(
            page.run_js(
                """
const givenInput = document.querySelector('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"]');
const familyInput = document.querySelector('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"]');
const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"]');
return !!(givenInput && familyInput && passwordInput);
            """
            )
        )
    except Exception:
        return False


def _email_page_advanced_once(email):
    """检测邮箱提交后页面是否真正前进（离开邮箱输入阶段）。

    点击注册按钮只代表触发了点击，不代表表单真的提交成功。
    若 Cloudflare 挑战未过或页面卡住，按钮点击无实际效果，
    邮箱输入框会一直停留，导致后续空等验证码。

    判定“已前进”的依据：
      - 出现验证码输入框（OTP / code 输入），或
      - 原本可见可用的邮箱输入框已消失/不可用

    返回:
      - True：页面已前进，提交生效
      - False：仍停留在邮箱输入页
    """
    try:
        return bool(
            page.run_js(
                """
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.getAttribute('aria-label'),
        node.getAttribute('placeholder'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
        node.getAttribute('data-testid'),
    ].filter(Boolean).join(' ').replace(/\\s+/g, ' ').trim().toLowerCase();
}
// 1. 出现验证码输入框 => 已前进
const codeInput = Array.from(document.querySelectorAll('input')).find((node) => {
    if (!isVisible(node)) return false;
    const type = (node.getAttribute('type') || '').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(type)) return false;
    const meta = textOf(node);
    const inMode = (node.getAttribute('inputmode') || '').toLowerCase();
    return (
        meta.includes('code') || meta.includes('otp') || meta.includes('verif') ||
        meta.includes('验证') || meta.includes('one-time') || inMode === 'numeric' ||
        node.getAttribute('autocomplete') === 'one-time-code'
    );
});
if (codeInput) return true;
// 2. 邮箱输入框已消失/不可用 => 已前进
const emailInput = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'))
    .find((node) => isVisible(node) && !node.disabled && !node.readOnly);
if (!emailInput) return true;
return false;
                """
            )
        )
    except Exception:
        return False


def _wait_email_page_advanced(email, wait=4.0, cancel_callback=None):
    """点击提交后，在有限窗口内轮询确认页面确实前进。

    给页面/网络一点反应时间：若窗口内检测到已前进则返回 True，
    否则返回 False，由调用方继续重试点击或最终超时换邮箱。
    """
    deadline = time.time() + wait
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if _email_page_advanced_once(email):
            return True
        sleep_with_cancel(0.4, cancel_callback)
    return False


def fill_email_and_submit(timeout=45, log_callback=None, cancel_callback=None):
    raise_if_cancelled(cancel_callback)
    email, dev_token = get_email_and_token()
    if not email or not dev_token:
        raise Exception("获取邮箱失败")
    if log_callback:
        log_callback(f"[*] 已创建邮箱: {email}")
    deadline = time.time() + timeout
    last_diag_time = 0
    last_reclick_time = 0
    last_snapshot = None
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            r"""
const email = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function describeInput(node) {
    return [
        `type=${node.getAttribute('type') || ''}`,
        `name=${node.getAttribute('name') || ''}`,
        `id=${node.getAttribute('id') || ''}`,
        `placeholder=${node.getAttribute('placeholder') || ''}`,
        `aria=${node.getAttribute('aria-label') || ''}`,
        `testid=${node.getAttribute('data-testid') || ''}`,
    ].join(' ').replace(/\s+/g, ' ').trim().slice(0, 160);
}
function describeAction(node) {
    return textOf(node).slice(0, 120);
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const visibleInputs = Array.from(document.querySelectorAll('input, textarea'))
    .filter((node) => isVisible(node) && !node.disabled && !node.readOnly)
    .map(describeInput)
    .slice(0, 8);
const visibleActions = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map(describeAction)
    .filter(Boolean)
    .slice(0, 10);
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input) {
    return {
        state: 'not-ready',
        url: location.href,
        title: document.title,
        inputs: visibleInputs,
        buttons: visibleActions,
    };
}
input.focus(); input.click();
const valueProto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
const valueSetter = Object.getOwnPropertyDescriptor(valueProto, 'value')?.set;
const tracker = input._valueTracker;
if (tracker) tracker.setValue('');
if (valueSetter) valueSetter.call(input, email); else input.value = email;
input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new InputEvent('input', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
const inputType = (input.getAttribute('type') || '').toLowerCase();
const isValid = inputType !== 'email' || input.checkValidity();
if ((input.value || '').trim() !== email || !isValid) {
    return {
        state: 'fill-failed',
        value: input.value || '',
        valid: isValid,
        input: describeInput(input),
        url: location.href,
    };
}
input.blur();
return {
    state: 'filled',
    input: describeInput(input),
    url: location.href,
};
            """,
            email,
        )
        state = filled.get("state") if isinstance(filled, dict) else filled
        if isinstance(filled, dict):
            last_snapshot = filled
        if state == "not-ready":
            now = time.time()
            if now - last_reclick_time >= 3:
                reclicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    if (compact.includes('使用邮箱注册')) return 100;
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
if (!candidates.length) return false;
candidates[0].node.click();
return candidates[0].text || true;
                """)
                last_reclick_time = now
                if reclicked and log_callback:
                    detail = f": {reclicked}" if isinstance(reclicked, str) else ""
                    log_callback(f"[Debug] 邮箱输入框未出现，已再次触发邮箱注册入口{detail}")
            if log_callback and now - last_diag_time >= 5:
                last_diag_time = now
                inputs = " | ".join((filled or {}).get("inputs", [])[:6]) if isinstance(filled, dict) else ""
                buttons = " | ".join((filled or {}).get("buttons", [])[:8]) if isinstance(filled, dict) else ""
                url = (filled or {}).get("url", page.url if page else "") if isinstance(filled, dict) else (page.url if page else "")
                log_callback(f"[Debug] 等待邮箱输入框: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if state != "filled":
            if log_callback:
                log_callback(f"[Debug] 邮箱输入框已出现，但写入失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        sleep_with_cancel(0.8, cancel_callback)
        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input || !(input.value || '').trim()) return false;
const inputType = (input.getAttribute('type') || '').toLowerCase();
if (inputType === 'email' && !input.checkValidity()) return false;
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true');
const submitButton = buttons.find((node) => {
    const text = textOf(node).replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text === '注册' ||
        text.includes('注册') ||
        text.includes('继续') ||
        text.includes('下一步') ||
        text.includes('确认') ||
        lower.includes('signup') ||
        lower.includes('sign up') ||
        lower.includes('continue') ||
        lower.includes('next') ||
        lower.includes('createaccount') ||
        lower.includes('submit')
    );
});
if (submitButton) {
    submitButton.click();
    return textOf(submitButton) || true;
}
const form = input.closest('form');
if (form) {
    if (form.requestSubmit) form.requestSubmit();
    else form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    return 'form-submit';
}
input.focus();
input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
input.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
return 'enter';
            """
        )
        if clicked:
            # 点击按钮 != 表单真正提交成功：CF 挑战未过或页面卡住时点击无效果，
            # 邮件不会发出。必须确认页面已离开邮箱输入阶段（邮箱框消失或出现验证码框），
            # 否则继续循环重试点击，最终超时抛异常触发换邮箱重试。
            if _wait_email_page_advanced(email, cancel_callback=cancel_callback):
                if log_callback:
                    detail = f" ({clicked})" if isinstance(clicked, str) else ""
                    log_callback(f"[*] 已填写邮箱并提交: {email}{detail}")
                return email, dev_token
            if log_callback and time.time() - last_diag_time >= 5:
                last_diag_time = time.time()
                log_callback(f"[Debug] 已点击注册但页面未前进，重试提交: {email}")
        sleep_with_cancel(0.5, cancel_callback)
    if last_snapshot:
        inputs = " | ".join(last_snapshot.get("inputs", [])[:6])
        buttons = " | ".join(last_snapshot.get("buttons", [])[:8])
        url = last_snapshot.get("url", page.url if page else "")
        raise Exception(
            f"未找到邮箱输入框或注册按钮，最后页面: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}"
        )
    raise Exception("未找到邮箱输入框或注册按钮")


def fill_code_and_submit(email, dev_token, timeout=180, log_callback=None, cancel_callback=None):
    def _resend_code():
        page.run_js(
            r"""
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = nodes.find((node) => {
  const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
  return t.includes('重新发送') || t.includes('resend') || t.includes('再次发送');
});
if (target && !target.disabled) { target.click(); return true; }
return false;
            """
        )

    code = get_oai_code(
        dev_token,
        email,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=_resend_code,
    )
    if not code:
        raise Exception("获取验证码失败")
    clean_code = str(code).replace("-", "").strip()
    deadline = time.time() + timeout

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            """
const code = String(arguments[0] || '').trim();
if (!code) return 'empty-code';

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function setInputValue(input, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

const aggregate = Array.from(document.querySelectorAll(
  'input[data-input-otp=\"true\"], input[name=\"code\"], input[autocomplete=\"one-time-code\"], input[inputmode=\"numeric\"], input[inputmode=\"text\"]'
)).find((node) => isVisible(node) && !node.disabled && !node.readOnly && Number(node.maxLength || 6) > 1);

if (aggregate) {
    aggregate.focus();
    aggregate.click();
    setInputValue(aggregate, code);
    return String(aggregate.value || '').replace(/\\s+/g, '') ? 'filled-aggregate' : 'aggregate-failed';
}

const otpBoxes = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const maxLength = Number(node.maxLength || 0);
    const ac = String(node.autocomplete || '').toLowerCase();
    return maxLength === 1 || ac === 'one-time-code';
});

if (otpBoxes.length >= code.length) {
    for (let i = 0; i < code.length; i += 1) {
        const ch = code[i] || '';
        const box = otpBoxes[i];
        box.focus();
        box.click();
        setInputValue(box, ch);
        box.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ch }));
        box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ch }));
    }
    const merged = otpBoxes.slice(0, code.length).map((x) => String(x.value || '').trim()).join('');
    return merged.length ? 'filled-boxes' : 'boxes-failed';
}

return 'not-ready';
            """,
            clean_code,
        )

        if filled == "not-ready":
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if "failed" in str(filled):
            if log_callback:
                log_callback(f"[Debug] 验证码填写失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue

        clicked = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const buttons = Array.from(document.querySelectorAll('button[type=\"submit\"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});

const btn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return (
        t.includes('确认邮箱') ||
        t.includes('继续') ||
        t.includes('下一步') ||
        t.includes('confirm') ||
        t.includes('continue') ||
        t.includes('next')
    );
});

if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
            """
        )

        if clicked == "clicked" or clicked == "no-button":
            if log_callback:
                log_callback(f"[*] 已填写验证码并提交: {code}")
            sleep_with_cancel(1.5, cancel_callback)
            return code

        sleep_with_cancel(0.5, cancel_callback)

    raise Exception("验证码已获取，但自动填写/提交失败")


def getTurnstileToken(log_callback=None, cancel_callback=None):
    global page
    if page is None:
        raise Exception("页面未就绪，无法执行 Turnstile")

    try:
        page.run_js(
            "try { if (window.turnstile && typeof turnstile.reset === 'function') turnstile.reset(); } catch(e) {}"
        )
    except Exception:
        pass

    for _ in range(0, 20):
        raise_if_cancelled(cancel_callback)
        try:
            token = page.run_js(
                """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
                """
            )
            token = str(token or "").strip()
            if len(token) >= 80:
                if log_callback:
                    log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
                return token

            challenge_input = page.ele("@name=cf-turnstile-response")
            if challenge_input:
                wrapper = challenge_input.parent()
                iframe = None
                try:
                    iframe = wrapper.shadow_root.ele("tag:iframe")
                except Exception:
                    iframe = None
                if iframe:
                    try:
                        iframe.run_js(
                            """
window.dtp = 1;
function getRandomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
let sx = getRandomInt(800, 1200);
let sy = getRandomInt(400, 700);
Object.defineProperty(MouseEvent.prototype, 'screenX', { value: sx });
Object.defineProperty(MouseEvent.prototype, 'screenY', { value: sy });
                            """
                        )
                    except Exception:
                        pass
                    try:
                        body_sr = iframe.ele("tag:body").shadow_root
                        btn = body_sr.ele("tag:input")
                        if btn:
                            btn.click()
                    except Exception:
                        pass
            else:
                # 兜底：尝试触发页面上可见的 Turnstile 容器
                page.run_js(
                    """
const nodes = Array.from(document.querySelectorAll('div,span,iframe')).filter((n) => {
  const txt = (n.className || '') + ' ' + (n.id || '') + ' ' + (n.getAttribute?.('src') || '');
  return String(txt).toLowerCase().includes('turnstile');
});
if (nodes.length && typeof nodes[0].click === 'function') nodes[0].click();
                    """
                )
        except Exception:
            pass
        sleep_with_cancel(1, cancel_callback)

    raise Exception("Turnstile 获取 token 失败")


def build_profile():
    given_name_pool = [
        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",
        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",
        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",
        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",
        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",
        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",
        "Aaron", "Damian",
    ]
    family_name_pool = [
        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",
        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",
        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",
        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",
        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",
        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",
        "Wei", "Xiong",
    ]
    given_name = random.choice(given_name_pool)
    family_name = random.choice(family_name_pool)
    password = "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)
    return given_name, family_name, password


def fill_profile_and_submit(timeout=120, log_callback=None, cancel_callback=None):
    given_name, family_name, password = build_profile()
    deadline = time.time() + timeout
    form_filled_once = False
    wait_cf_since = None
    last_cf_retry_at = 0.0

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if not form_filled_once:
            filled = page.run_js(
                """
const givenName = arguments[0];
const familyName = arguments[1];
const password = arguments[2];

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function pickInput(selector) {
    return Array.from(document.querySelectorAll(selector)).find((node) => {
        return isVisible(node) && !node.disabled && !node.readOnly;
    }) || null;
}

function setInputValue(input, value) {
    if (!input) return false;
    input.focus();
    input.click();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.blur();
    return String(input.value || '').trim() === String(value || '').trim();
}

const givenInput = pickInput('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"], input[aria-label*="名"]');
const familyInput = pickInput('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"], input[aria-label*="姓"]');
const passwordInput = pickInput('input[data-testid="password"], input[name="password"], input[type="password"], input[autocomplete="new-password"]');

if (!givenInput || !familyInput || !passwordInput) return 'not-ready';

const ok1 = setInputValue(givenInput, givenName);
const ok2 = setInputValue(familyInput, familyName);
const ok3 = setInputValue(passwordInput, password);

if (!ok1 || !ok2 || !ok3) return 'fill-failed';

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});

// 必须等待 Cloudflare 校验通过后再提交
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

if (submitBtn) {
    return 'ready-to-submit';
}
return 'filled-no-submit';
            """,
                given_name,
                family_name,
                password,
            )

            if isinstance(filled, str) and filled.startswith("wait-cloudflare"):
                form_filled_once = True
                if log_callback:
                    token_len = filled.split(":", 1)[1] if ":" in filled else "0"
                    log_callback(f"[*] 资料已填写，等待 Cloudflare 人机验证通过... 当前token长度={token_len}")
                if token_len == "0":
                    pause_seconds = random.uniform(1, 3)
                    if log_callback:
                        log_callback(f"[*] Cloudflare token 为空，暂停 {pause_seconds:.1f}s 后继续检测")
                    sleep_with_cancel(pause_seconds, cancel_callback)
                now = time.time()
                if wait_cf_since is None:
                    wait_cf_since = now
                # 卡住后自动二次复用 Turnstile 组件
                if now - wait_cf_since >= 12 and now - last_cf_retry_at >= 8:
                    if log_callback:
                        log_callback("[*] Cloudflare 验证卡住，开始二次复用 Turnstile...")
                    try:
                        token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                        if token:
                            synced = page.run_js(
                                """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                                """,
                                token,
                            )
                            if log_callback:
                                log_callback(f"[*] Turnstile 二次复用完成，回填长度={synced}")
                    except Exception as cf_exc:
                        if log_callback:
                            log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                    last_cf_retry_at = now
                sleep_with_cancel(0.8, cancel_callback)
                continue

            if filled in ("ready-to-submit", "filled-no-submit"):
                form_filled_once = True
            elif filled == "fill-failed" and log_callback:
                log_callback("[Debug] 资料输入失败，重试中...")
                sleep_with_cancel(0.5, cancel_callback)
                continue
            elif filled == "not-ready":
                sleep_with_cancel(0.5, cancel_callback)
                continue

        submit_state = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});
if (!submitBtn) {
    const visibleTexts = buttons.map(buttonText).filter(Boolean).slice(0, 8).join(' | ');
    return 'no-submit-button:' + visibleTexts;
}
submitBtn.focus();
submitBtn.click();
return 'submitted';
            """
        )

        if isinstance(submit_state, str) and submit_state.startswith("wait-cloudflare"):
            if log_callback:
                token_len = submit_state.split(":", 1)[1] if ":" in submit_state else "0"
                log_callback(f"[*] 等待 Cloudflare 人机验证通过后再提交... 当前token长度={token_len}")
            now = time.time()
            if wait_cf_since is None:
                wait_cf_since = now
            if now - wait_cf_since >= 12 and now - last_cf_retry_at >= 8:
                if log_callback:
                    log_callback("[*] 提交前仍卡住，自动再次复用 Turnstile...")
                try:
                    token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                    if token:
                        synced = page.run_js(
                            """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                            """,
                            token,
                        )
                        if log_callback:
                            log_callback(f"[*] Turnstile 二次复用完成，回填长度={synced}")
                except Exception as cf_exc:
                    if log_callback:
                        log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
                last_cf_retry_at = now
            sleep_with_cancel(0.8, cancel_callback)
            continue

        if submit_state == "submitted":
            if log_callback:
                log_callback(f"[*] 已填写注册资料并提交: {given_name} {family_name}")
            return {"given_name": given_name, "family_name": family_name, "password": password}
        wait_cf_since = None
        if isinstance(submit_state, str) and submit_state.startswith("no-submit-button") and log_callback:
            visible_buttons = submit_state.split(":", 1)[1] if ":" in submit_state else ""
            suffix = f" 可见按钮: {visible_buttons}" if visible_buttons else ""
            log_callback(f"[Debug] 未找到提交按钮，继续等待页面稳定...{suffix}")

        sleep_with_cancel(0.5, cancel_callback)

    raise Exception("最终注册页资料填写失败")


def wait_for_sso_cookie(timeout=120, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    last_seen_names = set()
    last_submit_retry = 0.0
    last_cf_retry_at = 0.0
    final_no_submit_state = ""
    final_no_submit_since = None
    final_no_submit_timeout = 25

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            refresh_active_page()
            if page is None:
                sleep_with_cancel(1, cancel_callback)
                continue

            # 仍停留在“完成注册”页时，若 Cloudflare 已通过，周期性重试点击提交
            now = time.time()
            if now - last_submit_retry >= 2.5:
                retried = page.run_js(
                    r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const titleHit = !!Array.from(document.querySelectorAll('h1,h2,div,span')).find((el) => {
    const t = (el.textContent || '').replace(/\s+/g, '');
    const lower = t.toLowerCase();
    return t.includes('完成注册') || lower.includes('completeyoursignup') || lower.includes('completesignup');
});
if (!titleHit) return 'not-final-page';

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solved = token.length >= 80;
    if (!solved) return 'final-page-wait-cf:' + token.length;
}

function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount');
});
if (!submitBtn) {
    const visibleTexts = buttons.map(buttonText).filter(Boolean).slice(0, 8).join(' | ');
    return 'final-page-no-submit:' + visibleTexts;
}
submitBtn.focus();
submitBtn.click();
return 'final-page-clicked-submit';
                    """
                )
                last_submit_retry = now
                if log_callback and (retried == "final-page-clicked-submit" or (isinstance(retried, str) and retried.startswith("final-page-no-submit"))):
                    log_callback(f"[Debug] 最终页状态: {retried}")
                if isinstance(retried, str) and retried.startswith("final-page-no-submit"):
                    if retried != final_no_submit_state:
                        final_no_submit_state = retried
                        final_no_submit_since = now
                    elif final_no_submit_since and now - final_no_submit_since >= final_no_submit_timeout:
                        raise AccountRetryNeeded(
                            f"最终注册页状态 {final_no_submit_timeout}s 未变化且未找到提交按钮，重试当前账号: {retried}"
                        )
                else:
                    final_no_submit_state = ""
                    final_no_submit_since = None
                if log_callback and isinstance(retried, str) and retried.startswith("final-page-wait-cf"):
                    token_len = retried.split(":", 1)[1] if ":" in retried else "0"
                    log_callback(f"[Debug] 最终页状态: final-page-wait-cf, token长度={token_len}")
                    if now - last_cf_retry_at >= 10:
                        if log_callback:
                            log_callback("[*] 最终页 Cloudflare 卡住，自动二次复用 Turnstile...")
                        try:
                            token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
                            if token:
                                synced = page.run_js(
                                    """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                                    """,
                                    token,
                                )
                                if log_callback:
                                    log_callback(f"[*] 最终页 Turnstile 二次复用完成，回填长度={synced}")
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] 最终页 Turnstile 二次复用失败: {cf_exc}")
                        last_cf_retry_at = now

            cookies = page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()

                if name:
                    last_seen_names.add(name)

                if name == "sso" and value:
                    if log_callback:
                        log_callback("[*] 已获取到 sso cookie")
                    return value
        except PageDisconnectedError:
            refresh_active_page()
        except AccountRetryNeeded:
            raise
        except RegistrationCancelled:
            raise
        except Exception:
            pass

        sleep_with_cancel(1, cancel_callback)

    raise Exception(
        f"等待超时：未获取到 sso cookie。已看到 cookies: {sorted(last_seen_names)}"
    )


class GrokRegisterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Grok 注册机")
        self.root.geometry("1120x900")
        self.root.minsize(960, 700)
        self.is_running = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.setup_ui()

    def setup_ui(self):
        load_config()
        main_frame = tk.Frame(self.root, bg=UI_BG, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

        config_frame = tk.LabelFrame(
            main_frame,
            text="配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=10,
            pady=10,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        config_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 8))
        config_frame.grid_columnconfigure(1, weight=1, minsize=260)
        config_frame.grid_columnconfigure(3, weight=1, minsize=260)

        def add_label(row, column, text):
            tk_label(config_frame, text=text, bg=UI_PANEL_BG).grid(
                row=row,
                column=column,
                sticky=tk.W,
                padx=(0, 6),
                pady=3,
            )

        def add_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )

        add_label(0, 0, "邮箱服务商:")
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "duckmail"))
        self.email_provider_combo = tk_option_menu(config_frame, self.email_provider_var, ["duckmail", "yyds", "cloudflare", "outlook_email_plus"], width=12)
        add_field(self.email_provider_combo, 0, 1, sticky=tk.W)

        add_label(0, 2, "注册数量:")
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.count_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=2500,
            width=8,
            textvariable=self.count_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.count_spinbox, 0, 3, sticky=tk.W)

        add_label(1, 0, "注册选项:")
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = tk_checkbutton(config_frame, text="注册后开启 NSFW", variable=self.nsfw_var)
        add_field(self.nsfw_check, 1, 1, sticky=tk.W)

        add_label(1, 2, "代理（可选）:")
        self.proxy_var = tk.StringVar(value=config.get("proxy", ""))
        self.proxy_entry = tk_entry(config_frame, textvariable=self.proxy_var, width=34)
        add_field(self.proxy_entry, 1, 3)

        add_label(2, 0, "DuckMail API Key:")
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.api_key_entry = tk_entry(config_frame, textvariable=self.api_key_var, width=34)
        add_field(self.api_key_entry, 2, 1)

        add_label(2, 2, "Cloudflare 鉴权模式:")
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "none"))
        self.cloudflare_auth_mode_combo = tk_option_menu(
            config_frame, self.cloudflare_auth_mode_var, ["query-key", "bearer", "x-api-key", "x-admin-auth", "none"], width=12
        )
        add_field(self.cloudflare_auth_mode_combo, 2, 3, sticky=tk.W)

        add_label(3, 0, "Cloudflare API Base:")
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_base_entry = tk_entry(config_frame, textvariable=self.cloudflare_api_base_var, width=72)
        add_field(self.cloudflare_api_base_entry, 3, 1, columnspan=3)

        add_label(4, 0, "Cloudflare API Key:")
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_api_key_entry = tk_entry(config_frame, textvariable=self.cloudflare_api_key_var, width=34)
        add_field(self.cloudflare_api_key_entry, 4, 1)

        add_label(4, 2, "CF 路径:")
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/api/domains"),
                    config.get("cloudflare_path_accounts", "/api/new_address"),
                    config.get("cloudflare_path_token", "/api/token"),
                    config.get("cloudflare_path_messages", "/api/mails"),
                ]
            )
        )
        self.cloudflare_paths_entry = tk_entry(config_frame, textvariable=self.cloudflare_paths_var, width=34)
        add_field(self.cloudflare_paths_entry, 4, 3)

        add_label(5, 0, "CPA 直出(SSO→auth):")
        self.cpa_auto_add_var = tk.BooleanVar(value=bool(config.get("cpa_auto_add", False)))
        self.cpa_auto_add_check = tk_checkbutton(config_frame, variable=self.cpa_auto_add_var)
        add_field(self.cpa_auto_add_check, 5, 1, sticky=tk.W)

        add_label(6, 0, "CPA auth 目录:")
        self.cpa_auth_dir_var = tk.StringVar(value=str(config.get("cpa_auth_dir", "")))
        self.cpa_auth_dir_entry = tk_entry(config_frame, textvariable=self.cpa_auth_dir_var, width=72)
        add_field(self.cpa_auth_dir_entry, 6, 1, columnspan=3)

        add_label(7, 0, "CPA 远程地址:")
        self.cpa_remote_url_var = tk.StringVar(value=str(config.get("cpa_remote_url", "")))
        self.cpa_remote_url_entry = tk_entry(config_frame, textvariable=self.cpa_remote_url_var, width=40)
        add_field(self.cpa_remote_url_entry, 7, 1)

        add_label(7, 2, "CPA 管理密钥:")
        self.cpa_management_key_var = tk.StringVar(value=str(config.get("cpa_management_key", "")))
        self.cpa_management_key_entry = tk_entry(config_frame, textvariable=self.cpa_management_key_var, width=28)
        add_field(self.cpa_management_key_entry, 7, 3)

        add_label(8, 0, "outlookEmailPlus API Base:")
        self.outlook_email_plus_api_base_var = tk.StringVar(value=str(config.get("outlook_email_plus_api_base", "")))
        self.outlook_email_plus_api_base_entry = tk_entry(config_frame, textvariable=self.outlook_email_plus_api_base_var, width=72)
        add_field(self.outlook_email_plus_api_base_entry, 8, 1, columnspan=3)

        add_label(9, 0, "outlookEmailPlus API Key:")
        self.outlook_email_plus_api_key_var = tk.StringVar(value=str(config.get("outlook_email_plus_api_key", "")))
        self.outlook_email_plus_api_key_entry = tk_entry(config_frame, textvariable=self.outlook_email_plus_api_key_var, width=34)
        add_field(self.outlook_email_plus_api_key_entry, 9, 1)

        add_label(9, 2, "outlookEmailPlus caller_id:")
        self.outlook_email_plus_caller_id_var = tk.StringVar(value=str(config.get("outlook_email_plus_caller_id", "grok-register")))
        self.outlook_email_plus_caller_id_entry = tk_entry(config_frame, textvariable=self.outlook_email_plus_caller_id_var, width=34)
        add_field(self.outlook_email_plus_caller_id_entry, 9, 3)

        btn_frame = tk.Frame(main_frame, bg=UI_BG)
        btn_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 6))
        self.start_btn = tk_button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk_button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = tk_button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(main_frame, bg=UI_BG)
        status_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 6))
        self.status_var = tk.StringVar(value="就绪")
        tk_label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, bg=UI_BG, fg="green")
        self.status_label.pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        tk.Label(status_frame, textvariable=self.stats_var, bg=UI_BG, fg=UI_FG).pack(side=tk.RIGHT)
        log_frame = tk.LabelFrame(
            main_frame,
            text="日志",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=5,
            pady=5,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        log_frame.grid(row=3, column=0, sticky=tk.NSEW)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            width=60,
            bg="#111111",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
            selectbackground="#345a8a",
            selectforeground="#ffffff",
            relief=tk.SOLID,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#555555",
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.log("[*] GUI 已就绪，配置已加载")
        self.log(f"[*] 当前邮箱服务商: {self.email_provider_var.get()} | 注册数量: {self.count_var.get()}")

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        print(line, flush=True)
        self.log_text.insert(tk.END, f"{line}\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        self.stats_var.set(f"成功: {self.success_count} | 失败: {self.fail_count}")

    def _set_running_ui(self, running):
        self.is_running = running
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def should_stop(self):
        return self.stop_requested or not self.is_running

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return

        config["email_provider"] = self.email_provider_var.get().strip() or "duckmail"
        config["enable_nsfw"] = bool(self.nsfw_var.get())
        config["proxy"] = self.proxy_var.get().strip()
        config["duckmail_api_key"] = self.api_key_var.get().strip()
        config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
        config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
        config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
        config["cpa_auto_add"] = bool(self.cpa_auto_add_var.get())
        config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
        config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
        config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
        config["outlook_email_plus_api_base"] = self.outlook_email_plus_api_base_var.get().strip()
        config["outlook_email_plus_api_key"] = self.outlook_email_plus_api_key_var.get().strip()
        config["outlook_email_plus_caller_id"] = self.outlook_email_plus_caller_id_var.get().strip() or "grok-register"
        raw_paths = [x.strip() for x in self.cloudflare_paths_var.get().split(",") if x.strip()]
        if len(raw_paths) >= 4:
            config["cloudflare_path_domains"] = raw_paths[0] if raw_paths[0].startswith("/") else ("/" + raw_paths[0])
            config["cloudflare_path_accounts"] = raw_paths[1] if raw_paths[1].startswith("/") else ("/" + raw_paths[1])
            config["cloudflare_path_token"] = raw_paths[2] if raw_paths[2].startswith("/") else ("/" + raw_paths[2])
            config["cloudflare_path_messages"] = raw_paths[3] if raw_paths[3].startswith("/") else ("/" + raw_paths[3])
        save_config()
        if config["email_provider"] == "cloudflare" and not config["cloudflare_api_base"]:
            self.log("[!] Cloudflare 模式需要先填写 Cloudflare API Base")
            return
        if config["email_provider"] == "outlook_email_plus":
            if not config["outlook_email_plus_api_base"]:
                self.log("[!] outlookEmailPlus 模式需要先填写 outlookEmailPlus API Base")
                return
            if not config["outlook_email_plus_api_key"]:
                self.log("[!] outlookEmailPlus 模式需要先填写 outlookEmailPlus API Key")
                return
        try:
            count = int(self.count_var.get())
        except Exception:
            self.log("[!] 注册数量无效")
            return
        config["register_count"] = count
        save_config()
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.accounts_output_file = os.path.join(
            os.path.dirname(__file__), f"accounts_{now}.txt"
        )
        self.update_stats()
        self._set_running_ui(True)
        self.log(f"[*] 配置已保存，开始执行。目标数量: {count}")
        self.log(f"[*] 成功账号将实时保存到: {self.accounts_output_file}")
        threading.Thread(
            target=self.run_registration,
            args=(count,),
            daemon=True,
        ).start()

    def stop_registration(self):
        self.stop_requested = True
        self.log("[!] 用户停止注册")

    def run_registration(self, count):
        try:
            start_browser(log_callback=self.log)
            self.log("[*] 浏览器已启动")
            i = 0
            retry_count_for_slot = 0
            max_slot_retry = 3
            while i < count:
                if self.should_stop():
                    break
                self.log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
                try:
                    email = ""
                    dev_token = ""
                    code = ""
                    mail_ok = False
                    max_mail_retry = 3
                    for mail_try in range(1, max_mail_retry + 1):
                        self.log(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                        open_signup_page(
                            log_callback=self.log, cancel_callback=self.should_stop
                        )
                        self.log("[*] 2. 创建邮箱并提交")
                        email, dev_token = fill_email_and_submit(
                            log_callback=self.log, cancel_callback=self.should_stop
                        )
                        self.log(f"[*] 邮箱: {email}")
                        self.log(f"[Debug] 邮箱credential(jwt): {dev_token}")
                        try:
                            with open(
                                os.path.join(os.path.dirname(__file__), "mail_credentials.txt"),
                                "a",
                                encoding="utf-8",
                            ) as f:
                                f.write(f"{email}\t{dev_token}\n")
                        except Exception:
                            pass
                        self.log("[*] 3. 拉取验证码")
                        try:
                            code = fill_code_and_submit(
                                email,
                                dev_token,
                                log_callback=self.log,
                                cancel_callback=self.should_stop,
                            )
                            mail_ok = True
                            break
                        except Exception as mail_exc:
                            msg = str(mail_exc)
                            if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                                self.log(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                                restart_browser(log_callback=self.log)
                                sleep_with_cancel(1, self.should_stop)
                                continue
                            raise

                    if not mail_ok:
                        raise Exception("验证码阶段失败，已达到最大重试次数")
                    self.log(f"[*] 验证码: {code}")
                    self.log("[*] 4. 填写资料")
                    profile = fill_profile_and_submit(
                        log_callback=self.log, cancel_callback=self.should_stop
                    )
                    self.log(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
                    self.log("[*] 5. 等待 sso cookie")
                    sso = wait_for_sso_cookie(
                        log_callback=self.log, cancel_callback=self.should_stop
                    )
                    if config.get("enable_nsfw", True):
                        self.log("[*] 6. 开启 NSFW")
                        cf_clearance, browser_ua = extract_cf_clearance_and_ua(self.log)
                        nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                            sso, cf_clearance=cf_clearance, user_agent=browser_ua, log_callback=self.log
                        )
                        if nsfw_ok:
                            self.log(f"[+] NSFW 开启成功: {nsfw_msg}")
                        else:
                            self.log(f"[!] NSFW 未开启，继续保存账号: {nsfw_msg}")
                    self.results.append({"email": email, "sso": sso, "profile": profile})
                    complete_email_provider_claim("success", "注册成功", log_callback=self.log)
                    try:
                        line = f"{email}----{profile.get('password','')}----{sso}\n"
                        with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                            f.write(line)
                    except Exception as file_exc:
                        self.log(f"[Debug] 保存账号文件失败: {file_exc}")
                    add_sso_to_cpa(sso, email=email, log_callback=self.log)
                    self.success_count += 1
                    retry_count_for_slot = 0
                    i += 1
                    self.log(f"[+] 注册成功: {email}")
                    if (
                        self.success_count > 0
                        and self.success_count % MEMORY_CLEANUP_INTERVAL == 0
                        and i < count
                    ):
                        cleanup_runtime_memory(
                            log_callback=self.log,
                            reason=f"已成功 {self.success_count} 个账号，执行定期清理",
                        )
                except RegistrationCancelled:
                    self.log("[!] 注册被用户停止")
                    break
                except AccountRetryNeeded as exc:
                    retry_count_for_slot += 1
                    if retry_count_for_slot <= max_slot_retry:
                        self.log(
                            f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                        )
                    else:
                        self.fail_count += 1
                        self.log(
                            f"[-] 当前账号已达到最大重试次数，跳过: {exc}"
                        )
                        release_email_provider_claim("registration_failed", log_callback=self.log)
                        retry_count_for_slot = 0
                        i += 1
                except Exception as exc:
                    self.fail_count += 1
                    retry_count_for_slot = 0
                    i += 1
                    self.log(f"[-] 注册失败: {exc}")
                    release_email_provider_claim("registration_failed", log_callback=self.log)
                finally:
                    self.update_stats()
                    if self.should_stop():
                        break
                    try:
                        if browser is None:
                            start_browser(log_callback=self.log)
                        else:
                            restart_browser(log_callback=self.log)
                        # 停止后不再调用 cancel_callback，避免 finally 里二次抛出 RegistrationCancelled
                        time.sleep(1)
                    except RegistrationCancelled:
                        break
                    except Exception as restart_exc:
                        if self.should_stop():
                            break
                        self.log(f"[Debug] 轮次清理/重启浏览器失败: {restart_exc}")
        except RegistrationCancelled:
            self.log("[!] 注册被用户停止")
        except Exception as exc:
            self.log(f"[!] 任务异常: {exc}")
        finally:
            release_email_provider_claim("registration_stopped", log_callback=self.log)
            try:
                stop_browser()
            except BaseException:
                pass
            self._set_running_ui(False)
            self.log("[*] 任务结束")


class CliStopController:
    def __init__(self):
        self.stop_requested = False

    def should_stop(self):
        return self.stop_requested

    def stop(self):
        self.stop_requested = True


def cli_log(message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def run_registration_cli(count):
    controller = CliStopController()

    # 一次 Ctrl+C 可靠置停：SIGINT 处理器直接设停止标志，不依赖异常在
    # curl_cffi C 回调里向上传播（那里 KeyboardInterrupt 会被吞掉，导致
    # 第一次 Ctrl+C 无效、循环继续跑下一个账号）。连按两次 Ctrl+C 时第二次
    # 恢复默认行为强制中断。
    _prev_sigint = signal.getsignal(signal.SIGINT)

    def _on_sigint(signum, frame):
        if controller.should_stop():
            # 第二次：恢复默认并重新抛出，强制中断
            signal.signal(signal.SIGINT, _prev_sigint)
            raise KeyboardInterrupt
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")

    signal.signal(signal.SIGINT, _on_sigint)
    success_count = 0
    fail_count = 0
    retry_count_for_slot = 0
    max_slot_retry = 3
    accounts_output_file = os.path.join(
        os.path.dirname(__file__),
        f"accounts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    cli_log(f"[*] 终端模式启动，目标数量: {count}")
    cli_log(f"[*] 成功账号将实时保存到: {accounts_output_file}")
    try:
        start_browser(log_callback=cli_log)
        cli_log("[*] 浏览器已启动")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            cli_log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            try:
                email = ""
                dev_token = ""
                code = ""
                mail_ok = False
                max_mail_retry = 3
                for mail_try in range(1, max_mail_retry + 1):
                    cli_log(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                    open_signup_page(
                        log_callback=cli_log, cancel_callback=controller.should_stop
                    )
                    cli_log("[*] 2. 创建邮箱并提交")
                    email, dev_token = fill_email_and_submit(
                        log_callback=cli_log, cancel_callback=controller.should_stop
                    )
                    cli_log(f"[*] 邮箱: {email}")
                    cli_log(f"[Debug] 邮箱credential(jwt): {dev_token}")
                    try:
                        with open(
                            os.path.join(os.path.dirname(__file__), "mail_credentials.txt"),
                            "a",
                            encoding="utf-8",
                        ) as f:
                            f.write(f"{email}\t{dev_token}\n")
                    except Exception:
                        pass
                    cli_log("[*] 3. 拉取验证码")
                    try:
                        code = fill_code_and_submit(
                            email,
                            dev_token,
                            log_callback=cli_log,
                            cancel_callback=controller.should_stop,
                        )
                        mail_ok = True
                        break
                    except Exception as mail_exc:
                        msg = str(mail_exc)
                        if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                            cli_log(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                            restart_browser(log_callback=cli_log)
                            sleep_with_cancel(1, controller.should_stop)
                            continue
                        raise

                if not mail_ok:
                    raise Exception("验证码阶段失败，已达到最大重试次数")
                cli_log(f"[*] 验证码: {code}")
                cli_log("[*] 4. 填写资料")
                profile = fill_profile_and_submit(
                    log_callback=cli_log, cancel_callback=controller.should_stop
                )
                cli_log(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
                cli_log("[*] 5. 等待 sso cookie")
                sso = wait_for_sso_cookie(
                    log_callback=cli_log, cancel_callback=controller.should_stop
                )
                if config.get("enable_nsfw", True):
                    cli_log("[*] 6. 开启 NSFW")
                    cf_clearance, browser_ua = extract_cf_clearance_and_ua(log_callback=cli_log)
                    nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                        sso, cf_clearance=cf_clearance, user_agent=browser_ua, log_callback=cli_log
                    )
                    if nsfw_ok:
                        cli_log(f"[+] NSFW 开启成功: {nsfw_msg}")
                    else:
                        cli_log(f"[!] NSFW 未开启，继续保存账号: {nsfw_msg}")
                try:
                    line = f"{email}----{profile.get('password','')}----{sso}\n"
                    with open(accounts_output_file, "a", encoding="utf-8") as f:
                        f.write(line)
                except Exception as file_exc:
                    cli_log(f"[Debug] 保存账号文件失败: {file_exc}")
                add_sso_to_cpa(sso, email=email, log_callback=cli_log)
                complete_email_provider_claim("success", "注册成功", log_callback=cli_log)
                success_count += 1
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[+] 注册成功: {email}")
                cli_log(f"[*] 当前统计: 成功 {success_count} | 失败 {fail_count}")
                if success_count > 0 and success_count % MEMORY_CLEANUP_INTERVAL == 0 and i < count:
                    cleanup_runtime_memory(
                        log_callback=cli_log,
                        reason=f"已成功 {success_count} 个账号，执行定期清理",
                    )
            except RegistrationCancelled:
                cli_log("[!] 注册被停止")
                break
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                if retry_count_for_slot <= max_slot_retry:
                    cli_log(
                        f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                    )
                else:
                    fail_count += 1
                    retry_count_for_slot = 0
                    i += 1
                    cli_log(f"[-] 当前账号已达到最大重试次数，跳过: {exc}")
                    release_email_provider_claim("registration_failed", log_callback=cli_log)
            except Exception as exc:
                fail_count += 1
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[-] 注册失败: {exc}")
                release_email_provider_claim("registration_failed", log_callback=cli_log)
            finally:
                if controller.should_stop():
                    break
                try:
                    if browser is None:
                        start_browser(log_callback=cli_log)
                    else:
                        restart_browser(log_callback=cli_log)
                    # 停止后不再调用 cancel_callback，避免 finally 里二次抛出 RegistrationCancelled
                    time.sleep(1)
                except KeyboardInterrupt:
                    controller.stop()
                    cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")
                    break
                except RegistrationCancelled:
                    break
                except Exception as restart_exc:
                    if controller.should_stop():
                        break
                    cli_log(f"[Debug] 轮次清理/重启浏览器失败: {restart_exc}")
    except KeyboardInterrupt:
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止并清理")
    except RegistrationCancelled:
        cli_log("[!] 注册被停止")
    except Exception as exc:
        cli_log(f"[!] 任务异常: {exc}")
    finally:
        release_email_provider_claim("registration_stopped", log_callback=cli_log)
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        try:
            cleanup_runtime_memory(log_callback=cli_log, reason="任务结束")
        except BaseException:
            pass
        try:
            cli_log(f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}")
        except BaseException:
            pass
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass


def _cli_test_outlook_email_plus():
    """自检 outlookEmailPlus 服务连通性与池读写能力。

    步骤：
      1. GET /api/external/health        服务健康检查
      2. GET /api/external/capabilities  查看开放能力
      3. POST /api/external/pool/claim-random  尝试领取一个邮箱
      4. POST /api/external/pool/claim-release  立即释放刚领取的邮箱
    任一步骤失败即判定不可用，并打印详细错误。
    """
    load_config()
    cli_log("[*] 自检 outlookEmailPlus (/api/external/*)...")

    api_base = get_outlook_email_plus_api_base()
    api_key = get_outlook_email_plus_api_key()
    if not api_base:
        cli_log("[!] 未配置 outlook_email_plus_api_base，无法测试")
        sys.exit(1)
    if not api_key:
        cli_log("[!] 未配置 outlook_email_plus_api_key，无法测试")
        sys.exit(1)

    cli_log(f"[*] Base: {api_base}")
    cli_log(f"[*] Caller ID: {get_outlook_email_plus_caller_id()}")
    headers = outlook_email_plus_build_headers(content_type=False)

    # 1. health
    try:
        resp = http_get(f"{api_base}/api/external/health", headers=headers, timeout=20)
        ok = 200 <= resp.status_code < 300
        data = {}
        try:
            data = resp.json()
        except Exception:
            ok = ok and False
        service = data.get("service") or "?"
        version = data.get("version") or "?"
        db_ok = data.get("database") or "?"
        up_ok = data.get("upstream_probe_ok")
        cli_log(
            f"[{'+' if ok else '!'}] health  HTTP {resp.status_code}  service={service} version={version} database={db_ok} upstream_probe_ok={up_ok}"
        )
        if not ok:
            cli_log(f"[!] health 接口返回非 2xx 或非 JSON: {response_preview(resp)}")
            sys.exit(1)
    except Exception as exc:
        cli_log(f"[!] health 请求异常: {exc}")
        sys.exit(1)

    # 2. capabilities
    try:
        resp = http_get(f"{api_base}/api/external/capabilities", headers=headers, timeout=20)
        ok = 200 <= resp.status_code < 300
        feats = []
        if ok:
            try:
                data = resp.json()
                feats = list((data.get("data") or {}).get("features") or [])
                public_mode = (data.get("data") or {}).get("public_mode")
                cli_log(f"[*] capabilities  HTTP {resp.status_code}  public_mode={public_mode} features={feats}")
            except Exception as exc:
                cli_log(f"[!] capabilities 非 JSON: {exc}  body={response_preview(resp)}")
                ok = False
        if not ok:
            cli_log(f"[!] capabilities 返回非 2xx: {response_preview(resp)}")
            sys.exit(1)
        # wait_message 是本接入的关键能力，不在列表里说明可能被公网模式禁用
        if "wait_message" not in feats:
            cli_log("[!] 提示: wait_message 能力未开放，outlookEmailPlus 取码会失败")
    except Exception as exc:
        cli_log(f"[!] capabilities 请求异常: {exc}")
        sys.exit(1)

    # 3. claim-random
    task_id = _outlook_email_plus_next_task_id()
    payload = {"caller_id": get_outlook_email_plus_caller_id(), "task_id": task_id}
    pool_provider = str(config.get("outlook_email_plus_pool_provider", "") or "").strip()
    if pool_provider:
        payload["provider"] = pool_provider
    project_key = str(config.get("outlook_email_plus_project_key", "") or "").strip()
    if project_key:
        payload["project_key"] = project_key
    email_domain = str(config.get("outlook_email_plus_email_domain", "") or "").strip()
    if email_domain and pool_provider == "cloudflare_temp_mail":
        payload["email_domain"] = email_domain

    claim_data = None
    try:
        cli_log(f"[*] claim-random  task_id={task_id} provider={pool_provider or '(不筛选)'}")
        resp = http_post(
            f"{api_base}/api/external/pool/claim-random",
            json=payload,
            headers=outlook_email_plus_build_headers(content_type=True),
            timeout=30,
        )
        ok_code = resp.status_code == 200
        try:
            data = resp.json()
        except Exception:
            data = {}
        success = ok_code and bool(data.get("success"))
        code = data.get("code") or ""
        claim_data = data.get("data") or {}
        email = (claim_data or {}).get("email") or ""
        lease = (claim_data or {}).get("lease_expires_at") or ""
        if success and email:
            cli_log(f"[+] claim-random  HTTP {resp.status_code}  email={email}  lease_expires_at={lease}")
        else:
            # 池中无可用邮箱也视为“池连接可用，仅当前无机可领”，不直接判失败
            if code == "no_available_account":
                cli_log(f"[~] claim-random  池连接正常但无可用邮箱  code={code}")
                cli_log("[*] outlookEmailPlus 服务可用（未领取邮箱，跳过 release 验证）")
                return
            cli_log(f"[!] claim-random  失败  HTTP {resp.status_code}  code={code}  body={response_preview(resp)}")
            sys.exit(1)
    except Exception as exc:
        cli_log(f"[!] claim-random 请求异常: {exc}")
        sys.exit(1)

    # 4. claim-release
    try:
        rel_payload = {
            "account_id": claim_data.get("account_id"),
            "claim_token": claim_data.get("claim_token"),
            "caller_id": get_outlook_email_plus_caller_id(),
            "task_id": task_id,
            "reason": "self_test",
        }
        resp = http_post(
            f"{api_base}/api/external/pool/claim-release",
            json=rel_payload,
            headers=outlook_email_plus_build_headers(content_type=True),
            timeout=20,
        )
        try:
            data = resp.json()
        except Exception:
            data = {}
        if 200 <= resp.status_code < 300 and bool(data.get("success")):
            cli_log(f"[+] claim-release HTTP {resp.status_code}  success=True  reason=self_test")
        else:
            cli_log(
                f"[!] claim-release 失败  HTTP {resp.status_code}  code={data.get('code')}  body={response_preview(resp)}"
            )
            sys.exit(1)
    except Exception as exc:
        cli_log(f"[!] claim-release 请求异常: {exc}")
        sys.exit(1)

    cli_log("[*] outlookEmailPlus 自检通过：health / capabilities / claim-random / claim-release 全部可用")


def _cli_test_cpa():
    """自检 CLIProxyAPI(CPA) 入库链路：本地 auth 目录 + 远程 Management API。

    本地：cpa_auth_dir 存在且可写（写一个 .probe 文件再删除，不产生 auth 文件）
    远程：GET /v0/management/config 验证 base + management_key 可用；
          GET /v0/management/auth-files 列出当前 auth 文件，统计 xai-*.json 数量。
    任一已配置的目标失败即判失败；未配置的目标跳过。
    """
    load_config()
    cli_log("[*] 自检 CLIProxyAPI(CPA) 入库链路...")

    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(config.get("cpa_remote_url", "") or "").strip().rstrip("/")
    management_key = str(config.get("cpa_management_key", "") or "").strip()
    auto_add = bool(config.get("cpa_auto_add", False))

    cli_log(f"[*] cpa_auto_add={auto_add}  本地目录={'已配置' if auth_dir else '未配置'}  远程={'已配置' if remote_url else '未配置'}")

    if not auto_add:
        cli_log("[~] cpa_auto_add 未开启；仅检测已配置的目标，不强制要求")

    any_configured = False
    all_ok = True

    # 1. 本地 auth 目录
    if auth_dir:
        any_configured = True
        cli_log(f"[*] 本地 auth 目录: {auth_dir}")
        try:
            import os as _os
            if not _os.path.isdir(auth_dir):
                cli_log(f"[!] 本地目录不存在: {auth_dir}")
                all_ok = False
            else:
                probe = _os.path.join(auth_dir, ".cpa_probe")
                try:
                    with open(probe, "w", encoding="utf-8") as f:
                        f.write("probe")
                    _os.remove(probe)
                    cli_log(f"[+] 本地目录可写: {auth_dir}")
                except Exception as w_exc:
                    cli_log(f"[!] 本地目录不可写: {w_exc}")
                    all_ok = False
        except Exception as exc:
            cli_log(f"[!] 本地目录检测异常: {exc}")
            all_ok = False
    else:
        cli_log("[~] 未配置 cpa_auth_dir，跳过本地目录检测")

    # 2. 远程 Management API
    if remote_url:
        any_configured = True
        if not management_key:
            cli_log("[!] 已配置 cpa_remote_url 但未配置 cpa_management_key，无法自检远程")
            all_ok = False
        else:
            cli_log(f"[*] 远程 CPA: {remote_url}")
            headers = {"Authorization": f"Bearer {management_key}"}

            # 2a. GET /v0/management/config — 验证连通性与密钥
            try:
                resp = http_get(
                    f"{remote_url}/v0/management/config",
                    headers=headers,
                    timeout=20,
                )
                if resp.status_code == 401 or resp.status_code == 403:
                    cli_log(f"[!] 远程管理密钥无效 HTTP {resp.status_code}（401/403 鉴权失败）")
                    all_ok = False
                elif resp.status_code == 404:
                    cli_log(f"[!] 远程 Management API 返回 404（未启用远程管理或 base 路径错误）")
                    all_ok = False
                elif not (200 <= resp.status_code < 300):
                    cli_log(f"[!] GET /config 失败 HTTP {resp.status_code}  body={response_preview(resp)}")
                    all_ok = False
                else:
                    try:
                        cfg = resp.json()
                    except Exception:
                        cfg = {}
                    auth_dir_remote = cfg.get("auth-dir") or cfg.get("auth_dir") or "?"
                    cli_log(f"[+] GET /config 成功  HTTP {resp.status_code}  auth-dir={auth_dir_remote}")
            except Exception as exc:
                cli_log(f"[!] GET /config 请求异常: {exc}")
                all_ok = False

            # 2b. GET /v0/management/auth-files — 列出 auth 文件，统计 xai-*.json
            if all_ok:
                try:
                    resp = http_get(
                        f"{remote_url}/v0/management/auth-files",
                        headers=headers,
                        timeout=20,
                    )
                    if not (200 <= resp.status_code < 300):
                        cli_log(f"[!] GET /auth-files 失败 HTTP {resp.status_code}  body={response_preview(resp)}")
                        all_ok = False
                    else:
                        try:
                            data = resp.json()
                        except Exception:
                            data = {}
                        files = data.get("files") or []
                        total = len(files)
                        xai_files = [f for f in files if str(f.get("name") or "").startswith("xai-")]
                        xai_count = len(xai_files)
                        cli_log(f"[+] GET /auth-files 成功  HTTP {resp.status_code}  auth 文件总数={total}  xai-*.json={xai_count}")
                        if xai_count > 0:
                            for f in xai_files[:5]:
                                cli_log(f"    - {f.get('name')}  provider={f.get('provider') or '?'}  status={f.get('status') or '?'}")
                            if xai_count > 5:
                                cli_log(f"    ... 其余 {xai_count - 5} 个 xai 文件未显示")
                except Exception as exc:
                    cli_log(f"[!] GET /auth-files 请求异常: {exc}")
                    all_ok = False
    else:
        cli_log("[~] 未配置 cpa_remote_url，跳过远程 Management API 检测")

    if not any_configured:
        cli_log("[!] 未配置任何 CPA 入库目标（cpa_auth_dir / cpa_remote_url 均为空）")
        sys.exit(1)
    if not all_ok:
        cli_log("[!] CPA 自检未通过")
        sys.exit(1)
    cli_log("[*] CPA 自检通过：已配置的入库目标均可用")


def main_cli():
    load_config()
    count = int(config.get("register_count", 1) or 1)
    cli_log("[*] CLI 已加载配置")
    cli_log(f"[*] 当前邮箱服务商: {config.get('email_provider', 'duckmail')} | 注册数量: {count}")
    cli_log("[*] 输入 start 后开始；按 Ctrl+C 可强制停止")
    try:
        command = input("> ").strip().lower()
    except KeyboardInterrupt:
        cli_log("[!] 已取消")
        return
    if command != "start":
        cli_log("[!] 未输入 start，已退出")
        return
    try:
        run_registration_cli(count)
    except KeyboardInterrupt:
        # 清理阶段仍可能漏出，保证 CLI 干净退出
        cli_log("[!] 已停止")


def main():
    argv = sys.argv[1:]
    if argv:
        cmd = argv[0].strip().lower()
        if cmd in ("start", "cli", "--cli"):
            main_cli()
            return
        if cmd in ("test-outlook-email-plus", "test-oep", "--test-outlook-email-plus"):
            _cli_test_outlook_email_plus()
            return
        if cmd in ("test-cpa", "--test-cpa"):
            _cli_test_cpa()
            return
        if cmd in ("-h", "--help", "help"):
            print(
                "用法:\n"
                "  python grok_register_ttk.py                          启动 GUI\n"
                "  python grok_register_ttk.py cli                      交互式 CLI 注册\n"
                "  python grok_register_ttk.py test-outlook-email-plus  自检 outlookEmailPlus 池读写\n"
                "  python grok_register_ttk.py test-cpa                 自检 CPA 入库链路（本地目录 + 远程 Management API）\n"
                "  python grok_register_ttk.py -h|--help                显示本帮助\n"
            )
            return
    root = tk.Tk()
    setup_light_theme(root)
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
