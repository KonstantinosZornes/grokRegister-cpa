import sys
import types
import unittest
from unittest.mock import patch


def _install_heavy_dep_stubs():
    if "DrissionPage" not in sys.modules:
        dp = types.ModuleType("DrissionPage")
        dp.Chromium = object
        dp.ChromiumOptions = object
        sys.modules["DrissionPage"] = dp
        errors = types.ModuleType("DrissionPage.errors")
        errors.PageDisconnectedError = type("PageDisconnectedError", (Exception,), {})
        sys.modules["DrissionPage.errors"] = errors
    if "curl_cffi" not in sys.modules:
        cc = types.ModuleType("curl_cffi")
        cc.requests = types.ModuleType("curl_cffi.requests")
        cc.requests.Session = object
        cc.requests.get = lambda *a, **k: None
        cc.requests.post = lambda *a, **k: None
        sys.modules["curl_cffi"] = cc
        sys.modules["curl_cffi.requests"] = cc.requests


_install_heavy_dep_stubs()

import grok_register_ttk as app  # noqa: E402


class DummyResponse:
    def __init__(self, payload=None, status_code=200, reason=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.reason = reason
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP Error {self.status_code}: {self.reason}")

    def json(self):
        return self._payload


class outlookEmailPlusClaimTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()
        self.original_pending = app._outlook_email_plus_pending_claim
        app._outlook_email_plus_pending_claim = None
        app.config.update({
            "email_provider": "outlook_email_plus",
            "outlook_email_plus_api_base": "https://omp.example.com",
            "outlook_email_plus_api_key": "api-secret",
            "outlook_email_plus_caller_id": "grok-register",
            "outlook_email_plus_pool_provider": "",
            "outlook_email_plus_project_key": "",
            "outlook_email_plus_email_domain": "",
            "proxy": "",
        })

    def tearDown(self):
        app.config = self.original_config
        app._outlook_email_plus_pending_claim = self.original_pending

    def test_claim_random_builds_correct_payload_and_returns_email_with_claim_context(self):
        posts = []

        def fake_post(url, **kwargs):
            posts.append((url, kwargs))
            return DummyResponse({
                "success": True,
                "code": "OK",
                "data": {
                    "account_id": 42,
                    "email": "abc@ex.com",
                    "claim_token": "clm_xxx",
                },
            })

        with patch.object(app, "http_post", side_effect=fake_post):
            email, dev_token = app.outlook_email_plus_get_email_and_token()

        self.assertEqual(email, "abc@ex.com")
        import json as _json
        ctx = _json.loads(dev_token)
        self.assertEqual(ctx["account_id"], 42)
        self.assertEqual(ctx["claim_token"], "clm_xxx")
        self.assertEqual(ctx["caller_id"], "grok-register")
        self.assertTrue(ctx["task_id"].startswith("grok-"))

        url, kwargs = posts[0]
        self.assertEqual(url, "https://omp.example.com/api/external/pool/claim-random")
        self.assertEqual(kwargs["headers"], {"Content-Type": "application/json", "X-API-Key": "api-secret"})
        self.assertEqual(kwargs["json"]["caller_id"], "grok-register")
        self.assertEqual(kwargs["json"]["task_id"], ctx["task_id"])
        # 留空筛选不携带 provider 字段
        self.assertNotIn("provider", kwargs["json"])
        # pending claim 已登记
        self.assertEqual(app._outlook_email_plus_pending_claim["account_id"], 42)
        self.assertEqual(app._outlook_email_plus_pending_claim["email"], "abc@ex.com")

    def test_claim_random_with_pool_provider_and_project_key(self):
        app.config.update({
            "outlook_email_plus_pool_provider": "cloudflare_temp_mail",
            "outlook_email_plus_project_key": "project-A",
            "outlook_email_plus_email_domain": "zerodotsix.top",
        })
        posts = []

        def fake_post(url, **kwargs):
            posts.append((url, kwargs))
            return DummyResponse({
                "success": True,
                "data": {"account_id": 7, "email": "x@z.top", "claim_token": "clm_y"},
            })

        with patch.object(app, "http_post", side_effect=fake_post):
            app.outlook_email_plus_get_email_and_token()

        payload = posts[0][1]["json"]
        self.assertEqual(payload["provider"], "cloudflare_temp_mail")
        self.assertEqual(payload["project_key"], "project-A")
        self.assertEqual(payload["email_domain"], "zerodotsix.top")

    def test_no_available_account_raises_friendly_message(self):
        def fake_post(url, **kwargs):
            return DummyResponse({"success": False, "code": "no_available_account", "message": "池中没有符合条件的可用邮箱"})

        with patch.object(app, "http_post", side_effect=fake_post):
            with self.assertRaises(Exception) as ctx:
                app.outlook_email_plus_get_email_and_token()
        self.assertIn("outlookEmailPlus 池中没有可用邮箱", str(ctx.exception))

    def test_complete_pending_posts_claim_complete_and_clears_state(self):
        app._outlook_email_plus_pending_claim = {
            "account_id": 11,
            "claim_token": "clm_11",
            "caller_id": "grok-register",
            "task_id": "grok-1",
            "email": "a@b.com",
        }
        posts = []

        def fake_post(url, **kwargs):
            posts.append((url, kwargs))
            return DummyResponse({"success": True, "data": {"pool_status": "used"}})

        with patch.object(app, "http_post", side_effect=fake_post):
            app.outlook_email_plus_complete_pending("success", "注册成功")

        self.assertIsNone(app._outlook_email_plus_pending_claim)
        url, kwargs = posts[0]
        self.assertEqual(url, "https://omp.example.com/api/external/pool/claim-complete")
        self.assertEqual(kwargs["json"], {
            "account_id": 11,
            "claim_token": "clm_11",
            "caller_id": "grok-register",
            "task_id": "grok-1",
            "result": "success",
            "detail": "注册成功",
        })

    def test_next_claim_releases_previous_pending(self):
        app._outlook_email_plus_pending_claim = {
            "account_id": 1,
            "claim_token": "clm_old",
            "caller_id": "grok-register",
            "task_id": "grok-old",
            "email": "old@b.com",
        }
        posts = []

        def fake_post(url, **kwargs):
            posts.append((url, kwargs))
            if url.endswith("/claim-release"):
                return DummyResponse({"success": True})
            return DummyResponse({
                "success": True,
                "data": {"account_id": 2, "email": "new@b.com", "claim_token": "clm_new"},
            })

        with patch.object(app, "http_post", side_effect=fake_post):
            app.outlook_email_plus_get_email_and_token()

        urls = [u for u, _ in posts]
        self.assertEqual(urls[0], "https://omp.example.com/api/external/pool/claim-release")
        self.assertEqual(urls[1], "https://omp.example.com/api/external/pool/claim-random")
        self.assertEqual(posts[0][1]["json"]["reason"], "verification_retry")
        self.assertEqual(posts[0][1]["json"]["account_id"], 1)

    def test_release_and_complete_dispatch_is_noop_for_other_providers(self):
        # 模拟 outlook_email_plus 挂起租约存在，但 provider 切换为 cloudflare
        app._outlook_email_plus_pending_claim = {
            "account_id": 99,
            "claim_token": "clm_z",
            "caller_id": "grok-register",
            "task_id": "grok-z",
            "email": "z@b.com",
        }
        app.config["email_provider"] = "cloudflare"
        with patch.object(app, "http_post") as fake_post:
            app.release_email_provider_claim("failed")
            app.complete_email_provider_claim("success")
        # dispatch 层应在非 outlook_email_plus 时直接返回，不触发任何请求；
        # 但 pending 仍保留，避免误清空其它 provider 的状态
        self.assertEqual(fake_post.call_count, 0)
        # 恢复以便后续断言
        app._outlook_email_plus_pending_claim = None


class outlookEmailPlusVerificationTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()
        self.original_pending = app._outlook_email_plus_pending_claim
        app._outlook_email_plus_pending_claim = {
            "account_id": 5,
            "claim_token": "clm_5",
            "caller_id": "grok-register",
            "task_id": "grok-5",
            "email": "verify@b.com",
        }
        app.config.update({
            "email_provider": "outlook_email_plus",
            "outlook_email_plus_api_base": "https://omp.example.com",
            "outlook_email_plus_api_key": "api-secret",
            "proxy": "",
        })

    def tearDown(self):
        app.config = self.original_config
        app._outlook_email_plus_pending_claim = self.original_pending

    def test_wait_message_returns_code(self):
        gets = []

        def fake_get(url, **kwargs):
            gets.append((url, kwargs))
            return DummyResponse({
                "success": True,
                "data": {
                    "id": "m1",
                    "subject": "A1B-2C3 xAI",
                    "content": "your verification code is A1B-2C3",
                },
            })

        with patch.object(app, "http_get", side_effect=fake_get):
            code = app.outlook_email_plus_get_oai_code(
                dev_token="{}",
                email="verify@b.com",
                timeout=30,
                poll_interval=1,
                cancel_callback=None,
                resend_callback=None,
            )
        self.assertEqual(code, "A1B-2C3")
        url, kwargs = gets[0]
        self.assertEqual(url, "https://omp.example.com/api/external/wait-message")
        self.assertEqual(kwargs["params"]["email"], "verify@b.com")
        self.assertEqual(kwargs["params"]["mode"], "sync")
        self.assertEqual(kwargs["headers"], {"X-API-Key": "api-secret"})

    def test_wait_message_404_then_success(self):
        # wait-message 第一轮 404，第二轮返回验证码；
        # 兜底 messages 接口始终返回空列表（不提供新邮件）
        wait_responses = [
            DummyResponse(status_code=404),
            DummyResponse({
                "success": True,
                "data": {"id": "m2", "subject": "Z9Y-8X7 xAI", "content": "code Z9Y-8X7"},
            }),
        ]
        widx = {"i": 0}

        def fake_get(url, **kwargs):
            if "/api/external/messages" in url and "/wait-message" not in url:
                return DummyResponse({"success": True, "data": {"count": 0, "emails": []}})
            r = wait_responses[widx["i"]]
            widx["i"] += 1
            return r

        # 把 poll sleep 加速
        with patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            code = app.outlook_email_plus_get_oai_code(
                dev_token="{}",
                email="verify@b.com",
                timeout=30,
                poll_interval=0,
                cancel_callback=None,
                resend_callback=None,
            )
        self.assertEqual(code, "Z9Y-8X7")

    def test_wait_message_timeout_raises(self):
        def fake_get(url, **kwargs):
            if "/api/external/messages" in url and "/wait-message" not in url:
                return DummyResponse({"success": True, "data": {"count": 0, "emails": []}})
            return DummyResponse(status_code=404)

        with patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            with self.assertRaises(Exception) as ctx:
                app.outlook_email_plus_get_oai_code(
                    dev_token="{}",
                    email="verify@b.com",
                    timeout=2,
                    poll_interval=0,
                    cancel_callback=None,
                    resend_callback=None,
                )
        self.assertIn("outlookEmailPlus", str(ctx.exception))

    def test_fallback_messages_list_catches_email_missed_by_wait_message(self):
        """wait-message 始终 404，但兜底 messages-list 发现了带验证码的新邮件。"""
        import time as _time
        now_ts = _time.time()

        def fake_get(url, **kwargs):
            if "/wait-message" in url:
                return DummyResponse(status_code=404)
            # messages 接口返回一封 timestamp=now 的新邮件
            return DummyResponse({
                "success": True,
                "data": {
                    "count": 1,
                    "emails": [
                        {
                            "id": "mx1",
                            "subject": "A1B-2C3 xAI confirmation code",
                            "content_preview": "your verification code is A1B-2C3",
                            "timestamp": now_ts,
                        }
                    ],
                },
            })

        with patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            code = app.outlook_email_plus_get_oai_code(
                dev_token="{}",
                email="verify@b.com",
                timeout=30,
                poll_interval=0,
                cancel_callback=None,
                resend_callback=None,
            )
        self.assertEqual(code, "A1B-2C3")

    def test_consecutive_upstream_502_fails_fast(self):
        """连续 HTTP 502 / UPSTREAM_READ_FAILED 应快速失败，而不是空转到 timeout。"""
        gets = []

        def fake_get(url, **kwargs):
            gets.append(url)
            return DummyResponse(
                {
                    "success": False,
                    "code": "UPSTREAM_READ_FAILED",
                    "message": "Graph/IMAP 均读取失败",
                },
                status_code=502,
            )

        with patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            with self.assertRaises(Exception) as ctx:
                app.outlook_email_plus_get_oai_code(
                    dev_token="{}",
                    email="verify@b.com",
                    timeout=180,
                    poll_interval=0,
                    cancel_callback=None,
                    resend_callback=None,
                    max_upstream_failures=3,
                )
        self.assertIn("上游连续失败", str(ctx.exception))
        self.assertIn("UPSTREAM_READ_FAILED", str(ctx.exception))
        # 只打 wait-message，不反复打兜底 messages-list
        self.assertEqual(len(gets), 3)
        self.assertTrue(all("/wait-message" in u for u in gets))

    def test_upstream_failure_skips_resend_callback(self):
        """上游连续失败期间不应触发页面端重新发送验证码。"""
        resend_calls = []
        t = {"now": 1000.0}

        def fake_time():
            return t["now"]

        def fake_get(url, **kwargs):
            # 每轮推进时间，确保会命中 next_resend_at
            t["now"] += 40
            return DummyResponse(
                {
                    "success": False,
                    "code": "UPSTREAM_READ_FAILED",
                    "message": "Graph/IMAP 均读取失败",
                },
                status_code=502,
            )

        with patch.object(app.time, "time", side_effect=fake_time), \
                patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            with self.assertRaises(Exception) as ctx:
                app.outlook_email_plus_get_oai_code(
                    dev_token="{}",
                    email="verify@b.com",
                    timeout=180,
                    poll_interval=0,
                    cancel_callback=None,
                    resend_callback=lambda: resend_calls.append(1),
                    max_upstream_failures=3,
                )
        self.assertIn("上游连续失败", str(ctx.exception))
        self.assertEqual(resend_calls, [])

    def test_upstream_failure_resets_after_404(self):
        """偶发上游失败后若恢复为 404/正常等待，计数应清零并继续轮询。"""
        wait_responses = [
            DummyResponse(
                {
                    "success": False,
                    "code": "UPSTREAM_READ_FAILED",
                    "message": "temporary",
                },
                status_code=502,
            ),
            DummyResponse(status_code=404),
            DummyResponse(
                {
                    "success": True,
                    "data": {
                        "id": "m3",
                        "subject": "Q1W-2E3 xAI",
                        "content": "code Q1W-2E3",
                    },
                }
            ),
        ]
        widx = {"i": 0}

        def fake_get(url, **kwargs):
            if "/api/external/messages" in url and "/wait-message" not in url:
                return DummyResponse({"success": True, "data": {"count": 0, "emails": []}})
            r = wait_responses[widx["i"]]
            widx["i"] += 1
            return r

        with patch.object(app, "sleep_with_cancel", lambda s, c=None: None), \
                patch.object(app, "http_get", side_effect=fake_get):
            code = app.outlook_email_plus_get_oai_code(
                dev_token="{}",
                email="verify@b.com",
                timeout=30,
                poll_interval=0,
                cancel_callback=None,
                resend_callback=None,
                max_upstream_failures=3,
            )
        self.assertEqual(code, "Q1W-2E3")


if __name__ == "__main__":
    unittest.main()
