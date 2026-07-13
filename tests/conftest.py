import sys
import types


def _ensure_heavy_dep_stubs():
    """无 DrissionPage / curl_cffi 运行时也能跑纯业务单测。

    仅当真实包尚未安装时注入最简桩，已安装则保持原状，
    不影响在完整运行时环境下对真实依赖的测试。
    """
    if "DrissionPage" not in sys.modules:
        try:
            import DrissionPage  # noqa: F401
        except Exception:
            dp = types.ModuleType("DrissionPage")
            dp.Chromium = object
            dp.ChromiumOptions = object
            sys.modules["DrissionPage"] = dp
            errors = types.ModuleType("DrissionPage.errors")
            errors.PageDisconnectedError = type(
                "PageDisconnectedError", (Exception,), {}
            )
            sys.modules["DrissionPage.errors"] = errors
    if "curl_cffi" not in sys.modules:
        try:
            import curl_cffi  # noqa: F401
        except Exception:
            cc = types.ModuleType("curl_cffi")
            requests_mod = types.ModuleType("curl_cffi.requests")
            requests_mod.Session = object
            requests_mod.get = lambda *a, **k: None
            requests_mod.post = lambda *a, **k: None
            cc.requests = requests_mod
            sys.modules["curl_cffi"] = cc
            sys.modules["curl_cffi.requests"] = requests_mod


_ensure_heavy_dep_stubs()
