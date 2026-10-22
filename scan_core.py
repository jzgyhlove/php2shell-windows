#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""被动指纹检测核心（php2shell / CVE-2026-109618、CVE-2026-109619）。

改编自 murrez/php2shell（MIT）的 `check` 模式：
仅发送 GET 请求，读取 X-Powered-By / Server / 页面前 8KB，解析 PHP 版本并比对
官方修复版本。不会发送 multipart 触发流量，也不包含任何利用代码。

当版本被 nginx / CDN 隐藏时，可选的增强识别会再发最多 3 个 GET 请求，
通过 Cookie、CMS 特征、index.php 可达性、随机 .php/.html 差异、PHP-FPM
404 特征等判断后端是否为 PHP，但无法据此确定具体补丁版本。
"""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import time
import uuid
import zlib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

# 厂商应急修复版本（与原 PoC 保持一致）
FIX_VERSIONS: dict[str, tuple[int, int, int]] = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
MAX_BODY = 16384
MAX_SCAN_TEXT = 8192
MAX_REDIRECTS = 4

STATUS_LABELS: dict[str, str] = {
    "likely_vulnerable": "疑似漏洞",
    "branch_only": "分支未知",
    "php_no_version": "PHP版本未知",
    "patched": "已修复",
    "eol_or_unknown": "EOL/未知",
    "no_php_version": "未发现PHP",
    "unreachable": "无法访问",
    "error": "错误",
}

STATUS_SEVERITY: dict[str, int] = {
    "likely_vulnerable": 0,
    "branch_only": 1,
    "php_no_version": 2,
    "eol_or_unknown": 3,
    "no_php_version": 4,
    "patched": 5,
    "unreachable": 6,
    "error": 7,
}

SUSPICIOUS_STATUSES = ("likely_vulnerable", "branch_only", "php_no_version")

PHP_CONFIDENCE_LABELS: dict[str, str] = {
    "confirmed": "确认PHP",
    "likely": "疑似PHP",
    "unlikely": "未发现PHP",
    "unknown": "未检测",
}

_SKIP_HEADERS = {
    "domain",
    "host",
    "url",
    "target",
    "site",
    "website",
    "域名",
    "网址",
    "地址",
    "网站",
}

_PHP_RE = re.compile(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", re.I)

_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "identity",
    "Connection": "close",
}

_COOKIE_NAME_RE = re.compile(r"(?:^|[;,])\s*([A-Za-z0-9_.\-]+)=")
_COOKIE_ATTRS = {
    "expires",
    "path",
    "domain",
    "max-age",
    "secure",
    "httponly",
    "samesite",
    "priority",
    "partitioned",
    "version",
}
_DRUPAL_COOKIE_RE = re.compile(r"^(?:sess|ssess)[0-9a-f]{16,}$")
_PHP_LINK_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["'][^"']*\.php(?:[?#"']|$)""", re.I
)
_PHP_ERROR_RE = re.compile(
    r"(?:PHP\s+(?:Warning|Fatal error|Parse error|Notice|Deprecated)"
    r"|<b>(?:Warning|Fatal error|Parse error)</b>"
    r"|Stack trace:\s*#0)",
    re.I,
)
_FILE_NOT_FOUND = re.compile(r"file\s+not\s+found", re.I)

_BODY_STRONG_SIGNALS: tuple[tuple[str, str], ...] = (
    ("wp-content", "页面含 wp-content（WordPress）"),
    ("wp-includes", "页面含 wp-includes（WordPress）"),
    ("wp-json", "页面含 wp-json（WordPress）"),
    ("wp-login.php", "页面含 wp-login.php（WordPress）"),
    ('content="wordpress', "meta generator 指向 WordPress"),
    ("/sites/default/files", "页面含 Drupal 路径特征"),
    ('content="drupal', "meta generator 指向 Drupal"),
    ("media/system/js/", "页面含 Joomla 路径特征"),
    ("phpsessid", "页面出现 PHPSESSID"),
    ("<?php", "响应包含 PHP 源码片段"),
    ("laravel_session", "页面出现 Laravel 会话标识"),
    ("ci_session", "页面出现 CodeIgniter 会话标识"),
)

_BODY_MEDIUM_SIGNALS: tuple[tuple[str, str], ...] = (
    ("thinkphp", "页面含 ThinkPHP 特征"),
    ("laravel", "页面含 Laravel 特征"),
    ("symfony", "页面含 Symfony 特征"),
    ("codeigniter", "页面含 CodeIgniter 特征"),
    ("yii framework", "页面含 Yii 特征"),
    ("wordpress", "页面含 WordPress 字样"),
    ("drupal", "页面含 Drupal 字样"),
    ("joomla", "页面含 Joomla 字样"),
    ("discuz", "页面含 Discuz 特征"),
    ("dedecms", "页面含 DedeCMS 特征"),
    ("phpcms", "页面含 PHPCMS 特征"),
    ("phpbb", "页面含 phpBB 特征"),
    ("phpmyadmin", "页面含 phpMyAdmin 特征"),
)


def _cookie_names(headers: dict[str, str]) -> set[str]:
    raw = headers.get("set-cookie", "")
    names: set[str] = set()
    if not raw:
        return names
    for match in _COOKIE_NAME_RE.finditer(raw):
        name = match.group(1).lower()
        if name not in _COOKIE_ATTRS:
            names.add(name)
    return names


def _body_digest(body: bytes) -> tuple[int, bytes]:
    sample = body[:4096]
    return len(sample), hashlib.sha1(sample).digest()


def _probe_base_url(final_url: str) -> str:
    parts = urlsplit(final_url)
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _dedupe_evidence(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _analyze_passive_signals(
    headers: dict[str, str],
    body: bytes,
    final_url: str,
    http_status: int = 200,
) -> list[tuple[str, str]]:
    signals: list[tuple[str, str]] = []

    names = _cookie_names(headers)
    for name in sorted(names):
        if name == "phpsessid":
            signals.append(("strong", "Set-Cookie: PHPSESSID"))
        elif name.startswith("laravel_session"):
            signals.append(("strong", "Set-Cookie: laravel_session（Laravel）"))
        elif name.startswith("ci_session"):
            signals.append(("strong", "Set-Cookie: ci_session（CodeIgniter）"))
        elif name.startswith("wordpress_") or name.startswith("wp-settings") or name.startswith("wp_"):
            signals.append(("strong", f"Set-Cookie: {name}（WordPress）"))
        elif name.startswith("joomla_"):
            signals.append(("strong", f"Set-Cookie: {name}（Joomla）"))
        elif _DRUPAL_COOKIE_RE.match(name):
            signals.append(("strong", f"Set-Cookie: {name}（Drupal）"))
        elif name == "xsrf-token":
            signals.append(("medium", "Set-Cookie: XSRF-TOKEN（可能为 Laravel）"))

    powered = headers.get("x-powered-by", "")
    if "php" in powered.lower():
        signals.append(("strong", "X-Powered-By 提及 PHP"))
    server = headers.get("server", "")
    if "php" in server.lower():
        signals.append(("strong", "Server 提及 PHP"))
    link = headers.get("link", "")
    if "wp-json" in link.lower():
        signals.append(("strong", "Link 头指向 WordPress wp-json"))
    pingback = headers.get("x-pingback", "")
    if "xmlrpc.php" in pingback.lower():
        signals.append(("strong", "X-Pingback 指向 xmlrpc.php（WordPress）"))
    for key in ("x-drupal-cache", "x-drupal-dynamic-cache"):
        if key in headers:
            signals.append(("strong", "响应头含 Drupal 缓存标识"))
            break
    generator = headers.get("x-generator", "").lower()
    if "wordpress" in generator:
        signals.append(("strong", "X-Generator 指向 WordPress"))
    elif "drupal" in generator:
        signals.append(("strong", "X-Generator 指向 Drupal"))
    expires = headers.get("expires", "").lower()
    cache_control = headers.get("cache-control", "").lower()
    pragma = headers.get("pragma", "").lower()
    if "19 nov 1981" in expires:
        signals.append(("strong", "Expires: 1981-11-19（PHP session 缓存头）"))
    elif (
        "no-store" in cache_control
        and "no-cache" in cache_control
        and "must-revalidate" in cache_control
        and "no-cache" in pragma
    ):
        signals.append(("medium", "会话缓存头三件套（常见 PHP session）"))
    if "x-fastcgi-cache" in headers:
        signals.append(("medium", "X-FastCGI-Cache（PHP FastCGI）"))
    if "litespeed" in server.lower() or "x-litespeed-cache" in headers or "x-lsadc-cache" in headers:
        signals.append(("medium", "LiteSpeed 环境（常见 PHP 主机）"))
    for key, value in headers.items():
        if key in ("x-powered-by", "server", "set-cookie"):
            continue
        lowered = value.lower()
        if "php" in key.lower() or "php" in lowered:
            signals.append(("medium", f"响应头 {key} 提及 PHP"))
            break

    text = body[:MAX_SCAN_TEXT].decode("latin-1", "replace")
    lowered_body = text.lower()
    for needle, label in _BODY_STRONG_SIGNALS:
        if needle in lowered_body:
            signals.append(("strong", label))
    for needle, label in _BODY_MEDIUM_SIGNALS:
        if needle in lowered_body:
            signals.append(("medium", label))
    if _PHP_LINK_RE.search(text):
        signals.append(("medium", "页面含 .php 链接"))
    if _PHP_ERROR_RE.search(text):
        signals.append(("strong", "页面含 PHP 错误信息"))

    ctype = headers.get("content-type", "").lower()
    path = urlsplit(final_url).path.lower()
    if "application/x-httpd-php" in ctype:
        signals.append(("strong", "Content-Type 为 application/x-httpd-php"))
    if (
        200 <= http_status < 300
        and path.endswith(".php")
        and "text/html" in ctype
        and "<?php" not in lowered_body
    ):
        signals.append(("strong", "目标 .php 页面返回 HTML（已被 PHP 执行）"))

    return signals


def _confidence_from_signals(signals: list[tuple[str, str]]) -> str:
    levels = {level for level, _ in signals}
    if "strong" in levels:
        return "confirmed"
    if "medium" in levels:
        return "likely"
    return "unlikely"


def _extract_php_version(
    headers: dict[str, str],
    body: bytes,
    prefix: str = "",
) -> tuple[ParsedPhpVersion | None, str]:
    powered = headers.get("x-powered-by", "")
    parsed = parse_php_version_detailed(powered)
    source = "header"
    if not parsed and headers.get("server"):
        parsed = parse_php_version_detailed(headers["server"])
        source = "server"
    if not parsed:
        text = body[:MAX_SCAN_TEXT].decode("latin-1", "replace")
        parsed = parse_php_version_detailed(text)
        source = "body"
    if not parsed:
        return None, ""
    if prefix:
        source = f"{prefix}: {source}"
    return parsed, source


@dataclass
class ParsedPhpVersion:
    major: int
    minor: int
    patch: int
    patch_known: bool

    def as_tuple(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def as_str(self) -> str:
        if self.patch_known:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}.?"


def parse_php_version_detailed(text: str) -> ParsedPhpVersion | None:
    """解析 PHP/x.y 或 PHP/x.y.z（必须带 PHP 标识，避免误匹配 WordPress 版本）。"""
    if not text:
        return None
    m = _PHP_RE.search(text)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch_known = m.group(3) is not None
    patch = int(m.group(3)) if patch_known else 0
    if not _is_plausible_php_version((major, minor, patch)):
        return None
    return ParsedPhpVersion(major, minor, patch, patch_known)


def _is_plausible_php_version(ver: tuple[int, int, int]) -> bool:
    major, minor, _patch = ver
    if major < 4 or major > 8:
        return False
    if major == 8 and minor > 5:
        return False
    if major == 7 and minor > 4:
        return False
    return True


def is_vulnerable_php(
    ver: tuple[int, int, int] | None,
    *,
    patch_known: bool = True,
) -> bool | None:
    if ver is None:
        return None
    if not patch_known:
        return None
    major, minor, _patch = ver
    if major < 5:
        return False
    if major == 8 and minor in (0, 1):
        return None
    key = f"{major}.{minor}"
    fix = FIX_VERSIONS.get(key)
    if fix is None:
        return True if major >= 5 else False
    return ver < fix


def classify(
    http_status: int,
    php_version: str | None,
    patch_known: bool | None,
    likely_vulnerable: bool | None,
) -> str:
    if not http_status:
        return "unreachable"
    if not php_version:
        return "no_php_version"
    if patch_known is False:
        return "branch_only"
    if likely_vulnerable is True:
        return "likely_vulnerable"
    if likely_vulnerable is False:
        return "patched"
    return "eol_or_unknown"


def normalize_targets(text: str) -> list[str]:
    """按行解析目标；支持注释、CSV 第一列，自动补 https:// 并去重。"""
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip().strip('"').strip("'").strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].strip()
        if not token:
            continue
        token = token.split()[0]
        if token.lower() in _SKIP_HEADERS:
            continue
        url = token if "://" in token else "https://" + token
        key = url.lower().rstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out


def _decompress(body: bytes, headers: dict[str, str]) -> bytes:
    encoding = (headers.get("content-encoding") or "").lower()
    if not body or not encoding:
        return body
    try:
        if "gzip" in encoding:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body)
    except Exception:
        return body
    return body


def _request(url: str, timeout: float) -> tuple[int, bytes, dict[str, str]]:
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("无效地址")
    host = parts.hostname
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        host = host.encode("idna").decode("ascii")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    port = parts.port

    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except ssl.SSLError:
            pass
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ctx
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request("GET", path, headers=_HEADERS)
        resp = conn.getresponse()
        try:
            body = resp.read(MAX_BODY)
        except Exception:
            body = b""
        headers: dict[str, str] = {}
        for key, value in resp.getheaders():
            low = key.lower()
            if low in headers:
                headers[low] += ", " + value
            else:
                headers[low] = value
        status = int(resp.status)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return status, _decompress(body, headers), headers


def _fetch_follow(
    url: str, timeout: float
) -> tuple[int, bytes, dict[str, str], str, list[str]]:
    current = url
    status = 0
    body = b""
    headers: dict[str, str] = {}
    visited: list[str] = []
    for _ in range(MAX_REDIRECTS + 1):
        status, body, headers = _request(current, timeout)
        visited.append(current)
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(current, location.strip())
            if urlsplit(nxt).scheme.lower() not in ("http", "https"):
                break
            current = nxt
            continue
        break
    return status, body, headers, current, visited


def _friendly_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "连接超时"
    if isinstance(exc, ConnectionRefusedError):
        return "连接被拒绝"
    if isinstance(exc, socket.gaierror):
        return "域名解析失败"
    if isinstance(exc, ssl.SSLError):
        return f"SSL 错误: {exc}"
    if isinstance(exc, http.client.RemoteDisconnected):
        return "连接被服务器关闭"
    if isinstance(exc, http.client.HTTPException):
        return f"HTTP 异常: {type(exc).__name__}"
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, OSError):
        return f"网络错误: {exc}"
    return f"{type(exc).__name__}: {exc}"


def _version_sort_key(version: str | None) -> tuple[int, int, int]:
    if not version:
        return (0, 0, 0)
    nums = re.findall(r"\d+", version)
    out = [int(n) for n in nums[:3]]
    while len(out) < 3:
        out.append(0)
    return out[0], out[1], out[2]


def _probe_php(
    final_url: str,
    baseline: tuple[int, bytes, dict[str, str]],
    timeout: float,
) -> dict[str, Any]:
    """增强识别：index.php 可达性 + 随机 .php/.html 差异，最多 3 个 GET。"""
    baseline_status, baseline_body, baseline_headers = baseline
    base_url = _probe_base_url(final_url)
    index_url = urljoin(base_url, "index.php")
    final_parts = urlsplit(final_url)
    index_parts = urlsplit(index_url)
    reuse_baseline = (
        final_parts.path.rstrip("/").endswith("/index.php")
        and final_parts.path == index_parts.path
        and final_parts.netloc == index_parts.netloc
    )

    signals: list[tuple[str, str]] = []
    ok = 0
    total = 0

    index_status, index_body, index_headers = 0, b"", {}
    if reuse_baseline:
        index_status, index_body, index_headers = (
            baseline_status,
            baseline_body,
            baseline_headers,
        )
    else:
        total += 1
        try:
            index_status, index_body, index_headers = _request(index_url, timeout)
            ok += 1
        except Exception:
            index_status, index_body, index_headers = 0, b"", {}

    token = uuid.uuid4().hex[:10]
    php_status, php_body, php_headers = 0, b"", {}
    html_status, html_body, html_headers = 0, b"", {}
    for kind, url in (
        ("php", urljoin(base_url, f"php2shell-{token}.php")),
        ("html", urljoin(base_url, f"php2shell-{token}.html")),
    ):
        total += 1
        try:
            status, body, headers = _request(url, timeout)
            ok += 1
        except Exception:
            status, body, headers = 0, b"", {}
        if kind == "php":
            php_status, php_body, php_headers = status, body, headers
        else:
            html_status, html_body, html_headers = status, body, headers

    if index_status:
        signals.extend(
            _analyze_passive_signals(
                index_headers, index_body, index_url, index_status
            )
        )
        ctype = index_headers.get("content-type", "").lower()
        index_digest = _body_digest(index_body)
        php_digest = _body_digest(php_body)
        html_digest = _body_digest(html_body)
        random_ok = php_status > 0 or html_status > 0
        soft_404 = (
            index_status == 200
            and php_status == 200
            and html_status == 200
            and index_digest == php_digest == html_digest
        )

        if "application/x-httpd-php" in ctype:
            signals.append(("strong", "index.php 返回 application/x-httpd-php"))
        if index_status == 200 and random_ok and not soft_404:
            if "text/html" in ctype:
                if php_status != 200 or php_digest != index_digest:
                    signals.append(("strong", "index.php 返回 HTML 且与随机路径不同"))
                else:
                    signals.append(("medium", "index.php 可访问"))
            elif "text/plain" in ctype or "octet-stream" in ctype:
                if "<?php" in index_body[:4096].decode("latin-1", "replace").lower():
                    signals.append(("medium", "index.php 源码可下载（服务器含 PHP 文件）"))
        if index_status in (301, 302, 303, 307, 308) and index_headers.get("location"):
            location = index_headers["location"].lower()
            if ".php" in location or "login" in location or "admin" in location:
                signals.append(("medium", "index.php 触发动态跳转"))
        if index_status == 500 and _PHP_ERROR_RE.search(
            index_body[:MAX_SCAN_TEXT].decode("latin-1", "replace")
        ):
            signals.append(("strong", "index.php 返回 PHP 错误信息"))

    if php_status and html_status:
        php_text = php_body[:MAX_SCAN_TEXT].decode("latin-1", "replace")
        php_ctype = php_headers.get("content-type", "").lower()
        if php_status in (404, 500) and _FILE_NOT_FOUND.search(php_text[:2048]):
            signals.append(("strong", "PHP-FPM 返回 File not found"))
        if (
            php_status == 200
            and "text/html" in php_ctype
            and _body_digest(php_body) != _body_digest(html_body)
        ):
            signals.append(("medium", "随机 .php 由动态路由处理"))
        if php_status == 500 and html_status != 500:
            signals.append(("medium", "随机 .php 返回 500"))
        if (
            php_status == 404
            and html_status == 404
            and _body_digest(php_body) != _body_digest(html_body)
        ):
            signals.append(("medium", "PHP 404 与静态 404 不同"))
        if "<?php" in php_text.lower():
            signals.append(("strong", "随机 .php 返回 PHP 源码片段"))

    version, version_source = (None, "")
    if index_status:
        version, version_source = _extract_php_version(
            index_headers, index_body, "index.php"
        )

    return {
        "signals": signals,
        "ok": ok,
        "total": total,
        "version": version,
        "version_source": version_source,
        "headers": index_headers,
    }


def _deep_confirm(
    final_url: str,
    baseline: tuple[int, bytes, dict[str, str]],
    timeout: float,
) -> dict[str, Any]:
    """深度确认：PATH_INFO 探测，仅在仍为“疑似PHP”且用户勾选时调用（2 个 GET）。"""
    base_url = _probe_base_url(final_url)
    token = uuid.uuid4().hex[:10]
    signals: list[tuple[str, str]] = []
    ok = 0
    total = 0
    results: dict[str, tuple[int, bytes, dict[str, str]]] = {}

    for kind, name in (("php", "index.php"), ("html", "index.html")):
        url = urljoin(base_url, f"{name}/php2shell-{token}")
        total += 1
        try:
            status, body, headers = _request(url, timeout)
            ok += 1
        except Exception:
            status, body, headers = 0, b"", {}
        results[kind] = (status, body, headers)
        if status:
            signals.extend(_analyze_passive_signals(headers, body, url, status))

    php_status, php_body, php_headers = results["php"]
    html_status, html_body, html_headers = results["html"]
    php_text = php_body[:MAX_SCAN_TEXT].decode("latin-1", "replace")
    php_digest = _body_digest(php_body)
    html_digest = _body_digest(html_body)

    if php_status == 200 and html_status != 200:
        signals.append(
            ("strong", "PATH_INFO: index.php/<随机> 返回 200，静态同类非 200")
        )
    elif (
        php_status == 200
        and html_status == 200
        and php_digest != html_digest
    ):
        signals.append(
            ("medium", "PATH_INFO 下 index.php 与 index.html 内容不同")
        )
    if php_status in (403, 404, 500) and _FILE_NOT_FOUND.search(php_text[:2048]):
        signals.append(("strong", "PATH_INFO 由 PHP-FPM 处理（File not found）"))
    if php_status == 500 and html_status != 500:
        signals.append(("strong", "index.php/<随机> 返回 500（PHP 执行错误）"))
    if "<?php" in php_text.lower():
        signals.append(("strong", "index.php/<随机> 返回 PHP 源码片段"))
    if (
        php_status == 200
        and baseline[0] == 200
        and php_digest == _body_digest(baseline[1])
    ):
        signals.append(
            ("strong", "index.php/<随机> 返回与应用页相同（PATH_INFO 执行）")
        )

    return {"signals": signals, "ok": ok, "total": total}


def check_target(
    raw: str,
    *,
    timeout: float = 10.0,
    retries: int = 1,
    enhanced: bool = True,
    deep: bool = False,
) -> dict[str, Any]:
    """检测单个目标。返回统一结构的结果字典。"""
    started = time.perf_counter()
    raw = (raw or "").strip()
    base_row: dict[str, Any] = {
        "input": raw,
        "target": raw,
        "final_url": "",
        "http_status": 0,
        "status": "unreachable",
        "php_version": None,
        "php_patch_known": None,
        "likely_vulnerable": None,
        "php_detected": "unknown",
        "php_evidence": [],
        "php_probes": 0,
        "x_powered_by": "",
        "server": "",
        "php_version_source": "",
        "redirects": [],
        "error": "",
        "elapsed_ms": 0,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if not raw:
        base_row["status"] = "error"
        base_row["error"] = "空地址"
        base_row["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return base_row

    explicit_scheme = "://" in raw
    candidates = [raw] if explicit_scheme else ["https://" + raw, "http://" + raw]
    errors: list[str] = []
    attempts = max(0, min(int(retries), 5)) + 1

    for url in candidates:
        for attempt in range(attempts):
            try:
                status, body, headers, final_url, visited = _fetch_follow(url, timeout)
                if status <= 0:
                    raise ConnectionError("无 HTTP 响应")

                powered = headers.get("x-powered-by", "")
                server = headers.get("server", "")
                parsed, source = _extract_php_version(headers, body)
                signals = _analyze_passive_signals(headers, body, final_url, status)
                probe_ok = 0
                probe_total = 0

                if parsed is None and enhanced and status not in (429,):
                    probe = _probe_php(final_url, (status, body, headers), timeout)
                    probe_ok = int(probe["ok"])
                    probe_total = int(probe["total"])
                    signals.extend(probe["signals"])
                    if probe["version"] is not None:
                        parsed = probe["version"]
                        source = str(probe["version_source"])
                        if probe["headers"].get("x-powered-by") and not powered:
                            powered = probe["headers"]["x-powered-by"]
                    if probe["headers"].get("x-powered-by") and not powered:
                        powered = probe["headers"]["x-powered-by"]

                if parsed is not None:
                    php_detected = "confirmed"
                else:
                    php_detected = _confidence_from_signals(signals)
                    if php_detected == "unlikely" and enhanced and probe_ok == 0:
                        php_detected = "unknown"
                    if not enhanced and not signals:
                        php_detected = "unknown"
                    if deep and php_detected == "likely" and status not in (429,):
                        extra = _deep_confirm(
                            final_url, (status, body, headers), timeout
                        )
                        probe_ok += int(extra["ok"])
                        probe_total += int(extra["total"])
                        signals.extend(extra["signals"])
                        php_detected = _confidence_from_signals(signals)

                ver = parsed.as_tuple() if parsed else None
                patch_known = parsed.patch_known if parsed else None
                vuln = (
                    is_vulnerable_php(ver, patch_known=bool(patch_known))
                    if parsed
                    else None
                )
                version_str = parsed.as_str() if parsed else None
                if parsed is not None:
                    status_value = classify(status, version_str, patch_known, vuln)
                elif php_detected in ("confirmed", "likely"):
                    status_value = "php_no_version"
                else:
                    status_value = "no_php_version"

                evidence = _dedupe_evidence([text for _, text in signals])

                base_row.update(
                    {
                        "target": final_url,
                        "final_url": final_url,
                        "http_status": status,
                        "status": status_value,
                        "php_version": version_str,
                        "php_patch_known": patch_known,
                        "likely_vulnerable": vuln,
                        "php_detected": php_detected,
                        "php_evidence": evidence,
                        "php_probes": probe_total,
                        "x_powered_by": powered,
                        "server": server,
                        "php_version_source": source,
                        "redirects": visited[:-1] if len(visited) > 1 else [],
                        "error": "",
                        "elapsed_ms": int((time.perf_counter() - started) * 1000),
                    }
                )
                return base_row
            except Exception as exc:
                message = _friendly_error(exc)
                errors.append(f"{url} -> {message}")
                if attempt + 1 < attempts:
                    time.sleep(0.35)

    base_row["error"] = " / ".join(errors[-3:])
    base_row["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    return base_row


def version_sort_key(version: str | None) -> tuple[int, int, int]:
    """供界面按 PHP 版本排序。"""
    return _version_sort_key(version)
