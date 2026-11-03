#!/usr/bin/env python3
"""HTTP regressions on an explicitly disposable WordPress installation only."""
from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wp-path", type=Path, required=True)
    parser.add_argument("--wp-cli", default="wp")
    parser.add_argument("--php", default="php")
    arguments = parser.parse_args()
    root = arguments.wp_path.resolve()
    php = shutil.which(arguments.php)
    if php is None or not (root / "wp-load.php").is_file():
        raise RuntimeError("PHP and the disposable WordPress installation are required")
    cli = [php, arguments.wp_cli] if arguments.wp_cli.endswith(".phar") else [arguments.wp_cli]
    common = ["--path=" + str(root), "--no-color"]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        common.append("--allow-root")

    def wp(*items: str) -> str:
        result = subprocess.run(cli + list(items) + common, text=True, capture_output=True, check=True, timeout=45)
        return result.stdout.strip()

    if wp("config", "get", "FSU_ISOLATED_TEST", "--type=constant").lower() not in {"true", "1"}:
        raise RuntimeError("Refusing a site without the explicit FSU_ISOLATED_TEST=true test constant")
    password = os.environ.get("FSU_TEST_PASSWORD")
    if not password:
        raise RuntimeError("Set FSU_TEST_PASSWORD to the disposable fixture password")
    original = {key: wp("option", "get", key) for key in ("home", "siteurl")}
    fixture = root / "wp-content/mu-plugins/fsu-http-export-fixture.php"
    if fixture.exists() or fixture.is_symlink():
        raise RuntimeError("Refusing to replace an existing fixture file")
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    server = None
    try:
        for key in original:
            wp("option", "update", key, base)
        fixture.write_text("""<?php
// Disposable integration fixture; this file is never part of the plugin ZIP.
add_action('admin_init', static function () {
    if (($_POST['action'] ?? '') !== 'fsu_export') { return; }
    $mode = $_SERVER['HTTP_X_FSU_TEST_OUTPUT'] ?? '';
    if ($mode === 'buffer' || $mode === 'gzip') {
        ob_start($mode === 'gzip' ? 'ob_gzhandler' : null);
        echo '<!-- FSU_PRELUDE_PRIVATE_PATH -->';
    }
    if ($mode === 'buffer' || $mode === 'gzip') {
        add_action('shutdown', static function () { echo 'FSU_WORDPRESS_SHUTDOWN_PRIVATE'; }, 999);
        register_shutdown_function(static function () { echo 'FSU_PHP_SHUTDOWN_PRIVATE'; });
    }
});
""", encoding="utf-8")
        with tempfile.TemporaryFile() as server_log:
            server = subprocess.Popen([php, "-S", f"127.0.0.1:{port}", "-t", str(root)], stdout=server_log, stderr=server_log)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(CookieJar()))
            for _ in range(50):
                try:
                    opener.open(base + "/wp-login.php", timeout=2).read()
                    break
                except OSError:
                    if server.poll() is not None:
                        raise RuntimeError("Isolated PHP server failed to start")
                    time.sleep(0.1)
            else:
                raise RuntimeError("Isolated PHP server readiness timed out")
            credentials = urllib.parse.urlencode({"log": os.environ.get("FSU_TEST_USER", "fsu-admin"), "pwd": password,
                                                "wp-submit": "Log In", "redirect_to": base + "/wp-admin/", "testcookie": "1"}).encode()
            opener.open(base + "/wp-login.php", credentials, timeout=30).read()
            page = opener.open(base + "/wp-admin/admin.php?page=fortress-security-ultimate", timeout=30).read().decode()
            form = next((item for item in re.findall(r"<form\b[^>]*>(.*?)</form>", page, re.S) if 'value="fsu_export"' in item), None)
            if form is None:
                raise RuntimeError("Administrator export form is unavailable")
            nonce = re.search(r'name="_wpnonce" value="([^"]+)"', form).group(1)
            versions = []
            for mode in ("clean", "buffer", "gzip"):
                request = urllib.request.Request(base + "/wp-admin/admin-post.php",
                    urllib.parse.urlencode({"action": "fsu_export", "_wpnonce": nonce, "hours": "1"}).encode(),
                    headers={"X-FSU-Test-Output": mode, "Accept-Encoding": "gzip"})
                response = opener.open(request, timeout=30)
                body = response.read()
                if response.status != 200 or not body.startswith(b"PK"):
                    raise RuntimeError("Export did not return an unprefixed ZIP in " + mode)
                if response.headers.get("Content-Encoding") not in (None, "identity"):
                    raise RuntimeError("Discarded compression handler left an incompatible encoding header")
                if int(response.headers["Content-Length"]) != len(body):
                    raise RuntimeError("Archive content length does not match in " + mode)
                for marker in (b"FSU_PRELUDE_PRIVATE_PATH", b"FSU_WORDPRESS_SHUTDOWN_PRIVATE", b"FSU_PHP_SHUTDOWN_PRIVATE"):
                    if marker in body:
                        raise RuntimeError("Foreign output leaked into the ZIP in " + mode)
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    if archive.testzip() is not None:
                        raise RuntimeError("Invalid archive CRC in " + mode)
                    versions.append(json.loads(archive.read("environment.json"))["version"])
                print("PASS HTTP ZIP " + mode + ": clean headers, exact length, no prefix or shutdown output")
            if len(set(versions)) != 1:
                raise RuntimeError("Export metadata version changed during the regression test")
            try:
                opener.open(base + "/wp-admin/admin-post.php", urllib.parse.urlencode({"action": "fsu_export", "_wpnonce": "invalid", "hours": "1"}).encode(), timeout=30)
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise RuntimeError("Invalid nonce did not return HTTP 403") from error
            else:
                raise RuntimeError("Invalid nonce was accepted")
            print("PASS HTTP invalid nonce rejected; plugin version=" + versions[0])
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)
        fixture.unlink(missing_ok=True)
        for key, value in original.items():
            wp("option", "update", key, value)


if __name__ == "__main__":
    main()
