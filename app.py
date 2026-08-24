#!/usr/bin/env python3
"""
Small internal web console for creating Tencent EdgeOne zones in batches.

This app intentionally keeps dependencies to the Python standard library. It
delegates all zone creation work to the existing tencent_eo_origin_tool.py in a
tx-eo checkout, so the operational behavior stays aligned with the migration
tooling already used in production.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


DEFAULT_CONFIG_JSON = "eo-zone-configs/178zq2.com_zone-3rrr4v0d08us.json"
DEFAULT_PLAN_ID = "edgeone-3rr130q221d0"
DEFAULT_AREA = "overseas"
DEFAULT_OUTPUT_ROOT = "onboard-results-web"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8088
DEFAULT_PRESETS_JSON = "presets.json"

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "item"


def split_domains(value: str) -> list[str]:
    raw = re.split(r"[\s,;]+", value.strip())
    domains: list[str] = []
    seen: set[str] = set()
    for item in raw:
        domain = item.strip().lower().strip(".")
        if not domain or domain in seen:
            continue
        if not DOMAIN_RE.match(domain) or domain.startswith("*."):
            raise ValueError(f"invalid zone name: {item}")
        domains.append(domain)
        seen.add(domain)
    return domains


def load_tool_module(tx_eo_dir: Path):
    tool = tx_eo_dir / "tencent_eo_origin_tool.py"
    if not tool.exists():
        raise RuntimeError(f"tencent_eo_origin_tool.py not found in {tx_eo_dir}")
    if str(tx_eo_dir) not in sys.path:
        sys.path.insert(0, str(tx_eo_dir))
    import tencent_eo_origin_tool as teo  # type: ignore

    return teo


class Job:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.id = dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        self.payload = payload
        self.status = "queued"
        self.created_at = now_iso()
        self.started_at = ""
        self.finished_at = ""
        self.logs: list[str] = []
        self.results: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def log(self, message: str) -> None:
        with self.lock:
            self.logs.append(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}")
            if len(self.logs) > 3000:
                self.logs = self.logs[-3000:]

    def set_status(self, status: str) -> None:
        with self.lock:
            self.status = status

    def add_result(self, result: dict[str, Any]) -> None:
        with self.lock:
            self.results.append(result)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "id": self.id,
                "status": self.status,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "payload": self.payload,
                "logs": list(self.logs),
                "results": list(self.results),
            }


class AppState:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.tx_eo_dir = Path(args.tx_eo_dir).resolve()
        presets_path = Path(args.presets_json)
        if not presets_path.is_absolute():
            presets_path = Path(__file__).resolve().parent / presets_path
        self.presets_path = presets_path
        self.jobs: dict[str, Job] = {}
        self.queue: queue.Queue[Job] = queue.Queue()
        self.template_cache: dict[str, Any] = {"loaded_at": 0.0, "items": []}
        self.lock = threading.Lock()

    def create_job(self, payload: dict[str, Any]) -> Job:
        job = Job(payload)
        with self.lock:
            self.jobs[job.id] = job
        self.queue.put(job)
        return job

    def get_job(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)


def load_presets() -> dict[str, Any]:
    if not STATE.presets_path.exists():
        return {"origin_cname_presets": [], "dns_env_presets": [STATE.args.dns_env_file]}
    with STATE.presets_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    origin_presets = data.get("origin_cname_presets") or []
    dns_env_presets = data.get("dns_env_presets") or [STATE.args.dns_env_file]
    if not isinstance(origin_presets, list):
        origin_presets = []
    if not isinstance(dns_env_presets, list):
        dns_env_presets = [STATE.args.dns_env_file]
    return {
        "origin_cname_presets": origin_presets,
        "dns_env_presets": dns_env_presets,
    }


STATE: AppState


def load_templates(refresh: bool = False) -> list[dict[str, Any]]:
    ttl = 120
    if not refresh and STATE.template_cache["items"] and time.time() - STATE.template_cache["loaded_at"] < ttl:
        return STATE.template_cache["items"]

    teo = load_tool_module(STATE.tx_eo_dir)

    class Args:
        env_file = STATE.args.env_file
        endpoint = "teo.tencentcloudapi.com"
        retries = 20
        sleep = 0.2
        limit = 100

    client = teo.require_credentials(Args())
    zones = teo.paged_call(client, "DescribeZones", {}, ("Zones",), 100)
    zone_names = {z.get("ZoneId"): z.get("ZoneName") for z in zones}
    templates: list[dict[str, Any]] = []

    zone_ids = [zid for zid in zone_names if zid]
    for idx in range(0, len(zone_ids), 50):
        chunk = zone_ids[idx : idx + 50]
        try:
            for item in teo.describe_web_security_templates(client, chunk):
                template_id = item.get("TemplateId") or item.get("SecurityPolicyTemplateId")
                template_name = item.get("TemplateName") or item.get("Name") or ""
                zone_id = item.get("ZoneId") or ""
                if not template_id:
                    continue
                templates.append(
                    {
                        "template_id": template_id,
                        "template_name": template_name,
                        "zone_id": zone_id,
                        "zone_name": zone_names.get(zone_id, ""),
                        "bind_count": item.get("BindCount") or item.get("EntityCount") or "",
                    }
                )
        except Exception:
            # Keep scanning other chunks; the UI will still show what was fetched.
            continue

    templates.sort(key=lambda x: (str(x.get("template_name") or ""), str(x.get("template_id") or "")))
    STATE.template_cache = {"loaded_at": time.time(), "items": templates}
    return templates


def read_zone_id_from_ownership(path: Path) -> str:
    if not path.exists():
        return ""
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return ""
    for key in ("zone_id", "ZoneId", "ZoneID"):
        value = rows[0].get(key)
        if value:
            return value
    for value in rows[0].values():
        if value and str(value).startswith("zone-"):
            return str(value)
    return ""


def bind_web_security_template(job: Job, zone_id: str, hosts: list[str], template_ref: str) -> None:
    if not template_ref:
        return
    try:
        template_zone_id, template_id = template_ref.split("|", 1)
    except ValueError:
        job.log(f"Web protection skipped: invalid template reference {template_ref}")
        return

    teo = load_tool_module(STATE.tx_eo_dir)

    class Args:
        env_file = STATE.args.env_file
        endpoint = "teo.tencentcloudapi.com"
        retries = 20
        sleep = 0.2
        limit = 100

    client = teo.require_credentials(Args())
    payloads = [
        {
            "ZoneId": template_zone_id,
            "TemplateId": template_id,
            "Entities": hosts,
            "Operate": "bind",
            "OverWrite": True,
        },
        {
            "ZoneId": template_zone_id,
            "TemplateId": template_id,
            "Entity": hosts,
            "Operate": "bind",
            "OverWrite": True,
        },
    ]

    last_error: Exception | None = None
    for payload in payloads:
        try:
            response = client.call("BindSecurityTemplateToEntity", payload)
            job.log(f"Web protection template bound to {', '.join(hosts)}: {json.dumps(response, ensure_ascii=False)}")
            return
        except Exception as exc:
            last_error = exc
    job.log(f"Web protection template bind failed for {', '.join(hosts)}: {last_error}")


def build_onboard_command(domain: str, payload: dict[str, Any], zone_output_dir: Path) -> list[str]:
    cmd = [
        sys.executable,
        str(STATE.tx_eo_dir / "tencent_eo_origin_tool.py"),
        "--env-file",
        str(payload["env_file"]),
        "--retries",
        str(payload.get("retries", 20)),
        "onboard-zone",
        "--zone-name",
        domain,
        "--area",
        payload["area"],
        "--plan-id",
        payload["plan_id"],
        "--dns-env-file",
        payload["dns_env_file"],
        "--dns-provider",
        payload["dns_provider"],
        "--verify-wait-seconds",
        str(payload["verify_wait_seconds"]),
        "--config-json",
        payload["config_json"],
        "--origin",
        payload["origin"],
        "--origin-type",
        payload["origin_type"],
        "--origin-protocol",
        payload["origin_protocol"],
        "--http-origin-port",
        str(payload["http_origin_port"]),
        "--https-origin-port",
        str(payload["https_origin_port"]),
        "--shared-cname",
        payload["shared_cname"],
        "--domain-names",
        f"*.{domain};{domain}",
        "--create-domain-retries",
        str(payload["create_domain_retries"]),
        "--create-domain-retry-wait-seconds",
        str(payload["create_domain_retry_wait_seconds"]),
        "--import-config-retries",
        str(payload["import_config_retries"]),
        "--import-config-retry-wait-seconds",
        str(payload["import_config_retry_wait_seconds"]),
        "--output-dir",
        str(zone_output_dir),
        "--apply",
        "--yes",
    ]
    if payload.get("host_header"):
        cmd.extend(["--host-header", payload["host_header"]])
    if payload.get("auto_cert", True):
        cmd.append("--auto-cert")
    if payload.get("enable_origin_acl", True):
        cmd.append("--enable-origin-acl")
    return cmd


def build_dns_cname_command(domain: str, payload: dict[str, Any], output_root: Path) -> list[str]:
    return [
        sys.executable,
        str(STATE.tx_eo_dir / "dns_txt_verify_tool.py"),
        "--env-file",
        payload["dns_env_file"],
        "--retries",
        str(payload.get("retries", 20)),
        "add-cname",
        "--zone-names",
        domain,
        "--records",
        "@,*",
        "--target",
        payload["shared_cname"],
        "--ttl",
        str(payload["dns_cname_ttl"]),
        "--out",
        str(output_root / f"dns-cname-{safe_name(domain)}.csv"),
        "--no-legacy-dnspod",
        "--domain-cache-json",
        str(output_root / "dns-domain-cache.json"),
        "--apply",
        "--yes",
    ]


def run_dns_cname(job: Job, domain: str, payload: dict[str, Any], output_root: Path) -> bool:
    cmd = build_dns_cname_command(domain, payload, output_root)
    job.log("DNS CNAME Command: " + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=str(STATE.tx_eo_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        job.log(line.rstrip())
    exit_code = proc.wait()
    if exit_code != 0:
        job.log(f"DNS CNAME failed for {domain}: exit {exit_code}")
        return False
    job.log(f"DNS CNAME configured for {domain}: @ and * -> {payload['shared_cname']}")
    return True


def run_job(job: Job) -> None:
    payload = job.payload
    job.started_at = now_iso()
    job.set_status("running")
    domains = payload["domains"]
    output_root = STATE.tx_eo_dir / payload["output_root"] / job.id
    output_root.mkdir(parents=True, exist_ok=True)
    job.log(f"Output: {output_root}")

    failures = 0
    for index, domain in enumerate(domains, 1):
        zone_output_dir = output_root / f"{index:03d}-{safe_name(domain)}"
        zone_output_dir.mkdir(parents=True, exist_ok=True)
        job.log(f"Start {index}/{len(domains)} {domain}")
        cmd = build_onboard_command(domain, payload, zone_output_dir)
        job.log("Command: " + " ".join(cmd))

        started = now_iso()
        proc = subprocess.Popen(
            cmd,
            cwd=str(STATE.tx_eo_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            job.log(line.rstrip())
        exit_code = proc.wait()
        finished = now_iso()
        zone_id = read_zone_id_from_ownership(zone_output_dir / f"ownership-{domain}.csv")

        status = "success" if exit_code == 0 else "failed"
        if exit_code == 0 and payload.get("web_template_ref") and zone_id:
            hosts = [f"*.{domain}", domain]
            bind_web_security_template(job, zone_id, hosts, payload["web_template_ref"])
        elif exit_code == 0 and payload.get("web_template_ref"):
            job.log(f"Web protection skipped for {domain}: zone id not found in ownership CSV")

        dns_cname_status = "skipped"
        if exit_code == 0 and payload.get("configure_dns_cname", False):
            dns_cname_status = "success" if run_dns_cname(job, domain, payload, output_root) else "failed"
            if dns_cname_status == "failed":
                status = "failed"
                exit_code = 2

        if exit_code != 0:
            failures += 1
        job.add_result(
            {
                "domain": domain,
                "status": status,
                "exit_code": exit_code,
                "zone_id": zone_id,
                "dns_cname_status": dns_cname_status,
                "output_dir": str(zone_output_dir),
                "started_at": started,
                "finished_at": finished,
            }
        )

    job.finished_at = now_iso()
    job.set_status("failed" if failures else "success")
    job.log(f"Completed: {len(domains) - failures} success, {failures} failed")


def worker_loop() -> None:
    while True:
        job = STATE.queue.get()
        try:
            run_job(job)
        except Exception:
            job.log(traceback.format_exc())
            job.finished_at = now_iso()
            job.set_status("failed")
        finally:
            STATE.queue.task_done()


def parse_create_payload(raw: dict[str, Any]) -> dict[str, Any]:
    domains = split_domains(str(raw.get("domains", "")))
    if not domains:
        raise ValueError("domains is required")
    origin = str(raw.get("origin", "")).strip()
    shared_cname = str(raw.get("shared_cname", "")).strip()
    if not origin:
        raise ValueError("origin is required")
    if not shared_cname:
        raise ValueError("shared cname is required")

    def int_value(key: str, default: int) -> int:
        value = raw.get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number")

    host_header_mode = raw.get("host_header_mode", "accelerated")
    host_header = ""
    if host_header_mode == "custom":
        host_header = str(raw.get("host_header", "")).strip()
        if not host_header:
            raise ValueError("custom host header is required when custom mode is selected")

    return {
        "domains": domains,
        "origin": origin,
        "shared_cname": shared_cname,
        "env_file": str(raw.get("env_file") or STATE.args.env_file),
        "dns_env_file": str(raw.get("dns_env_file") or STATE.args.dns_env_file),
        "dns_provider": str(raw.get("dns_provider") or "auto"),
        "plan_id": str(raw.get("plan_id") or STATE.args.plan_id),
        "area": str(raw.get("area") or STATE.args.area),
        "config_json": str(raw.get("config_json") or STATE.args.config_json),
        "output_root": str(raw.get("output_root") or STATE.args.output_root),
        "origin_type": str(raw.get("origin_type") or "IP_DOMAIN"),
        "origin_protocol": str(raw.get("origin_protocol") or "FOLLOW"),
        "http_origin_port": int_value("http_origin_port", 80),
        "https_origin_port": int_value("https_origin_port", 443),
        "host_header": host_header,
        "auto_cert": bool(raw.get("auto_cert", True)),
        "enable_origin_acl": bool(raw.get("enable_origin_acl", True)),
        "configure_dns_cname": bool(raw.get("configure_dns_cname", False)),
        "dns_cname_ttl": int_value("dns_cname_ttl", 600),
        "web_template_ref": str(raw.get("web_template_ref") or ""),
        "verify_wait_seconds": int_value("verify_wait_seconds", 5),
        "import_config_retries": int_value("import_config_retries", 60),
        "import_config_retry_wait_seconds": int_value("import_config_retry_wait_seconds", 10),
        "create_domain_retries": int_value("create_domain_retries", 30),
        "create_domain_retry_wait_seconds": int_value("create_domain_retry_wait_seconds", 20),
        "retries": int_value("retries", 20),
    }


HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EdgeOne 站点创建</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --line: #d8dee9;
      --text: #1f2937;
      --muted: #6b7280;
      --blue: #1463ff;
      --blue-dark: #0d47c8;
      --red: #c0342b;
      --green: #0a8f4b;
      --amber: #9a6700;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
    }
    header {
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 650;
      letter-spacing: 0;
    }
    main {
      display: grid;
      grid-template-columns: minmax(460px, 600px) 1fr;
      gap: 16px;
      padding: 16px;
      min-height: calc(100vh - 56px);
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
    }
    .form { padding: 18px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; }
    input, textarea, select {
      width: 100%;
      border: 1px solid #cfd6e2;
      border-radius: 4px;
      padding: 9px 10px;
      font: inherit;
      background: #fff;
      min-height: 38px;
    }
    textarea { min-height: 120px; resize: vertical; }
    .full { grid-column: 1 / -1; }
    .hint { color: var(--muted); font-size: 12px; margin-top: 4px; line-height: 1.4; }
    .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .check { display: flex; align-items: center; gap: 8px; font-weight: 500; }
    .check input { width: 16px; min-height: 16px; }
    details {
      border-top: 1px solid var(--line);
      margin-top: 16px;
      padding-top: 14px;
    }
    summary { cursor: pointer; font-weight: 650; }
    button {
      border: 1px solid var(--blue);
      background: var(--blue);
      color: #fff;
      border-radius: 4px;
      height: 38px;
      padding: 0 16px;
      font-weight: 650;
      cursor: pointer;
    }
    button.secondary { background: #fff; color: var(--blue); }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }
    .status { font-weight: 700; }
    .status.success { color: var(--green); }
    .status.failed { color: var(--red); }
    .status.running, .status.queued { color: var(--amber); }
    .results { padding: 0 16px 16px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 9px 6px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 650; }
    pre {
      margin: 0;
      height: 360px;
      overflow: auto;
      background: #101827;
      color: #d7e0ef;
      padding: 12px;
      border-radius: 0 0 6px 6px;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .split { display: grid; grid-template-rows: auto 1fr; min-height: 0; }
    .pill {
      display: inline-flex;
      align-items: center;
      height: 24px;
      padding: 0 8px;
      border-radius: 12px;
      background: #eef2ff;
      color: #273c94;
      font-size: 12px;
      font-weight: 650;
    }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>EdgeOne 站点创建</h1>
    <span class="pill">新账号批量创建 @ 和 *</span>
  </header>
  <main>
    <section class="form">
      <div class="grid">
        <div class="full">
          <label for="domains">站点域名</label>
          <textarea id="domains" placeholder="example.com&#10;example2.com"></textarea>
          <div class="hint">每行一个，也支持空格、逗号、分号分隔。每个站点会创建 <b>@</b> 和 <b>*</b> 两个加速域名。</div>
        </div>
        <div class="full">
          <label for="origin_cname_preset">源站 / 共享 CNAME 预设</label>
          <select id="origin_cname_preset">
            <option value="">自定义</option>
          </select>
          <div class="hint">选择后会自动填充下面的源站和共享 CNAME，仍然可以手动修改。</div>
        </div>
        <div>
          <label for="origin">源站</label>
          <input id="origin" placeholder="source-178.gtmvip.com">
        </div>
        <div>
          <label for="shared_cname">共享 CNAME</label>
          <input id="shared_cname" placeholder="178-web.3rr2n4ammrbn.share.dnse4.com">
        </div>
        <div>
          <label for="origin_protocol">回源协议</label>
          <select id="origin_protocol">
            <option value="FOLLOW">协议跟随</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
          </select>
        </div>
        <div>
          <label for="host_header_mode">回源 HOST 头</label>
          <select id="host_header_mode">
            <option value="accelerated">使用加速域名</option>
            <option value="custom">自定义</option>
          </select>
        </div>
        <div id="custom_host_wrap" style="display:none">
          <label for="host_header">自定义 HOST</label>
          <input id="host_header" placeholder="origin-host.example.com">
        </div>
        <div>
          <label for="web_template">Web 防护模板</label>
          <select id="web_template"><option value="">不关联</option></select>
          <div class="hint">从新账号实时拉取。模板绑定失败不会中断站点创建，会写日志。</div>
        </div>
        <div class="full row">
          <label class="check"><input id="auto_cert" type="checkbox" checked> 自动匹配 HTTPS 证书</label>
          <label class="check"><input id="enable_origin_acl" type="checkbox" checked> 开启源站防护</label>
          <label class="check"><input id="configure_dns_cname" type="checkbox"> 自动写 DNS CNAME（@ 和 *）</label>
          <button class="secondary" id="refresh_templates" type="button">刷新防护模板</button>
        </div>
      </div>
      <details>
        <summary>高级参数</summary>
        <div class="grid" style="margin-top:12px">
          <div><label for="config_json">配置模板 JSON</label><input id="config_json" value="__DEFAULT_CONFIG__"></div>
          <div><label for="plan_id">套餐 ID</label><input id="plan_id" value="__DEFAULT_PLAN__"></div>
          <div><label for="env_file">新账号 env</label><input id="env_file" value="tencent-eo-new.env"></div>
          <div>
            <label for="dns_env_preset">DNS env</label>
            <select id="dns_env_preset"></select>
            <input id="dns_env_file" value="dns-providers.env" style="margin-top:8px">
          </div>
          <div><label for="http_origin_port">HTTP 回源端口</label><input id="http_origin_port" type="number" value="80"></div>
          <div><label for="https_origin_port">HTTPS 回源端口</label><input id="https_origin_port" type="number" value="443"></div>
          <div><label for="dns_cname_ttl">DNS CNAME TTL</label><input id="dns_cname_ttl" type="number" value="600"></div>
        </div>
      </details>
      <div class="row" style="margin-top:16px">
        <button id="start">开始创建</button>
        <button class="secondary" id="clear" type="button">清空日志</button>
      </div>
      <div class="hint" style="margin-top:10px">配置模板应包含：节点缓存不缓存、浏览器缓存 TTL 0、HTTPS、WebSocket、中国大陆网络优化。勾选 DNS CNAME 后，站点创建成功才会把 @ 和 * 指向共享 CNAME。</div>
    </section>

    <section class="split">
      <div class="toolbar">
        <div>任务状态：<span id="job_status" class="status">未开始</span></div>
        <div id="job_id" class="hint"></div>
      </div>
      <div class="results">
        <table>
          <thead><tr><th>域名</th><th>状态</th><th>ZoneId</th><th>DNS CNAME</th><th>输出目录</th></tr></thead>
          <tbody id="results"></tbody>
        </table>
      </div>
      <pre id="logs"></pre>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    let currentJob = null;
    let pollTimer = null;
    let originCnamePresets = [];

    async function initPresets() {
      let dnsEnvPresets = ["dns-providers.env"];
      try {
        const res = await fetch("/api/presets?ts=" + Date.now());
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "load presets failed");
        originCnamePresets = data.origin_cname_presets || [];
        dnsEnvPresets = data.dns_env_presets || dnsEnvPresets;
      } catch (err) {
        appendLog("加载预设失败: " + err.message);
      }
      const preset = $("origin_cname_preset");
      preset.innerHTML = '<option value="">自定义</option>';
      for (const item of originCnamePresets) {
        const opt = document.createElement("option");
        opt.value = item.label;
        opt.textContent = item.label + " · " + (item.origin || "自填源站") + " · " + item.cname;
        preset.appendChild(opt);
      }
      preset.addEventListener("change", () => {
        const item = originCnamePresets.find(x => x.label === preset.value);
        if (!item) return;
        if (item.origin) $("origin").value = item.origin;
        $("shared_cname").value = item.cname;
      });
      if (originCnamePresets.length) {
        preset.value = originCnamePresets[0].label;
        preset.dispatchEvent(new Event("change"));
      }

      const dnsPreset = $("dns_env_preset");
      dnsPreset.innerHTML = "";
      for (const value of dnsEnvPresets) {
        const opt = document.createElement("option");
        opt.value = value;
        opt.textContent = value;
        dnsPreset.appendChild(opt);
      }
      const custom = document.createElement("option");
      custom.value = "";
      custom.textContent = "自定义";
      dnsPreset.appendChild(custom);
      dnsPreset.value = "dns-providers.env";
      dnsPreset.addEventListener("change", () => {
        if (dnsPreset.value) $("dns_env_file").value = dnsPreset.value;
      });
    }

    $("host_header_mode").addEventListener("change", () => {
      $("custom_host_wrap").style.display = $("host_header_mode").value === "custom" ? "block" : "none";
    });

    async function loadTemplates(refresh=false) {
      const select = $("web_template");
      select.disabled = true;
      const current = select.value;
      select.innerHTML = '<option value="">不关联</option>';
      try {
        const res = await fetch("/api/templates" + (refresh ? "?refresh=1" : ""));
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "load failed");
        for (const t of data.templates) {
          const opt = document.createElement("option");
          opt.value = `${t.zone_id}|${t.template_id}`;
          opt.textContent = `${t.template_name || "(未命名)"} · ${t.template_id} · ${t.zone_name || t.zone_id}`;
          select.appendChild(opt);
        }
        select.value = current;
      } catch (err) {
        appendLog("加载 Web 防护模板失败: " + err.message);
      } finally {
        select.disabled = false;
      }
    }

    function appendLog(line) {
      $("logs").textContent += line + "\n";
      $("logs").scrollTop = $("logs").scrollHeight;
    }

    function payload() {
      return {
        domains: $("domains").value,
        origin: $("origin").value,
        shared_cname: $("shared_cname").value,
        web_template_ref: $("web_template").value,
        origin_protocol: $("origin_protocol").value,
        host_header_mode: $("host_header_mode").value,
        host_header: $("host_header").value,
        auto_cert: $("auto_cert").checked,
        enable_origin_acl: $("enable_origin_acl").checked,
        configure_dns_cname: $("configure_dns_cname").checked,
        config_json: $("config_json").value,
        plan_id: $("plan_id").value,
        env_file: $("env_file").value,
        dns_env_file: $("dns_env_file").value,
        http_origin_port: $("http_origin_port").value,
        https_origin_port: $("https_origin_port").value,
        dns_cname_ttl: $("dns_cname_ttl").value
      };
    }

    async function startJob() {
      $("start").disabled = true;
      try {
        const res = await fetch("/api/create", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload())
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "create failed");
        currentJob = data.job_id;
        $("job_id").textContent = currentJob;
        $("results").innerHTML = "";
        $("logs").textContent = "";
        poll();
        pollTimer = setInterval(poll, 2000);
      } catch (err) {
        appendLog("提交失败: " + err.message);
      } finally {
        $("start").disabled = false;
      }
    }

    async function poll() {
      if (!currentJob) return;
      const res = await fetch(`/api/jobs/${currentJob}`);
      const data = await res.json();
      if (!res.ok) {
        appendLog(data.error || "poll failed");
        return;
      }
      $("job_status").textContent = data.status;
      $("job_status").className = "status " + data.status;
      $("logs").textContent = data.logs.join("\n");
      $("logs").scrollTop = $("logs").scrollHeight;
      $("results").innerHTML = data.results.map(r => `
        <tr>
          <td>${escapeHtml(r.domain || "")}</td>
          <td>${escapeHtml(r.status || "")}</td>
          <td>${escapeHtml(r.zone_id || "")}</td>
          <td>${escapeHtml(r.dns_cname_status || "")}</td>
          <td>${escapeHtml(r.output_dir || "")}</td>
        </tr>`).join("");
      if (["success", "failed"].includes(data.status) && pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    $("start").addEventListener("click", startJob);
    $("clear").addEventListener("click", () => { $("logs").textContent = ""; $("results").innerHTML = ""; });
    $("refresh_templates").addEventListener("click", () => loadTemplates(true));
    initPresets();
    loadTemplates(false);
  </script>
</body>
</html>
""".replace("__DEFAULT_CONFIG__", html.escape(DEFAULT_CONFIG_JSON)).replace("__DEFAULT_PLAN__", html.escape(DEFAULT_PLAN_ID))


class Handler(BaseHTTPRequestHandler):
    server_version = "EOSiteCreator/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}", file=sys.stderr)

    def send_json(self, data: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/templates":
            qs = parse_qs(parsed.query)
            try:
                templates = load_templates(refresh=qs.get("refresh") == ["1"])
                self.send_json({"templates": templates})
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=500)
            return
        if parsed.path == "/api/presets":
            try:
                self.send_json(load_presets())
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=500)
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            job = STATE.get_job(job_id)
            if not job:
                self.send_json({"error": "job not found"}, status=404)
                return
            self.send_json(job.snapshot())
            return
        self.send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self.send_json({"error": "invalid json"}, status=400)
            return
        if parsed.path == "/api/create":
            try:
                payload = parse_create_payload(data)
                job = STATE.create_job(payload)
                self.send_json({"job_id": job.id})
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        self.send_json({"error": "not found"}, status=404)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Internal EdgeOne batch site creator web console.")
    parser.add_argument(
        "--tx-eo-dir",
        default=os.environ.get("TX_EO_DIR", str(Path(__file__).resolve().parent)),
        help="Directory containing tencent_eo_origin_tool.py and dns_txt_verify_tool.py. Default: this repo.",
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--env-file", default="tencent-eo-new.env")
    parser.add_argument("--dns-env-file", default="dns-providers.env")
    parser.add_argument("--plan-id", default=DEFAULT_PLAN_ID)
    parser.add_argument("--area", default=DEFAULT_AREA)
    parser.add_argument("--config-json", default=DEFAULT_CONFIG_JSON)
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--presets-json", default=DEFAULT_PRESETS_JSON)
    return parser


def main() -> int:
    global STATE
    args = build_parser().parse_args()
    STATE = AppState(args)
    load_tool_module(STATE.tx_eo_dir)
    thread = threading.Thread(target=worker_loop, daemon=True)
    thread.start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"EdgeOne site creator listening on http://{args.host}:{args.port}")
    print(f"Using tx-eo dir: {STATE.tx_eo_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
