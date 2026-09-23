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
import hashlib
import html
import hmac
import json
import os
from pathlib import Path
import queue
import re
import secrets
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
DEFAULT_APP_ENV = "eo-site-creator.env"

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


def load_app_env_file(path: Path) -> None:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            item = line.strip()
            if not item or item.startswith("#") or "=" not in item:
                continue
            key, value = item.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or key in os.environ:
                continue
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            os.environ[key] = value


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
        self.sessions: dict[str, float] = {}
        self.session_secret = args.session_secret or secrets.token_hex(32)
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

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = time.time() + 86400
        return token

    def valid_session(self, token: str) -> bool:
        if not token:
            return False
        with self.lock:
            expires_at = self.sessions.get(token)
            if not expires_at:
                return False
            if expires_at < time.time():
                self.sessions.pop(token, None)
                return False
            self.sessions[token] = time.time() + 86400
            return True

    def destroy_session(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)


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


def auth_enabled() -> bool:
    return bool(getattr(STATE.args, "auth_password", ""))


def verify_password(password: str) -> bool:
    expected = STATE.args.auth_password or ""
    return hmac.compare_digest(password.encode("utf-8"), expected.encode("utf-8"))


def parse_cookie(header: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in header.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def cache_buster() -> str:
    seed = str(STATE.args.session_secret or "") + str(STATE.args.auth_user or "")
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8]


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


def retryable_web_template_error(exc: Exception) -> bool:
    message = str(exc)
    patterns = (
        "存在变更状态",
        "未开启安全功能",
        "being deployed",
        "deploying",
        "initializing",
        "not ready",
        "ConfigInitializing",
    )
    return any(pattern in message for pattern in patterns)


def bind_web_security_template(job: Job, zone_id: str, hosts: list[str], template_ref: str) -> str:
    if not template_ref:
        return "skipped"
    try:
        template_zone_id, template_id = template_ref.split("|", 1)
    except ValueError:
        job.log(f"Web protection skipped: invalid template reference {template_ref}")
        return "failed"

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
            "ZoneId": zone_id,
            "TemplateId": template_id,
            "Entities": hosts,
            "Operate": "bind",
            "OverWrite": True,
        },
    ]
    actions = ["OperateSecurityTemplate", "BindSecurityTemplateToEntity"]

    last_error: Exception | None = None
    attempted: list[str] = []
    max_attempts = 36
    wait_seconds = 10
    for bind_attempt in range(1, max_attempts + 1):
        attempted = []
        for action in actions:
            for payload in payloads:
                attempted.append(f"{action}/ZoneId={payload['ZoneId']}")
                try:
                    response = client.call(action, payload)
                    job.log(
                        f"Web protection template bound to {', '.join(hosts)} "
                        f"using {action}: {json.dumps(response, ensure_ascii=False)}"
                    )
                    return "success"
                except Exception as exc:
                    last_error = exc
        if last_error and retryable_web_template_error(last_error) and bind_attempt < max_attempts:
            job.log(
                "Web protection template not ready for "
                + f"{', '.join(hosts)}; retrying in {wait_seconds}s "
                + f"({bind_attempt}/{max_attempts}): {last_error}"
            )
            time.sleep(wait_seconds)
            continue
        break
    job.log(
        "Web protection template bind failed for "
        + f"{', '.join(hosts)}: {last_error}; "
        + f"template_zone_id={template_zone_id}, target_zone_id={zone_id}, "
        + f"template_id={template_id}, attempted={';'.join(attempted)}"
    )
    return "failed"


def resolve_tx_eo_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return STATE.tx_eo_dir / path


def config_for_domain(job: Job, domain: str, payload: dict[str, Any], zone_output_dir: Path) -> str:
    mode = payload.get("accelerate_mainland", "template")
    if mode == "template":
        return payload["config_json"]
    if mode not in {"on", "off"}:
        raise ValueError(f"invalid accelerate mainland mode: {mode}")

    source = resolve_tx_eo_path(payload["config_json"])
    with source.open("r", encoding="utf-8") as f:
        config = json.load(f)

    zone_config = config.setdefault("ZoneConfig", {})
    accelerate = zone_config.setdefault("AccelerateMainland", {})
    accelerate["Switch"] = mode

    target = zone_output_dir / f"config-{safe_name(domain)}-mainland-{mode}.json"
    with target.open("w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")
    job.log(f"Using generated config for {domain}: AccelerateMainland.Switch={mode} {target}")
    return str(target)


def build_onboard_command(job: Job, domain: str, payload: dict[str, Any], zone_output_dir: Path) -> list[str]:
    config_json = config_for_domain(job, domain, payload, zone_output_dir)
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
        config_json,
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


def log_dns_cname_issues(job: Job, domain: str, output_root: Path) -> None:
    path = output_root / f"dns-cname-{safe_name(domain)}.csv"
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("status") == "failed":
                    job.log(
                        "DNS CNAME issue: "
                        f"{row.get('zone_name', '')} {row.get('record_name', '')} "
                        f"provider={row.get('provider', '')} rr={row.get('rr', '')} "
                        f"error={row.get('error', '')}"
                    )
    except Exception as exc:
        job.log(f"Read DNS CNAME issues failed for {domain}: {exc}")


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
        log_dns_cname_issues(job, domain, output_root)
        job.log(f"DNS CNAME failed for {domain}: exit {exit_code}")
        return False
    job.log(f"DNS CNAME configured for {domain}: @ and * -> {payload['shared_cname']}")
    return True


def read_origin_acl_status(domain: str, zone_output_dir: Path, enabled: bool) -> str:
    if not enabled:
        return "skipped"
    path = zone_output_dir / f"origin-acl-issues-{safe_name(domain)}.csv"
    if not path.exists():
        return "unknown"
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
    except Exception:
        return "unknown"
    if not rows:
        return "success"
    return "failed" if any((row.get("error") or row.get("status")) for row in rows) else "success"


def write_job_summary(job: Job, output_root: Path) -> None:
    rows = job.snapshot()["results"]
    path = output_root / "summary.csv"
    fields = [
        "domain",
        "status",
        "zone_id",
        "dns_cname_status",
        "origin_acl_status",
        "web_protection_status",
        "output_dir",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})

    job.log("Summary:")
    for row in rows:
        job.log(
            "  "
            + f"{row.get('domain', '')}: "
            + f"site={row.get('status', '')}, "
            + f"dns={row.get('dns_cname_status', '')}, "
            + f"origin_acl={row.get('origin_acl_status', '')}, "
            + f"web_protection={row.get('web_protection_status', '')}, "
            + f"zone_id={row.get('zone_id', '')}"
        )
    job.log(f"Wrote summary CSV: {path}")


def run_job(job: Job) -> None:
    payload = job.payload
    job.started_at = now_iso()
    job.set_status("running")
    domains = payload["domains"]
    output_root = STATE.tx_eo_dir / payload["output_root"] / job.id
    output_root.mkdir(parents=True, exist_ok=True)
    job.log(f"Output: {output_root}")

    failures = 0
    result_by_domain: dict[str, dict[str, Any]] = {}
    web_template_queue: list[tuple[str, str, list[str], str]] = []
    for index, domain in enumerate(domains, 1):
        zone_output_dir = output_root / f"{index:03d}-{safe_name(domain)}"
        zone_output_dir.mkdir(parents=True, exist_ok=True)
        job.log(f"Start {index}/{len(domains)} {domain}")
        cmd = build_onboard_command(job, domain, payload, zone_output_dir)
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
        web_protection_status = "skipped"
        if exit_code == 0 and payload.get("web_template_ref") and zone_id:
            hosts = [f"*.{domain}", domain]
            web_template_queue.append((domain, zone_id, hosts, payload["web_template_ref"]))
            web_protection_status = "pending"
            job.log(f"Web protection queued for {domain}; will bind after all domains are created")
        elif exit_code == 0 and payload.get("web_template_ref"):
            web_protection_status = "failed"
            job.log(f"Web protection skipped for {domain}: zone id not found in ownership CSV")

        dns_cname_status = "skipped"
        if exit_code == 0 and payload.get("configure_dns_cname", False):
            dns_cname_status = "success" if run_dns_cname(job, domain, payload, output_root) else "failed"
            if dns_cname_status == "failed":
                status = "failed"
                exit_code = 2

        if exit_code != 0:
            failures += 1
        origin_acl_status = (
            read_origin_acl_status(domain, zone_output_dir, bool(payload.get("enable_origin_acl", True)))
            if exit_code == 0
            else "skipped"
        )
        result = {
            "domain": domain,
            "status": status,
            "exit_code": exit_code,
            "zone_id": zone_id,
            "dns_cname_status": dns_cname_status,
            "origin_acl_status": origin_acl_status,
            "web_protection_status": web_protection_status,
            "output_dir": str(zone_output_dir),
            "started_at": started,
            "finished_at": finished,
        }
        job.add_result(result)
        result_by_domain[domain] = result

    if web_template_queue:
        wait_before_bind = 90
        job.log(
            "Waiting "
            + f"{wait_before_bind}s before deferred Web protection binding "
            + f"for {len(web_template_queue)} domain(s)"
        )
        time.sleep(wait_before_bind)
        for domain, zone_id, hosts, template_ref in web_template_queue:
            job.log(f"Deferred Web protection bind start for {domain}")
            web_status = bind_web_security_template(job, zone_id, hosts, template_ref)
            if domain in result_by_domain:
                result_by_domain[domain]["web_protection_status"] = web_status

    job.finished_at = now_iso()
    write_job_summary(job, output_root)
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
        "accelerate_mainland": str(raw.get("accelerate_mainland") or "template"),
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
      --bg: #edf3fb;
      --panel: #ffffff;
      --panel-soft: #f8fbff;
      --panel-tint: #f3f7ff;
      --line: #d8e1ee;
      --line-strong: #c8d4e5;
      --text: #172033;
      --muted: #64748b;
      --blue: #1463ff;
      --blue-dark: #0d47c8;
      --red: #c0342b;
      --green: #0a8f4b;
      --amber: #9a6700;
      --shadow: 0 18px 46px rgba(15, 23, 42, .10);
      --shadow-soft: 0 10px 26px rgba(15, 23, 42, .06);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at 12% 0, rgba(20, 99, 255, .16), transparent 33rem),
        radial-gradient(circle at 100% 18%, rgba(14, 165, 233, .12), transparent 31rem),
        linear-gradient(180deg, #f8fbff 0, var(--bg) 280px);
      color: var(--text);
      font-size: 14px;
    }
    header {
      min-height: 68px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 0 28px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, .88);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 5;
      box-shadow: 0 8px 24px rgba(15, 23, 42, .04);
    }
    .brand { display: flex; flex-direction: column; gap: 3px; }
    h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 750;
      letter-spacing: 0;
    }
    .subtitle { color: var(--muted); font-size: 12px; }
    .header-actions { display: flex; align-items: center; gap: 10px; }
    main {
      display: grid;
      grid-template-columns: minmax(500px, 680px) minmax(0, 1fr);
      gap: 18px;
      padding: 18px;
      min-height: calc(100vh - 68px);
      align-items: start;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 16px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .form { padding: 22px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 16px; }
    label { display: block; font-weight: 700; margin-bottom: 7px; }
    input, textarea, select {
      width: 100%;
      border: 1px solid #cbd5e1;
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
      background: #fff;
      min-height: 42px;
      color: var(--text);
      outline: none;
      transition: border-color .15s ease, box-shadow .15s ease, background .15s ease;
    }
    input:focus, textarea:focus, select:focus {
      border-color: var(--blue);
      box-shadow: 0 0 0 3px rgba(20, 99, 255, .12);
    }
    textarea { min-height: 120px; resize: vertical; }
    .full { grid-column: 1 / -1; }
    .hint { color: var(--muted); font-size: 12px; margin-top: 4px; line-height: 1.4; }
    .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .check { display: flex; align-items: center; gap: 8px; font-weight: 650; }
    .check input { width: 16px; min-height: 16px; }
    details {
      border-top: 1px solid var(--line);
      margin-top: 18px;
      padding-top: 16px;
    }
    summary { cursor: pointer; font-weight: 650; }
    button {
      border: 1px solid var(--blue);
      background: var(--blue);
      color: #fff;
      border-radius: 10px;
      height: 40px;
      padding: 0 18px;
      font-weight: 750;
      cursor: pointer;
      transition: transform .12s ease, box-shadow .12s ease, background .12s ease;
    }
    button:hover { background: var(--blue-dark); box-shadow: 0 8px 20px rgba(20, 99, 255, .18); }
    button:active { transform: translateY(1px); }
    button.secondary { background: #fff; color: var(--blue); }
    button.secondary:hover { background: #f5f8ff; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .logout {
      height: 32px;
      padding: 0 12px;
      border-color: #cbd5e1;
      color: #475569;
      font-size: 12px;
    }
    .primary-action { min-width: 110px; }
    .action-row {
      margin-top: 18px;
      padding-top: 16px;
      border-top: 1px solid var(--line);
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding: 18px 22px;
      border-bottom: 1px solid var(--line);
      background:
        linear-gradient(135deg, rgba(20, 99, 255, .07), transparent 45%),
        var(--panel-soft);
    }
    .panel-kicker {
      color: var(--muted);
      font-size: 12px;
      font-weight: 750;
      margin-bottom: 6px;
    }
    .status {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 12px;
      border-radius: 999px;
      background: #eef2ff;
      color: #273c94;
      font-weight: 800;
    }
    .status.success { color: var(--green); background: #e8f8ef; }
    .status.failed { color: var(--red); background: #fff1f1; }
    .status.running, .status.queued { color: var(--amber); background: #fff7df; }
    .job-id {
      max-width: 46%;
      text-align: right;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .results { padding: 0 18px 18px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 11px 8px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 650; }
    tbody tr:hover { background: #f8fbff; }
    .table-status {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 0 9px;
      border-radius: 999px;
      background: #eef2ff;
      color: #273c94;
      font-weight: 750;
      font-size: 12px;
    }
    .table-status.success { color: var(--green); background: #e8f8ef; }
    .table-status.failed { color: var(--red); background: #fff1f1; }
    .table-status.running, .table-status.queued { color: var(--amber); background: #fff7df; }
    .empty-row td {
      color: var(--muted);
      text-align: center;
      padding: 48px 8px;
      border-bottom: 0;
    }
    .log-title {
      padding: 10px 16px;
      background: #111827;
      color: #cbd5e1;
      border-top: 1px solid #1e293b;
      font-weight: 750;
      letter-spacing: 0;
    }
    pre {
      margin: 0;
      height: 390px;
      overflow: auto;
      background: #0f172a;
      color: #d7e0ef;
      padding: 14px 16px;
      border-top: 1px solid #1e293b;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .split { display: grid; grid-template-rows: auto minmax(190px, 1fr) auto 390px; min-height: calc(100vh - 104px); }
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
    .field-card {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      background: linear-gradient(180deg, #fbfdff, var(--panel-soft));
      box-shadow: var(--shadow-soft);
    }
    .section-label {
      color: #334155;
      font-size: 12px;
      font-weight: 800;
      margin: 2px 0 -4px;
    }
    .option-bar {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 14px;
      background: var(--panel-tint);
    }
    .compact-note {
      border-left: 3px solid var(--blue);
      background: #f4f7ff;
      padding: 10px 12px;
      border-radius: 8px;
      color: #475569;
    }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
      header { align-items: flex-start; padding: 14px 18px; flex-direction: column; }
      .header-actions { width: 100%; justify-content: space-between; }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>EdgeOne 站点创建</h1>
      <div class="subtitle">批量创建站点、共享 CNAME、HTTPS、源站防护和 DNS CNAME</div>
    </div>
    <div class="header-actions">
      <span class="pill">新账号批量创建 @ 和 *</span>
      <form method="post" action="/logout"><button class="secondary logout" type="submit">退出登录</button></form>
    </div>
  </header>
  <main>
    <section class="form">
      <div class="grid">
        <div class="full field-card">
          <label for="domains">站点域名</label>
          <textarea id="domains" placeholder="example.com&#10;example2.com"></textarea>
          <div class="hint">每行一个，也支持空格、逗号、分号分隔。每个站点会创建 <b>@</b> 和 <b>*</b> 两个加速域名。</div>
        </div>
        <div class="full field-card">
          <label for="origin_cname_preset">源站 / 共享 CNAME 预设</label>
          <select id="origin_cname_preset">
            <option value="">自定义</option>
          </select>
          <div class="hint">选择后会自动填充下面的源站和共享 CNAME，仍然可以手动修改。</div>
          <div class="hint" id="active_origin_cname">当前：自定义</div>
        </div>
        <div class="full section-label">基础配置</div>
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
          <label for="accelerate_mainland">中国大陆网络优化</label>
          <select id="accelerate_mainland">
            <option value="template">按配置模板</option>
            <option value="on">开启</option>
            <option value="off">关闭</option>
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
        <div class="full row option-bar">
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
      <div class="row action-row">
        <button id="start" class="primary-action">开始创建</button>
        <button class="secondary" id="clear" type="button">清空日志</button>
      </div>
      <div class="hint compact-note" style="margin-top:10px">配置模板应包含：节点缓存不缓存、浏览器缓存 TTL 0、HTTPS、WebSocket、中国大陆网络优化。勾选 DNS CNAME 后，站点创建成功才会把 @ 和 * 指向共享 CNAME。</div>
    </section>

    <section class="split">
      <div class="toolbar">
        <div>
          <div class="panel-kicker">任务状态</div>
          <span id="job_status" class="status idle">未开始</span>
        </div>
        <div id="job_id" class="hint job-id"></div>
      </div>
      <div class="results">
        <table>
          <thead><tr><th>域名</th><th>状态</th><th>ZoneId</th><th>DNS CNAME</th><th>源站防护</th><th>Web 防护</th><th>输出目录</th></tr></thead>
          <tbody id="results"><tr class="empty-row"><td colspan="7">等待提交任务</td></tr></tbody>
        </table>
      </div>
      <div class="log-title">实时日志</div>
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
      originCnamePresets.forEach((item, index) => {
        const opt = document.createElement("option");
        opt.value = String(index);
        opt.textContent = item.label + " · " + (item.origin || "自填源站") + " · " + item.cname;
        opt.title = opt.textContent;
        preset.appendChild(opt);
      });

      function updateActiveOriginCname() {
        $("origin").title = $("origin").value;
        $("shared_cname").title = $("shared_cname").value;
        $("active_origin_cname").textContent =
          "当前实际提交：源站 " + ($("origin").value || "-") +
          " / CNAME " + ($("shared_cname").value || "-") +
          " / 大陆优化 " + $("accelerate_mainland").value;
      }

      function applyOriginCnamePreset() {
        const item = originCnamePresets[Number(preset.value)];
        if (!item) return;
        if (item.origin) $("origin").value = item.origin;
        $("shared_cname").value = item.cname;
        if (["template", "on", "off"].includes(item.accelerate_mainland)) {
          $("accelerate_mainland").value = item.accelerate_mainland;
        }
        updateActiveOriginCname();
      }

      preset.addEventListener("change", applyOriginCnamePreset);
      $("origin").addEventListener("input", () => {
        preset.value = "";
        updateActiveOriginCname();
      });
      $("shared_cname").addEventListener("input", () => {
        preset.value = "";
        updateActiveOriginCname();
      });
      $("accelerate_mainland").addEventListener("change", updateActiveOriginCname);
      if (originCnamePresets.length) {
        preset.value = "0";
        applyOriginCnamePreset();
      } else {
        updateActiveOriginCname();
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
        accelerate_mainland: $("accelerate_mainland").value,
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
          <td>${statusBadge(r.status || "")}</td>
          <td>${escapeHtml(r.zone_id || "")}</td>
          <td>${escapeHtml(r.dns_cname_status || "")}</td>
          <td>${escapeHtml(r.origin_acl_status || "")}</td>
          <td>${escapeHtml(r.web_protection_status || "")}</td>
          <td>${escapeHtml(r.output_dir || "")}</td>
        </tr>`).join("") || '<tr class="empty-row"><td colspan="7">任务已提交，等待第一条结果</td></tr>';
      if (["success", "failed"].includes(data.status) && pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function statusBadge(s) {
      const safe = escapeHtml(s);
      const klass = ["success", "failed", "running", "queued"].includes(s) ? s : "";
      return `<span class="table-status ${klass}">${safe}</span>`;
    }

    $("start").addEventListener("click", startJob);
    $("clear").addEventListener("click", () => {
      $("logs").textContent = "";
      $("results").innerHTML = '<tr class="empty-row"><td colspan="7">等待提交任务</td></tr>';
    });
    $("refresh_templates").addEventListener("click", () => loadTemplates(true));
    initPresets();
    loadTemplates(false);
  </script>
</body>
</html>
""".replace("__DEFAULT_CONFIG__", html.escape(DEFAULT_CONFIG_JSON)).replace("__DEFAULT_PLAN__", html.escape(DEFAULT_PLAN_ID))


LOGIN_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>登录 · EdgeOne 站点创建</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #172033;
      background:
        linear-gradient(135deg, rgba(20, 99, 255, .14), transparent 36%),
        linear-gradient(315deg, rgba(11, 132, 90, .12), transparent 34%),
        #f4f7fb;
    }
    .login {
      width: min(420px, calc(100vw - 32px));
      background: #fff;
      border: 1px solid #d7deea;
      border-radius: 10px;
      box-shadow: 0 18px 50px rgba(23, 32, 51, .12);
      padding: 28px;
    }
    h1 { margin: 0 0 6px; font-size: 22px; letter-spacing: 0; }
    p { margin: 0 0 22px; color: #667085; line-height: 1.5; }
    label { display: block; font-weight: 650; margin: 14px 0 6px; }
    input {
      width: 100%;
      height: 42px;
      border: 1px solid #cfd6e2;
      border-radius: 6px;
      padding: 0 12px;
      font: inherit;
      outline: none;
    }
    input:focus { border-color: #1463ff; box-shadow: 0 0 0 3px rgba(20, 99, 255, .12); }
    button {
      width: 100%;
      height: 42px;
      margin-top: 20px;
      border: 0;
      border-radius: 6px;
      background: #1463ff;
      color: #fff;
      font-weight: 700;
      cursor: pointer;
    }
    .error {
      margin-top: 14px;
      padding: 10px 12px;
      border-radius: 6px;
      color: #9f1f17;
      background: #fff0ee;
      display: __ERROR_DISPLAY__;
    }
  </style>
</head>
<body>
  <form class="login" method="post" action="/login">
    <h1>EdgeOne 站点创建</h1>
    <p>登录后可批量创建站点、绑定共享 CNAME、证书、源站防护和 DNS 解析。</p>
    <label for="username">账号</label>
    <input id="username" name="username" autocomplete="username" value="__AUTH_USER__" autofocus>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password">
    <button type="submit">登录</button>
    <div class="error">账号或密码不正确</div>
  </form>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "EOSiteCreator/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}", file=sys.stderr)

    def send_html(self, body: str, status: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, data: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def session_token(self) -> str:
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        return cookies.get("eo_site_creator_session", "")

    def is_authenticated(self) -> bool:
        if not auth_enabled():
            return True
        return STATE.valid_session(self.session_token())

    def login_page(self, failed: bool = False) -> str:
        return (
            LOGIN_HTML.replace("__AUTH_USER__", html.escape(STATE.args.auth_user))
            .replace("__ERROR_DISPLAY__", "block" if failed else "none")
        )

    def require_auth(self) -> bool:
        if self.is_authenticated():
            return True
        if self.path.startswith("/api/"):
            self.send_json({"error": "unauthorized"}, status=401)
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            if self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            self.send_html(self.login_page(failed=qs.get("failed") == ["1"]))
            return
        if not self.require_auth():
            return
        if parsed.path == "/":
            self.send_html(HTML.replace("__CACHE_BUSTER__", cache_buster()))
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
        if parsed.path == "/login":
            form = parse_qs(raw.decode("utf-8"))
            username = (form.get("username") or [""])[0]
            password = (form.get("password") or [""])[0]
            if username == STATE.args.auth_user and verify_password(password):
                token = STATE.create_session()
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"eo_site_creator_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
                )
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", "/login?failed=1")
            self.end_headers()
            return
        if parsed.path == "/logout":
            STATE.destroy_session(self.session_token())
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                "eo_site_creator_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
            self.end_headers()
            return
        if not self.require_auth():
            return
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
    parser.add_argument("--auth-user", default=os.environ.get("EO_SITE_CREATOR_USER", "admin"))
    parser.add_argument("--auth-password", default=os.environ.get("EO_SITE_CREATOR_PASSWORD", ""))
    parser.add_argument("--session-secret", default=os.environ.get("EO_SITE_CREATOR_SESSION_SECRET", ""))
    return parser


def main() -> int:
    global STATE
    load_app_env_file(Path(__file__).resolve().parent / DEFAULT_APP_ENV)
    args = build_parser().parse_args()
    STATE = AppState(args)
    load_tool_module(STATE.tx_eo_dir)
    thread = threading.Thread(target=worker_loop, daemon=True)
    thread.start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"EdgeOne site creator listening on http://{args.host}:{args.port}")
    print(f"Using tx-eo dir: {STATE.tx_eo_dir}")
    print(f"Login auth: {'enabled' if auth_enabled() else 'disabled'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
