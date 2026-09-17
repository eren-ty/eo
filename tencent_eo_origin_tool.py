#!/usr/bin/env python3
"""
Export and batch-replace Tencent Cloud EdgeOne origin settings.

Environment variables:
  TENCENTCLOUD_SECRET_ID
  TENCENTCLOUD_SECRET_KEY
  TENCENTCLOUD_TOKEN        optional, for temporary credentials

The script also reads a local env file by default:
  ./tencent-eo.env

Examples:
  python3 tencent_eo_origin_tool.py export --json eo-origins.json --csv eo-origins.csv
  python3 tencent_eo_origin_tool.py replace --mapping mapping.csv
  python3 tencent_eo_origin_tool.py replace --mapping mapping.csv --apply --yes

mapping.csv format:
  old,new
  1.1.1.1,2.2.2.2
  old-origin.example.com,new-origin.example.com
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any


SERVICE = "teo"
VERSION = "2022-09-01"
DEFAULT_ENDPOINT = "teo.tencentcloudapi.com"
DEFAULT_LIMIT = 100
DEFAULT_ENV_FILE = "tencent-eo.env"
VALID_SCOPES = {"origin_group", "acceleration_domain", "l7_rule"}
VALID_CONFIG_TYPES = {
    "L7AccelerationConfig",
    "AccelerationDomain",
    "Origin",
    "WebSecurity",
}
EXPORT_ACTIONS = {
    "origin_group": ("DescribeOriginGroup", "origin_groups", ("OriginGroups", "OriginGroup")),
    "acceleration_domain": ("DescribeAccelerationDomains", "acceleration_domains", ("AccelerationDomains", "Domains")),
    "l7_rule": ("DescribeL7AccRules", "l7_rules", ("Rules",)),
}


class EdgeOneError(RuntimeError):
    pass


class TencentCloudClient:
    def __init__(
        self,
        secret_id: str,
        secret_key: str,
        token: str | None = None,
        endpoint: str = DEFAULT_ENDPOINT,
        version: str = VERSION,
        service: str = SERVICE,
        retries: int = 3,
        sleep_seconds: float = 0.15,
    ) -> None:
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.token = token
        self.endpoint = endpoint
        self.version = version
        self.service = service
        self.retries = retries
        self.sleep_seconds = sleep_seconds

    def call(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = self._headers(action, body)
        req = urllib.request.Request(
            f"https://{self.endpoint}/",
            data=body,
            headers=headers,
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(min(2**attempt, 20) + random.uniform(0.2, 1.0))
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                response = data.get("Response", {})
                if "Error" in response:
                    err = response["Error"]
                    code = err.get("Code")
                    message = err.get("Message")
                    if code == "RequestLimitExceeded" and attempt < self.retries:
                        delay = min(2**attempt, 8) + random.uniform(0.2, 0.8)
                        print(f"{action} hit rate limit; retrying in {delay:.1f}s", file=sys.stderr)
                        time.sleep(delay)
                        continue
                    raise EdgeOneError(f"{action} failed: {code}: {message}")
                if self.sleep_seconds:
                    time.sleep(self.sleep_seconds)
                return response
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, EdgeOneError) as exc:
                last_error = exc
                if isinstance(exc, EdgeOneError):
                    raise
                if attempt < self.retries:
                    print(
                        f"{action} network error; retrying ({attempt + 1}/{self.retries}): {exc}",
                        file=sys.stderr,
                    )
        raise EdgeOneError(f"{action} failed after retries: {last_error}")

    def _headers(self, action: str, body: bytes) -> dict[str, str]:
        timestamp = int(time.time())
        date = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%d")

        http_request_method = "POST"
        canonical_uri = "/"
        canonical_query_string = ""
        canonical_headers = (
            f"content-type:application/json; charset=utf-8\n"
            f"host:{self.endpoint}\n"
            f"x-tc-action:{action.lower()}\n"
        )
        signed_headers = "content-type;host;x-tc-action"
        hashed_request_payload = hashlib.sha256(body).hexdigest()
        canonical_request = "\n".join(
            [
                http_request_method,
                canonical_uri,
                canonical_query_string,
                canonical_headers,
                signed_headers,
                hashed_request_payload,
            ]
        )

        algorithm = "TC3-HMAC-SHA256"
        credential_scope = f"{date}/{self.service}/tc3_request"
        hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join(
            [
                algorithm,
                str(timestamp),
                credential_scope,
                hashed_canonical_request,
            ]
        )

        secret_date = hmac_sha256(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = hmac_sha256(secret_date, self.service)
        secret_signing = hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            f"{algorithm} Credential={self.secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json; charset=utf-8",
            "Host": self.endpoint,
            "X-TC-Action": action,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": self.version,
        }
        if self.token:
            headers["X-TC-Token"] = self.token
        return headers


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def load_env_file(path: str) -> None:
    if not path or not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise SystemExit(f"Invalid env line {line_no} in {path}: expected KEY=VALUE")
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def require_credentials(args: argparse.Namespace) -> TencentCloudClient:
    load_env_file(args.env_file)
    secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
    secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")
    if not secret_id or not secret_key:
        raise SystemExit(
            "Missing TENCENTCLOUD_SECRET_ID or TENCENTCLOUD_SECRET_KEY. "
            f"Set environment variables or fill {args.env_file}."
        )
    return TencentCloudClient(
        secret_id=secret_id,
        secret_key=secret_key,
        token=os.environ.get("TENCENTCLOUD_TOKEN"),
        endpoint=args.endpoint,
        retries=args.retries,
        sleep_seconds=args.sleep,
    )


def client_from_env_file(
    env_file: str,
    args: argparse.Namespace,
    endpoint: str | None = None,
    version: str | None = None,
    service: str | None = None,
) -> TencentCloudClient:
    old_secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
    old_secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")
    old_token = os.environ.get("TENCENTCLOUD_TOKEN")
    for key in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN"):
        os.environ.pop(key, None)
    try:
        load_env_file(env_file)
        secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
        secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")
        token = os.environ.get("TENCENTCLOUD_TOKEN")
    finally:
        for key in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN"):
            os.environ.pop(key, None)
        if old_secret_id is not None:
            os.environ["TENCENTCLOUD_SECRET_ID"] = old_secret_id
        if old_secret_key is not None:
            os.environ["TENCENTCLOUD_SECRET_KEY"] = old_secret_key
        if old_token is not None:
            os.environ["TENCENTCLOUD_TOKEN"] = old_token

    if not secret_id or not secret_key:
        raise SystemExit(
            "Missing TENCENTCLOUD_SECRET_ID or TENCENTCLOUD_SECRET_KEY. "
            f"Set them in {env_file}."
        )
    return TencentCloudClient(
        secret_id=secret_id,
        secret_key=secret_key,
        token=token,
        endpoint=endpoint or args.endpoint,
        version=version or VERSION,
        service=service or SERVICE,
        retries=args.retries,
        sleep_seconds=args.sleep,
    )


def require_ssl_client(args: argparse.Namespace) -> TencentCloudClient:
    load_env_file(args.env_file)
    secret_id = os.environ.get("TENCENTCLOUD_SECRET_ID")
    secret_key = os.environ.get("TENCENTCLOUD_SECRET_KEY")
    if not secret_id or not secret_key:
        raise SystemExit(
            "Missing TENCENTCLOUD_SECRET_ID or TENCENTCLOUD_SECRET_KEY. "
            f"Set environment variables or fill {args.env_file}."
        )
    return TencentCloudClient(
        secret_id=secret_id,
        secret_key=secret_key,
        token=os.environ.get("TENCENTCLOUD_TOKEN"),
        endpoint="ssl.tencentcloudapi.com",
        version="2019-12-05",
        service="ssl",
        retries=args.retries,
        sleep_seconds=args.sleep,
    )


def paged_call(
    client: TencentCloudClient,
    action: str,
    base_payload: dict[str, Any],
    list_keys: tuple[str, ...],
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        payload = dict(base_payload)
        payload["Offset"] = offset
        payload["Limit"] = limit
        response = client.call(action, payload)
        page: list[dict[str, Any]] = []
        for key in list_keys:
            value = response.get(key)
            if isinstance(value, list):
                page = value
                break
        if not page:
            return items
        items.extend(page)
        total = response.get("TotalCount")
        offset += len(page)
        if total is not None and offset >= int(total):
            return items
        if len(page) < limit:
            return items


def parse_scopes(value: str) -> set[str]:
    scopes = {scope.strip() for scope in value.split(",") if scope.strip()}
    if "all" in scopes:
        scopes.remove("all")
        scopes.update(VALID_SCOPES)
    unknown = scopes - VALID_SCOPES
    if unknown:
        raise SystemExit(f"Unknown scope(s): {', '.join(sorted(unknown))}")
    if not scopes:
        raise SystemExit("At least one scope is required.")
    return scopes


def parse_config_types(value: str) -> list[str]:
    types = [item.strip() for item in value.split(",") if item.strip()]
    if not types or "all" in types:
        return []
    unknown = set(types) - VALID_CONFIG_TYPES
    if unknown:
        raise SystemExit(f"Unknown config type(s): {', '.join(sorted(unknown))}")
    return types


def export_zone(
    client: TencentCloudClient,
    zone: dict[str, Any],
    scopes: set[str],
    limit: int,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    zone_id = zone.get("ZoneId")
    zone_name = zone.get("ZoneName")
    entry = {
        "zone": zone,
        "origin_groups": [],
        "acceleration_domains": [],
        "l7_rules": [],
    }
    errors: list[dict[str, str]] = []
    print(f"Exporting {zone_name or ''} {zone_id}", file=sys.stderr)

    for scope in sorted(scopes):
        action, target_key, list_keys = EXPORT_ACTIONS[scope]
        try:
            entry[target_key] = paged_call(client, action, {"ZoneId": zone_id}, list_keys, limit)
        except Exception as exc:  # Keep exporting other zones/scopes.
            errors.append(
                {
                    "zone_id": str(zone_id or ""),
                    "zone_name": str(zone_name or ""),
                    "action": action,
                    "error": str(exc),
                }
            )
    return entry, errors


def export_all(client: TencentCloudClient, args: argparse.Namespace) -> dict[str, Any]:
    scopes = parse_scopes(args.scope)
    zones = paged_call(client, "DescribeZones", {}, ("Zones",), args.limit)
    result = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "endpoint": args.endpoint,
        "scopes": sorted(scopes),
        "zones": [],
        "errors": [],
    }

    workers = max(1, int(getattr(args, "workers", 1)))
    if workers == 1:
        for zone in zones:
            entry, errors = export_zone(client, zone, scopes, args.limit)
            result["zones"].append(entry)
            result["errors"].extend(errors)
            if getattr(args, "checkpoint", False):
                write_export_files(data=result, json_path=args.json, csv_path=args.csv)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(export_zone, client, zone, scopes, args.limit) for zone in zones]
            for future in as_completed(futures):
                entry, errors = future.result()
                result["zones"].append(entry)
                result["errors"].extend(errors)
                if getattr(args, "checkpoint", False):
                    write_export_files(data=result, json_path=args.json, csv_path=args.csv)
    return result


def write_export_files(data: dict[str, Any], json_path: str, csv_path: str) -> None:
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)

    rows = flatten_origin_rows(data)
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scope",
                "zone_id",
                "zone_name",
                "resource_id",
                "resource_name",
                "domain_name",
                "path",
                "origin_type",
                "origin",
                "backup_origin",
                "host_header",
                "origin_protocol",
                "http_origin_port",
                "https_origin_port",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def safe_filename(value: str) -> str:
    keep = []
    for char in value:
        if char.isalnum() or char in "._-":
            keep.append(char)
        else:
            keep.append("_")
    return "".join(keep).strip("._") or "unknown"


def export_zone_config(
    client: TencentCloudClient,
    zone: dict[str, Any],
    config_types: list[str],
    output_dir: str,
) -> dict[str, str]:
    zone_id = str(zone.get("ZoneId") or "")
    zone_name = str(zone.get("ZoneName") or "")
    row_data = {
        "zone_id": zone_id,
        "zone_name": zone_name,
        "types": ",".join(config_types) if config_types else "all",
        "file": "",
        "status": "success",
        "error": "",
    }
    print(f"Exporting zone config {zone_name} {zone_id}", file=sys.stderr)
    payload: dict[str, Any] = {"ZoneId": zone_id}
    if config_types:
        payload["Types"] = config_types

    try:
        response = client.call("ExportZoneConfig", payload)
        content = response.get("Content")
        if not content:
            raise EdgeOneError("ExportZoneConfig response did not include Content")
        parsed = json.loads(content)
        filename = f"{safe_filename(zone_name)}_{safe_filename(zone_id)}.json"
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(parsed, f, ensure_ascii=False, indent=2, sort_keys=True)
        row_data["file"] = path
    except Exception as exc:
        row_data["status"] = "failed"
        row_data["error"] = str(exc)
    return row_data


def cmd_export_zone_config(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    config_types = parse_config_types(args.types)
    os.makedirs(args.output_dir, exist_ok=True)

    if args.zone_id:
        zones = [{"ZoneId": args.zone_id, "ZoneName": args.zone_name or args.zone_id}]
    else:
        zones = paged_call(client, "DescribeZones", {}, ("Zones",), args.limit)

    rows: list[dict[str, str]] = []
    workers = max(1, int(args.workers))
    if workers == 1:
        for zone in zones:
            rows.append(export_zone_config(client, zone, config_types, args.output_dir))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(export_zone_config, client, zone, config_types, args.output_dir)
                for zone in zones
            ]
            for future in as_completed(futures):
                rows.append(future.result())

    rows.sort(key=lambda item: (item["zone_name"], item["zone_id"]))
    with open(args.summary_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["zone_id", "zone_name", "types", "file", "status", "error"])
        writer.writeheader()
        writer.writerows(rows)

    failures = sum(1 for row_data in rows if row_data["status"] != "success")
    print(f"Wrote zone config files: {args.output_dir}")
    print(f"Wrote summary CSV:       {args.summary_csv}")
    if failures:
        print(f"Completed with {failures} failed export(s). See summary CSV for details.", file=sys.stderr)
        return 2
    return 0


def clean_security_policy_for_create(value: Any) -> Any:
    output_only_keys = {
        "Id",
        "MetaData",
        "GroupDetail",
        "GroupName",
        "RuleDetails",
    }
    if isinstance(value, dict):
        return {
            key: clean_security_policy_for_create(child)
            for key, child in value.items()
            if key not in output_only_keys
        }
    if isinstance(value, list):
        return [clean_security_policy_for_create(item) for item in value]
    return value


def int_to_ipv4(value: str) -> str:
    number = int(value)
    if number < 0 or number > 0xFFFFFFFF:
        return value
    return ".".join(str((number >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def normalize_security_policy_conditions(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize_security_policy_conditions(child) for key, child in value.items()}
    if isinstance(value, list):
        return [normalize_security_policy_conditions(item) for item in value]
    if not isinstance(value, str):
        return value
    if "http.request.ip" not in value and "http.request.xff_header_ip" not in value:
        return value

    def replace_numeric_ip(match: re.Match[str]) -> str:
        raw = match.group(1)
        try:
            converted = int_to_ipv4(raw)
        except ValueError:
            return match.group(0)
        return f"'{converted}'"

    return re.sub(r"'([0-9]{8,10})'", replace_numeric_ip, value)


def describe_web_security_templates(
    client: TencentCloudClient,
    zone_ids: list[str],
) -> list[dict[str, Any]]:
    response = client.call("DescribeWebSecurityTemplates", {"ZoneIds": zone_ids})
    return response.get("SecurityPolicyTemplates") or []


def describe_shared_cnames(client: TencentCloudClient, zone_id: str, limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    return paged_call(
        client,
        "DescribeSharedCNAME",
        {"ZoneId": zone_id, "Order": "create-time", "Direction": "desc"},
        ("SharedCNAMEInfo",),
        limit,
    )


def export_web_security_templates(
    client: TencentCloudClient,
    zone_id: str,
    names: set[str] | None = None,
) -> dict[str, Any]:
    templates = describe_web_security_templates(client, [zone_id])
    selected: list[dict[str, Any]] = []
    for template in templates:
        template_name = str(template.get("TemplateName") or "")
        template_id = str(template.get("TemplateId") or "")
        if names and template_name not in names and template_id not in names:
            continue
        print(f"Exporting web security template {template_name} {template_id}", file=sys.stderr)
        detail = client.call(
            "DescribeWebSecurityTemplate",
            {
                "ZoneId": str(template.get("ZoneId") or zone_id),
                "TemplateId": template_id,
            },
        )
        selected.append(
            {
                "ZoneId": str(template.get("ZoneId") or zone_id),
                "TemplateId": template_id,
                "TemplateName": template_name,
                "BindDomains": template.get("BindDomains") or [],
                "SecurityPolicy": detail.get("SecurityPolicy") or {},
                "DescribeResponse": detail,
            }
        )
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_zone_id": zone_id,
        "templates": selected,
    }


def write_web_security_template_summary(path: str, rows: list[dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "source_template_id",
                "target_template_id",
                "template_name",
                "status",
                "error",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[idx : idx + size] for idx in range(0, len(items), size)]


def cmd_list_web_security_templates(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    if args.zone_ids:
        zone_ids = [item.strip() for item in args.zone_ids.split(",") if item.strip()]
        zones = [{"ZoneId": zone_id, "ZoneName": ""} for zone_id in zone_ids]
    else:
        zones = paged_call(client, "DescribeZones", {}, ("Zones",), args.limit)
        zone_ids = [str(zone.get("ZoneId") or "") for zone in zones if zone.get("ZoneId")]
    zone_names = {str(zone.get("ZoneId") or ""): str(zone.get("ZoneName") or "") for zone in zones}

    templates: list[dict[str, Any]] = []
    for zone_id_group in chunked(zone_ids, 100):
        if not zone_id_group:
            continue
        print(f"Scanning web security templates in {len(zone_id_group)} zone(s)", file=sys.stderr)
        templates.extend(describe_web_security_templates(client, zone_id_group))

    rows = []
    for template in templates:
        zone_id = str(template.get("ZoneId") or "")
        bind_domains = template.get("BindDomains") or []
        rows.append(
            {
                "zone_id": zone_id,
                "zone_name": zone_names.get(zone_id, ""),
                "template_id": str(template.get("TemplateId") or ""),
                "template_name": str(template.get("TemplateName") or ""),
                "bind_domain_count": str(len(bind_domains)),
                "bind_domains": ";".join(str(item.get("Domain") or "") for item in bind_domains),
            }
        )
    rows.sort(key=lambda item: (item["template_name"], item["zone_name"], item["zone_id"]))

    os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "total_count": len(rows),
                "templates": templates,
            },
            f,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    with open(args.output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "zone_id",
                "zone_name",
                "template_id",
                "template_name",
                "bind_domain_count",
                "bind_domains",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote web security template list: {args.output_json}")
    print(f"Wrote summary CSV:                {args.output_csv}")
    print(f"Templates found:                  {len(rows)}")
    return 0


def write_rows_csv(path: str, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_completed_zone_ids(status_csvs: str) -> set[str]:
    completed: set[str] = set()
    for path in [item.strip() for item in status_csvs.split(",") if item.strip()]:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row_data in csv.DictReader(f):
                if row_data.get("status") == "success" and row_data.get("old_zone_id"):
                    completed.add(row_data["old_zone_id"])
    return completed


def write_filtered_batches(
    source_csv: str,
    output_dir: str,
    excluded_zone_ids: set[str],
    max_size: int,
) -> dict[str, Any]:
    with open(source_csv, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    kept = [
        row_data
        for row_data in rows
        if row_data.get("zone_id") not in excluded_zone_ids and row_data.get("config_status") == "success"
    ]
    excluded = [row_data for row_data in rows if row_data.get("zone_id") in excluded_zone_ids]
    missing = [
        row_data
        for row_data in rows
        if row_data.get("zone_id") not in excluded_zone_ids and row_data.get("config_status") != "success"
    ]

    os.makedirs(output_dir, exist_ok=True)
    fieldnames = [
        "zone_id",
        "zone_name",
        "primary_origin",
        "origins",
        "domain_count",
        "domains",
        "config_file",
        "config_status",
        "config_error",
    ]
    write_rows_csv(os.path.join(output_dir, "all-zones-safe.csv"), kept, fieldnames)
    write_rows_csv(os.path.join(output_dir, "excluded-protected-or-completed.csv"), excluded, fieldnames)
    write_rows_csv(os.path.join(output_dir, "missing-configs.csv"), missing, fieldnames)

    grouped: dict[str, list[dict[str, str]]] = {}
    for row_data in kept:
        grouped.setdefault(row_data.get("primary_origin") or "unknown", []).append(row_data)

    manifest_rows: list[dict[str, str]] = []
    max_size = max(1, int(max_size))
    batch_no = 1
    for origin, group_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        group_rows.sort(key=lambda item: item.get("zone_name") or "")
        for idx in range(0, len(group_rows), max_size):
            batch_rows = group_rows[idx : idx + max_size]
            batch_name = f"batch-{batch_no:03d}-{safe_filename(origin)}.csv"
            batch_path = os.path.join(output_dir, batch_name)
            write_rows_csv(batch_path, batch_rows, fieldnames)
            manifest_rows.append(
                {
                    "batch_no": str(batch_no),
                    "origin": origin,
                    "count": str(len(batch_rows)),
                    "missing_or_failed_configs": "0",
                    "file": batch_path,
                }
            )
            batch_no += 1
    write_rows_csv(
        os.path.join(output_dir, "manifest.csv"),
        manifest_rows,
        ["batch_no", "origin", "count", "missing_or_failed_configs", "file"],
    )
    return {
        "kept": len(kept),
        "excluded": len(excluded),
        "missing": len(missing),
        "batches": len(manifest_rows),
    }


def cmd_audit_protected_zones(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    os.makedirs(args.output_dir, exist_ok=True)
    zones = paged_call(client, "DescribeZones", {}, ("Zones",), args.limit)
    zone_names = {str(zone.get("ZoneId") or ""): str(zone.get("ZoneName") or "") for zone in zones}
    zone_ids = [zone_id for zone_id in zone_names if zone_id]

    protected: dict[str, dict[str, Any]] = {}
    template_rows: list[dict[str, str]] = []
    shared_cname_rows: list[dict[str, str]] = []

    for zone_id_group in chunked(zone_ids, 100):
        templates = describe_web_security_templates(client, zone_id_group)
        for template in templates:
            zone_id = str(template.get("ZoneId") or "")
            bind_domains = template.get("BindDomains") or []
            template_rows.append(
                {
                    "zone_id": zone_id,
                    "zone_name": zone_names.get(zone_id, ""),
                    "template_id": str(template.get("TemplateId") or ""),
                    "template_name": str(template.get("TemplateName") or ""),
                    "bind_domain_count": str(len(bind_domains)),
                    "bind_domains": ";".join(str(item.get("Domain") or "") for item in bind_domains),
                }
            )
            entry = protected.setdefault(
                zone_id,
                {
                    "zone_id": zone_id,
                    "zone_name": zone_names.get(zone_id, ""),
                    "reasons": set(),
                    "templates": [],
                    "shared_cnames": [],
                },
            )
            entry["reasons"].add("web_security_template")
            entry["templates"].append(str(template.get("TemplateName") or template.get("TemplateId") or ""))

    for idx, zone_id in enumerate(zone_ids, start=1):
        print(f"Scanning shared CNAME {idx}/{len(zone_ids)} {zone_names.get(zone_id, '')} {zone_id}", file=sys.stderr)
        try:
            shared_cnames = describe_shared_cnames(client, zone_id, args.limit)
        except Exception as exc:
            shared_cname_rows.append(
                {
                    "zone_id": zone_id,
                    "zone_name": zone_names.get(zone_id, ""),
                    "shared_cname": "",
                    "domain_count": "",
                    "domains": "",
                    "status": "failed",
                    "error": str(exc),
                }
            )
            continue
        for item in shared_cnames:
            shared_cname = str(item.get("SharedCNAME") or item.get("SharedCname") or item.get("Cname") or "")
            domains = item.get("Domains") or item.get("DomainNames") or []
            if isinstance(domains, list):
                domain_text = ";".join(str(domain.get("DomainName") if isinstance(domain, dict) else domain) for domain in domains)
                domain_count = str(len(domains))
            else:
                domain_text = str(domains or "")
                domain_count = ""
            shared_cname_rows.append(
                {
                    "zone_id": zone_id,
                    "zone_name": zone_names.get(zone_id, ""),
                    "shared_cname": shared_cname,
                    "domain_count": domain_count,
                    "domains": domain_text,
                    "status": "success",
                    "error": "",
                }
            )
            entry = protected.setdefault(
                zone_id,
                {
                    "zone_id": zone_id,
                    "zone_name": zone_names.get(zone_id, ""),
                    "reasons": set(),
                    "templates": [],
                    "shared_cnames": [],
                },
            )
            entry["reasons"].add("shared_cname")
            entry["shared_cnames"].append(shared_cname)

    completed_zone_ids = read_completed_zone_ids(args.completed_status_csvs)
    for zone_id in completed_zone_ids:
        entry = protected.setdefault(
            zone_id,
            {
                "zone_id": zone_id,
                "zone_name": zone_names.get(zone_id, ""),
                "reasons": set(),
                "templates": [],
                "shared_cnames": [],
            },
        )
        entry["reasons"].add("completed")

    protected_rows = []
    for zone_id, entry in protected.items():
        reasons = sorted(entry["reasons"])
        protected_rows.append(
            {
                "zone_id": zone_id,
                "zone_name": entry["zone_name"],
                "reasons": ";".join(reasons),
                "templates": ";".join(sorted(set(entry["templates"]))),
                "shared_cnames": ";".join(sorted(set(item for item in entry["shared_cnames"] if item))),
            }
        )
    protected_rows.sort(key=lambda item: (item["zone_name"], item["zone_id"]))

    protected_csv = os.path.join(args.output_dir, "protected-zones.csv")
    protected_json = os.path.join(args.output_dir, "protected-zones.json")
    write_rows_csv(protected_csv, protected_rows, ["zone_id", "zone_name", "reasons", "templates", "shared_cnames"])
    write_rows_csv(
        os.path.join(args.output_dir, "web-security-template-zones.csv"),
        sorted(template_rows, key=lambda item: (item["template_name"], item["zone_name"])),
        ["zone_id", "zone_name", "template_id", "template_name", "bind_domain_count", "bind_domains"],
    )
    write_rows_csv(
        os.path.join(args.output_dir, "shared-cname-zones.csv"),
        sorted(shared_cname_rows, key=lambda item: (item["zone_name"], item["shared_cname"])),
        ["zone_id", "zone_name", "shared_cname", "domain_count", "domains", "status", "error"],
    )
    with open(protected_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "protected_zones": [
                    {
                        "zone_id": row_data["zone_id"],
                        "zone_name": row_data["zone_name"],
                        "reasons": row_data["reasons"].split(";") if row_data["reasons"] else [],
                        "templates": row_data["templates"].split(";") if row_data["templates"] else [],
                        "shared_cnames": row_data["shared_cnames"].split(";") if row_data["shared_cnames"] else [],
                    }
                    for row_data in protected_rows
                ],
            },
            f,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )

    if args.source_all_zones_csv and args.safe_batch_dir:
        stats = write_filtered_batches(
            args.source_all_zones_csv,
            args.safe_batch_dir,
            {row_data["zone_id"] for row_data in protected_rows},
            args.max_size,
        )
        print(f"Wrote safe batch dir: {args.safe_batch_dir}")
        print(
            f"Safe batches: kept={stats['kept']} excluded={stats['excluded']} "
            f"missing={stats['missing']} batches={stats['batches']}"
        )

    print(f"Wrote protected zones: {protected_csv}")
    print(f"Wrote protected JSON:  {protected_json}")
    print(f"Protected zones found: {len(protected_rows)}")
    return 0


def cmd_export_web_security_templates(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    names = {item.strip() for item in args.names.split(",") if item.strip()} if args.names else None
    data = export_web_security_templates(client, args.zone_id, names)
    os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    rows = [
        {
            "source_template_id": item.get("TemplateId", ""),
            "target_template_id": "",
            "template_name": item.get("TemplateName", ""),
            "status": "exported",
            "error": "",
        }
        for item in data["templates"]
    ]
    write_web_security_template_summary(args.summary_csv, rows)
    print(f"Wrote web security templates: {args.output_json}")
    print(f"Wrote summary CSV:           {args.summary_csv}")
    return 0


def cmd_import_web_security_templates(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    templates = data.get("templates") or []
    existing = {
        str(item.get("TemplateName") or ""): str(item.get("TemplateId") or "")
        for item in describe_web_security_templates(client, [args.target_zone_id])
    }
    rows: list[dict[str, str]] = []
    results: list[dict[str, Any]] = []
    failures = 0
    for template in templates:
        name = str(template.get("TemplateName") or "")
        source_template_id = str(template.get("TemplateId") or "")
        if not name:
            failures += 1
            rows.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": "",
                    "template_name": name,
                    "status": "failed",
                    "error": "TemplateName is empty",
                }
            )
            continue
        if name in existing and not args.overwrite:
            rows.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": existing[name],
                    "template_name": name,
                    "status": "skipped_existing",
                    "error": "",
                }
            )
            print(f"Template already exists in target zone, skipped: {name} {existing[name]}")
            continue
        if name in existing and args.overwrite:
            delete_response = client.call(
                "DeleteWebSecurityTemplate",
                {
                    "ZoneId": args.target_zone_id,
                    "TemplateId": existing[name],
                },
            )
            results.append(
                {
                    "template_name": name,
                    "target_template_id": existing[name],
                    "delete_response": delete_response,
                }
            )
        security_policy = template.get("SecurityPolicy") or {}
        if not args.raw_security_policy:
            security_policy = clean_security_policy_for_create(security_policy)
            security_policy = normalize_security_policy_conditions(security_policy)
        payload = {
            "ZoneId": args.target_zone_id,
            "TemplateName": name,
            "SecurityPolicy": security_policy,
        }
        if not args.apply:
            rows.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": "",
                    "template_name": name,
                    "status": "dry_run",
                    "error": "",
                }
            )
            results.append({"template_name": name, "payload": payload, "dry_run": True})
            continue
        if not args.yes:
            raise SystemExit("Refusing to import web security templates without --yes.")
        try:
            response = client.call("CreateWebSecurityTemplate", payload)
            target_template_id = str(response.get("TemplateId") or "")
            rows.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": target_template_id,
                    "template_name": name,
                    "status": "created",
                    "error": "",
                }
            )
            results.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": target_template_id,
                    "template_name": name,
                    "payload": payload,
                    "response": response,
                }
            )
            print(f"Created web security template: {name} {target_template_id}")
        except Exception as exc:
            failures += 1
            rows.append(
                {
                    "source_template_id": source_template_id,
                    "target_template_id": "",
                    "template_name": name,
                    "status": "failed",
                    "error": str(exc),
                }
            )
            results.append(
                {
                    "source_template_id": source_template_id,
                    "template_name": name,
                    "payload": payload,
                    "error": str(exc),
                }
            )
            print(f"FAILED CreateWebSecurityTemplate {name}: {exc}", file=sys.stderr)
    os.makedirs(os.path.dirname(args.response_json) or ".", exist_ok=True)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, ensure_ascii=False, indent=2, sort_keys=True)
    write_web_security_template_summary(args.summary_csv, rows)
    print(f"Wrote import response: {args.response_json}")
    print(f"Wrote summary CSV:     {args.summary_csv}")
    return 3 if failures else 0


def cmd_migrate_web_security_templates(args: argparse.Namespace) -> int:
    old_client = client_from_env_file(args.old_env_file, args)
    names = {item.strip() for item in args.names.split(",") if item.strip()} if args.names else None
    data = export_web_security_templates(old_client, args.old_zone_id, names)
    os.makedirs(args.output_dir, exist_ok=True)
    prefix = safe_filename(args.zone_name or args.old_zone_id)
    export_path = os.path.join(args.output_dir, f"web-security-templates-export-{prefix}.json")
    import_path = os.path.join(args.output_dir, f"web-security-templates-import-{prefix}.json")
    summary_path = os.path.join(args.output_dir, f"web-security-templates-summary-{prefix}.csv")
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"Wrote web security template export: {export_path}")
    import_args = copy.copy(args)
    import_args.input_json = export_path
    import_args.target_zone_id = args.new_zone_id
    import_args.response_json = import_path
    import_args.summary_csv = summary_path
    return cmd_import_web_security_templates(import_args)


def read_config_summary(path: str) -> dict[tuple[str, str], dict[str, str]]:
    configs: dict[tuple[str, str], dict[str, str]] = {}
    if not os.path.exists(path):
        return configs
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for record in reader:
            zone_id = record.get("zone_id") or ""
            zone_name = record.get("zone_name") or ""
            if zone_id:
                configs[(zone_id, zone_name)] = record
    return configs


def parse_patterns(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def matches_any_pattern(values: list[str], patterns: list[str]) -> str:
    for pattern in patterns:
        for value in values:
            if pattern in value.lower():
                return pattern
    return ""


def build_origin_batches(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, str]]]:
    configs = read_config_summary(args.config_summary)
    exclude_patterns = parse_patterns(args.exclude)
    zones: dict[tuple[str, str], dict[str, Any]] = {}
    with open(args.origins_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for record in reader:
            if record.get("scope") != "acceleration_domain":
                continue
            zone_id = record.get("zone_id") or ""
            zone_name = record.get("zone_name") or ""
            origin = (record.get("origin") or "").strip()
            domain_name = (record.get("domain_name") or "").strip()
            if not zone_id or not origin:
                continue
            key = (zone_id, zone_name)
            zone_data = zones.setdefault(
                key,
                {
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "origins": {},
                    "domains": set(),
                },
            )
            zone_data["origins"][origin] = zone_data["origins"].get(origin, 0) + 1
            if domain_name:
                zone_data["domains"].add(domain_name)

    rows: list[dict[str, str]] = []
    excluded_rows: list[dict[str, str]] = []
    grouped: dict[str, list[dict[str, str]]] = {}
    for key, zone_data in zones.items():
        origin_counts = zone_data["origins"]
        primary_origin = sorted(origin_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        config = configs.get(key) or {}
        row_data = {
            "zone_id": zone_data["zone_id"],
            "zone_name": zone_data["zone_name"],
            "primary_origin": primary_origin,
            "origins": ";".join(sorted(origin_counts)),
            "domain_count": str(len(zone_data["domains"])),
            "domains": ";".join(sorted(zone_data["domains"])),
            "config_file": config.get("file", ""),
            "config_status": config.get("status", "missing"),
            "config_error": config.get("error", ""),
        }
        matched_pattern = matches_any_pattern(
            [
                row_data["zone_name"],
                row_data["primary_origin"],
                row_data["origins"],
                row_data["domains"],
            ],
            exclude_patterns,
        )
        if matched_pattern:
            row_data["exclude_reason"] = matched_pattern
            excluded_rows.append(row_data)
            continue
        rows.append(row_data)
        grouped.setdefault(primary_origin, []).append(row_data)

    batches: list[dict[str, Any]] = []
    max_size = max(1, int(args.max_size))
    for origin, group_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        group_rows.sort(key=lambda item: item["zone_name"])
        for idx in range(0, len(group_rows), max_size):
            batch_rows = group_rows[idx : idx + max_size]
            batches.append(
                {
                    "batch_no": len(batches) + 1,
                    "origin": origin,
                    "count": len(batch_rows),
                    "rows": batch_rows,
                }
            )
    return batches, rows, excluded_rows


def cmd_make_migration_batches(args: argparse.Namespace) -> int:
    os.makedirs(args.output_dir, exist_ok=True)
    batches, rows, excluded_rows = build_origin_batches(args)
    fieldnames = [
        "zone_id",
        "zone_name",
        "primary_origin",
        "origins",
        "domain_count",
        "domains",
        "config_file",
        "config_status",
        "config_error",
    ]

    all_zones_path = os.path.join(args.output_dir, "all-zones-by-origin.csv")
    with open(all_zones_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda item: (item["primary_origin"], item["zone_name"])))

    excluded_path = os.path.join(args.output_dir, "excluded-zones.csv")
    with open(excluded_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames + ["exclude_reason"])
        writer.writeheader()
        writer.writerows(sorted(excluded_rows, key=lambda item: (item["exclude_reason"], item["zone_name"])))

    manifest_rows = []
    for batch in batches:
        batch_name = f"batch-{batch['batch_no']:03d}-{safe_filename(batch['origin'])}.csv"
        batch_path = os.path.join(args.output_dir, batch_name)
        with open(batch_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(batch["rows"])
        missing_configs = sum(1 for row_data in batch["rows"] if row_data["config_status"] != "success")
        manifest_rows.append(
            {
                "batch_no": str(batch["batch_no"]),
                "origin": batch["origin"],
                "count": str(batch["count"]),
                "missing_or_failed_configs": str(missing_configs),
                "file": batch_path,
            }
        )

    manifest_path = os.path.join(args.output_dir, "manifest.csv")
    with open(manifest_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["batch_no", "origin", "count", "missing_or_failed_configs", "file"],
        )
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"Wrote batch manifest: {manifest_path}")
    print(f"Wrote all-zone list:  {all_zones_path}")
    print(f"Wrote excluded list:  {excluded_path}")
    print(f"Wrote batch files:    {args.output_dir}")
    print(f"Zones planned:        {len(rows)}")
    print(f"Zones excluded:       {len(excluded_rows)}")
    print(f"Batches planned:      {len(batches)}")
    missing = sum(1 for row_data in rows if row_data["config_status"] != "success")
    if missing:
        print(f"Warning: {missing} zone(s) have missing/failed config exports.", file=sys.stderr)
        return 2
    return 0


def flatten_origin_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for zone_entry in data.get("zones", []):
        zone = zone_entry.get("zone", {})
        zone_id = str(zone.get("ZoneId", ""))
        zone_name = str(zone.get("ZoneName", ""))

        for group in zone_entry.get("origin_groups", []):
            for idx, record in enumerate(group.get("Records") or []):
                rows.append(
                    row(
                        scope="origin_group",
                        zone_id=zone_id,
                        zone_name=zone_name,
                        resource_id=group.get("GroupId"),
                        resource_name=group.get("Name"),
                        domain_name="",
                        path=f"Records[{idx}].Record",
                        origin_type=record.get("Type") or group.get("Type"),
                        origin=record.get("Record"),
                        backup_origin="",
                        host_header=group.get("HostHeader"),
                        origin_protocol="",
                        http_origin_port="",
                        https_origin_port="",
                    )
                )

        for domain in zone_entry.get("acceleration_domains", []):
            info = get_domain_origin_info(domain)
            domain_name = domain.get("DomainName") or domain.get("Host") or domain.get("Name") or ""
            rows.append(
                row(
                    scope="acceleration_domain",
                    zone_id=zone_id,
                    zone_name=zone_name,
                    resource_id=domain_name,
                    resource_name=domain_name,
                    domain_name=domain_name,
                    path="OriginDetail.Origin" if domain.get("OriginDetail") else "OriginInfo.Origin",
                    origin_type=info.get("OriginType"),
                    origin=info.get("Origin"),
                    backup_origin=info.get("BackupOrigin"),
                    host_header=info.get("HostHeader") or domain.get("HostHeader"),
                    origin_protocol=domain.get("OriginProtocol") or info.get("OriginProtocol"),
                    http_origin_port=domain.get("HttpOriginPort") or info.get("HttpOriginPort"),
                    https_origin_port=domain.get("HttpsOriginPort") or info.get("HttpsOriginPort"),
                )
            )

        for rule in zone_entry.get("l7_rules", []):
            for path, action in find_modify_origin_actions(rule):
                params = action.get("ModifyOriginParameters") or {}
                rows.append(
                    row(
                        scope="l7_rule",
                        zone_id=zone_id,
                        zone_name=zone_name,
                        resource_id=rule.get("RuleId"),
                        resource_name=rule.get("RuleName"),
                        domain_name="",
                        path=f"{path}.ModifyOriginParameters.Origin",
                        origin_type=params.get("OriginType"),
                        origin=params.get("Origin"),
                        backup_origin=params.get("BackupOrigin"),
                        host_header=params.get("HostHeader"),
                        origin_protocol=params.get("OriginProtocol"),
                        http_origin_port=params.get("HttpOriginPort"),
                        https_origin_port=params.get("HttpsOriginPort"),
                    )
                )
    return rows


def row(**kwargs: Any) -> dict[str, str]:
    return {k: "" if v is None else str(v) for k, v in kwargs.items()}


def find_modify_origin_actions(obj: Any, path: str = "$") -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(obj, dict):
        if obj.get("Name") == "ModifyOrigin" and isinstance(obj.get("ModifyOriginParameters"), dict):
            found.append((path, obj))
        for key, value in obj.items():
            found.extend(find_modify_origin_actions(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            found.extend(find_modify_origin_actions(value, f"{path}[{idx}]"))
    return found


def get_domain_origin_info(domain: dict[str, Any]) -> dict[str, Any]:
    info = domain.get("OriginInfo") or domain.get("OriginDetail") or {}
    return info if isinstance(info, dict) else {}


def mutable_domain_origin_info(info: dict[str, Any]) -> dict[str, Any]:
    cleaned = copy.deepcopy(info)
    for key in (
        # DescribeAccelerationDomains returns this display-only field, but
        # ModifyAccelerationDomain rejects it inside OriginInfo.
        "OriginGroupName",
    ):
        cleaned.pop(key, None)
    return cleaned


def read_mapping(path: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "old" not in reader.fieldnames or "new" not in reader.fieldnames:
            raise SystemExit("Mapping CSV must contain headers: old,new")
        for line_no, record in enumerate(reader, start=2):
            old = (record.get("old") or "").strip()
            new = (record.get("new") or "").strip()
            if not old or not new:
                print(f"Skipping mapping line {line_no}: old/new is empty", file=sys.stderr)
                continue
            mapping[old] = new
    if not mapping:
        raise SystemExit("Mapping CSV did not contain any usable old,new rows.")
    return mapping


def replace_value(value: Any, mapping: dict[str, str]) -> tuple[Any, bool]:
    if isinstance(value, str) and value in mapping:
        return mapping[value], True
    return value, False


def build_changes(data: dict[str, Any], mapping: dict[str, str], scopes: set[str]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for zone_entry in data.get("zones", []):
        zone = zone_entry.get("zone", {})
        zone_id = zone.get("ZoneId")
        zone_name = zone.get("ZoneName")

        if "origin_group" in scopes:
            for group in zone_entry.get("origin_groups", []):
                updated = copy.deepcopy(group)
                replacements = []
                for idx, record in enumerate(updated.get("Records") or []):
                    new_value, changed = replace_value(record.get("Record"), mapping)
                    if changed:
                        replacements.append({"path": f"Records[{idx}].Record", "old": record.get("Record"), "new": new_value})
                        record["Record"] = new_value
                if replacements:
                    changes.append(
                        {
                            "scope": "origin_group",
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                            "resource_id": group.get("GroupId"),
                            "resource_name": group.get("Name"),
                            "replacements": replacements,
                            "action": "ModifyOriginGroup",
                            "payload": {
                                "ZoneId": zone_id,
                                "GroupId": group.get("GroupId"),
                                "Records": updated.get("Records") or [],
                            },
                        }
                    )

        if "acceleration_domain" in scopes:
            for domain in zone_entry.get("acceleration_domains", []):
                info = mutable_domain_origin_info(get_domain_origin_info(domain))
                replacements = []
                for key in ("Origin", "BackupOrigin"):
                    new_value, changed = replace_value(info.get(key), mapping)
                    if changed:
                        replacements.append({"path": f"OriginInfo.{key}", "old": info.get(key), "new": new_value})
                        info[key] = new_value
                if replacements:
                    domain_name = domain.get("DomainName") or domain.get("Host") or domain.get("Name")
                    changes.append(
                        {
                            "scope": "acceleration_domain",
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                            "resource_id": domain_name,
                            "resource_name": domain_name,
                            "replacements": replacements,
                            "action": "ModifyAccelerationDomain",
                            "payload": {
                                "ZoneId": zone_id,
                                "DomainName": domain_name,
                                "OriginInfo": info,
                            },
                        }
                    )

        if "l7_rule" in scopes:
            for rule in zone_entry.get("l7_rules", []):
                updated_rule = copy.deepcopy(rule)
                replacements = []
                for path, action in find_modify_origin_actions(updated_rule):
                    params = action.get("ModifyOriginParameters") or {}
                    for key in ("Origin", "BackupOrigin"):
                        new_value, changed = replace_value(params.get(key), mapping)
                        if changed:
                            replacements.append(
                                {
                                    "path": f"{path}.ModifyOriginParameters.{key}",
                                    "old": params.get(key),
                                    "new": new_value,
                                }
                            )
                            params[key] = new_value
                if replacements:
                    clean_rule = {
                        key: updated_rule[key]
                        for key in ("RuleId", "RuleName", "Status", "Description", "Branches")
                        if key in updated_rule
                    }
                    changes.append(
                        {
                            "scope": "l7_rule",
                            "zone_id": zone_id,
                            "zone_name": zone_name,
                            "resource_id": rule.get("RuleId"),
                            "resource_name": rule.get("RuleName"),
                            "replacements": replacements,
                            "action": "ModifyL7AccRule",
                            "payload": {
                                "ZoneId": zone_id,
                                "Rule": clean_rule,
                            },
                        }
                    )
    return changes


def cmd_export(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    data = export_all(client, args)
    write_export_files(data, args.json, args.csv)
    print(f"Wrote JSON: {args.json}")
    print(f"Wrote CSV:  {args.csv}")
    if data.get("errors"):
        print(f"Completed with {len(data['errors'])} non-fatal API errors. See JSON errors[] for details.", file=sys.stderr)
        return 2
    return 0


def cmd_replace(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    mapping = read_mapping(args.mapping)
    scopes = parse_scopes(args.scope)

    data = export_all(client, args)
    changes = build_changes(data, mapping, scopes)
    with open(args.plan, "w", encoding="utf-8") as f:
        json.dump({"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "changes": changes}, f, ensure_ascii=False, indent=2)

    print(f"Planned changes: {len(changes)}")
    print(f"Wrote plan: {args.plan}")
    for change in changes:
        print(
            f"- {change['scope']} {change.get('zone_name')} {change.get('resource_name')}: "
            f"{len(change['replacements'])} replacement(s)"
        )

    if not args.apply:
        print("Dry-run only. Add --apply --yes to execute these changes.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to modify without --yes.")

    failures = 0
    for idx, change in enumerate(changes, start=1):
        try:
            print(f"Applying {idx}/{len(changes)} {change['action']} {change.get('resource_name')}", file=sys.stderr)
            response = client.call(change["action"], change["payload"])
            change["response"] = response
        except Exception as exc:
            failures += 1
            change["error"] = str(exc)
            print(f"FAILED {change['action']} {change.get('resource_name')}: {exc}", file=sys.stderr)

    with open(args.plan, "w", encoding="utf-8") as f:
        json.dump({"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "changes": changes}, f, ensure_ascii=False, indent=2)
    if failures:
        print(f"Applied with {failures} failure(s). See plan file for details.", file=sys.stderr)
        return 3
    print("Apply completed.")
    return 0


def cmd_fix_acceleration_domain_host_headers(args: argparse.Namespace) -> int:
    client = require_credentials(args)
    data = export_all(client, args)
    only_domains = set(split_domain_names(args.domain_names)) if args.domain_names else set()
    from_host_headers = set(split_domain_names(args.from_host_header)) if args.from_host_header else set()
    target_ports = acceleration_domain_origin_ports(args)

    changes: list[dict[str, Any]] = []
    for zone_entry in data.get("zones", []):
        zone = zone_entry.get("zone", {})
        zone_id = zone.get("ZoneId")
        zone_name = zone.get("ZoneName")
        for domain in zone_entry.get("acceleration_domains", []):
            domain_name = str(domain.get("DomainName") or domain.get("Host") or domain.get("Name") or "")
            if not domain_name:
                continue
            if only_domains and domain_name not in only_domains:
                continue

            info = mutable_domain_origin_info(get_domain_origin_info(domain))
            old_host_header = str(info.get("HostHeader") or domain.get("HostHeader") or "")
            if from_host_headers and old_host_header not in from_host_headers:
                continue

            current_protocol = str(domain.get("OriginProtocol") or info.get("OriginProtocol") or "")
            current_http_port = domain.get("HttpOriginPort") or info.get("HttpOriginPort")
            current_https_port = domain.get("HttpsOriginPort") or info.get("HttpsOriginPort")
            needs_change = bool(old_host_header)
            needs_change = needs_change or current_protocol != args.origin_protocol
            needs_change = needs_change or str(current_http_port or "") != str(args.http_origin_port)
            needs_change = needs_change or str(current_https_port or "") != str(args.https_origin_port)
            if not needs_change:
                continue

            info.pop("HostHeader", None)
            changes.append(
                {
                    "scope": "acceleration_domain",
                    "zone_id": zone_id,
                    "zone_name": zone_name,
                    "resource_id": domain_name,
                    "resource_name": domain_name,
                    "replacements": [
                        {
                            "path": "OriginInfo.HostHeader",
                            "old": old_host_header,
                            "new": "use acceleration domain",
                        },
                        {
                            "path": "OriginProtocol",
                            "old": current_protocol,
                            "new": args.origin_protocol,
                        },
                        {
                            "path": "HttpOriginPort",
                            "old": current_http_port,
                            "new": args.http_origin_port,
                        },
                        {
                            "path": "HttpsOriginPort",
                            "old": current_https_port,
                            "new": args.https_origin_port,
                        },
                    ],
                    "action": "ModifyAccelerationDomain",
                    "payload": {
                        "ZoneId": zone_id,
                        "DomainName": domain_name,
                        "OriginInfo": info,
                        **target_ports,
                    },
                }
            )

    with open(args.plan, "w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "changes": changes},
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"Planned acceleration domain fixes: {len(changes)}")
    print(f"Wrote plan: {args.plan}")
    for change in changes:
        host_replacement = change["replacements"][0]
        protocol_replacement = change["replacements"][1]
        print(
            f"- {change.get('zone_name')} {change.get('resource_name')}: "
            f"HostHeader {host_replacement['old'] or '(empty)'} -> use acceleration domain; "
            f"OriginProtocol {protocol_replacement['old'] or '(empty)'} -> {protocol_replacement['new']}"
        )

    if not args.apply:
        print("Dry-run only. Add --apply --yes to execute these fixes.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to modify acceleration domains without --yes.")

    failures = 0
    for idx, change in enumerate(changes, start=1):
        try:
            print(f"Applying {idx}/{len(changes)} {change['resource_name']}", file=sys.stderr)
            change["response"] = client.call(change["action"], change["payload"])
        except Exception as exc:
            failures += 1
            change["error"] = str(exc)
            print(f"FAILED {change['resource_name']}: {exc}", file=sys.stderr)

    with open(args.plan, "w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "changes": changes},
            f,
            ensure_ascii=False,
            indent=2,
        )
    if failures:
        print(f"Applied with {failures} failure(s). See plan file for details.", file=sys.stderr)
        return 3
    print("Apply completed.")
    return 0


def ownership_row(zone_name: str, response: dict[str, Any]) -> dict[str, str]:
    verification = response.get("OwnershipVerification") or {}
    dns = verification.get("DnsVerification") or {}
    file_verify = verification.get("FileVerification") or {}
    ns = verification.get("NsVerification") or {}
    return {
        "zone_name": zone_name,
        "zone_id": str(response.get("ZoneId") or ""),
        "subdomain": str(dns.get("Subdomain") or ""),
        "record_type": str(dns.get("RecordType") or ""),
        "record_value": str(dns.get("RecordValue") or ""),
        "file_path": str(file_verify.get("Path") or ""),
        "file_content": str(file_verify.get("Content") or ""),
        "name_servers": ";".join(str(item) for item in (ns.get("NameServers") or [])),
        "request_id": str(response.get("RequestId") or ""),
    }


def cmd_create_zone(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "Type": args.type,
        "ZoneName": args.zone_name,
    }
    if args.area:
        payload["Area"] = args.area
    if args.plan_id:
        payload["PlanId"] = args.plan_id
    if args.alias_zone_name:
        payload["AliasZoneName"] = args.alias_zone_name

    print(json.dumps({"Action": "CreateZone", "Payload": payload}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to create the zone.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to create zone without --yes.")

    client = require_credentials(args)
    response = client.call("CreateZone", payload)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(response, f, ensure_ascii=False, indent=2, sort_keys=True)

    row_data = ownership_row(args.zone_name, response)
    with open(args.ownership_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "zone_name",
                "zone_id",
                "subdomain",
                "record_type",
                "record_value",
                "file_path",
                "file_content",
                "name_servers",
                "request_id",
            ],
        )
        writer.writeheader()
        writer.writerow(row_data)

    print(f"Created zone: {row_data['zone_name']} {row_data['zone_id']}")
    print(f"Wrote response JSON: {args.response_json}")
    print(f"Wrote ownership CSV: {args.ownership_csv}")
    if row_data["subdomain"] and row_data["record_value"]:
        print(f"TXT verification: {row_data['subdomain']} = {row_data['record_value']}")
    if row_data["name_servers"]:
        print(f"NS verification: {row_data['name_servers']}")
    return 0


def cmd_verify_ownership(args: argparse.Namespace) -> int:
    payload = {"Domain": args.domain}
    print(json.dumps({"Action": "VerifyOwnership", "Payload": payload}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to verify ownership.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to verify ownership without --yes.")

    client = require_credentials(args)
    response = client.call("VerifyOwnership", payload)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(response, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"VerifyOwnership response written: {args.response_json}")
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def cmd_import_zone_config(args: argparse.Namespace) -> int:
    with open(args.config_json, "r", encoding="utf-8") as f:
        config = json.load(f)
    content = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    payload = {"ZoneId": args.zone_id, "Content": content}
    print(
        json.dumps(
            {
                "Action": "ImportZoneConfig",
                "Payload": {
                    "ZoneId": args.zone_id,
                    "ConfigFile": args.config_json,
                    "ContentBytes": len(content.encode("utf-8")),
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if not args.apply:
        print("Dry-run only. Add --apply --yes to import the config.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to import zone config without --yes.")

    client = require_credentials(args)
    response = client.call("ImportZoneConfig", payload)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(response, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"ImportZoneConfig response written: {args.response_json}")
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def cmd_bind_shared_cname(args: argparse.Namespace) -> int:
    domains = split_domain_names(args.domain_names)
    if not domains:
        raise SystemExit("At least one domain name is required.")
    payload = {
        "ZoneId": args.zone_id,
        "BindType": args.bind_type,
        "BindSharedCNAMEMaps": [
            {
                "SharedCNAME": args.shared_cname,
                "DomainNames": domains,
            }
        ],
    }
    print(json.dumps({"Action": "BindSharedCNAME", "Payload": payload}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to bind shared CNAME.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to bind shared CNAME without --yes.")

    client = require_credentials(args)
    response = client.call("BindSharedCNAME", payload)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(response, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"BindSharedCNAME response written: {args.response_json}")
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def split_domain_names(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,;]", value or "") if item.strip()]


def cmd_delete_acceleration_domains(args: argparse.Namespace) -> int:
    domains = split_domain_names(args.domain_names)
    if not domains:
        raise SystemExit("At least one domain name is required.")
    payload: dict[str, Any] = {
        "ZoneId": args.zone_id,
        "DomainNames": domains,
    }
    if args.force:
        payload["Force"] = True
    print(json.dumps({"Action": "DeleteAccelerationDomains", "Payload": payload}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to delete acceleration domains.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to delete acceleration domains without --yes.")
    client = require_credentials(args)
    response = client.call("DeleteAccelerationDomains", payload)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(response, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"DeleteAccelerationDomains response written: {args.response_json}")
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def describe_origin_acl(client: TencentCloudClient, zone_id: str) -> dict[str, Any]:
    return client.call("DescribeOriginACL", {"ZoneId": zone_id})


def origin_acl_enabled(response: dict[str, Any]) -> bool:
    info = response.get("OriginACLInfo") or response.get("OriginACL") or response
    status = str(info.get("Status") or "").lower() if isinstance(info, dict) else ""
    l7_hosts = info.get("L7Hosts") if isinstance(info, dict) else []
    l4_proxy_ids = info.get("L4ProxyIds") if isinstance(info, dict) else []
    return status in {"online", "updating"} or bool(l7_hosts) or bool(l4_proxy_ids)


def enable_origin_acl_for_l7_hosts(
    client: TencentCloudClient,
    zone_id: str,
    hosts: list[str],
    origin_acl_family: str = "",
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    unique_hosts = list(dict.fromkeys(hosts))
    if not unique_hosts:
        raise EdgeOneError("No L7 hosts provided for origin protection.")
    describe_response: dict[str, Any] = {}
    try:
        describe_response = describe_origin_acl(client, zone_id)
    except Exception:
        describe_response = {}

    if origin_acl_enabled(describe_response):
        action = "ModifyOriginACL"
        payload: dict[str, Any] = {
            "ZoneId": zone_id,
            "OriginACLEntities": [
                {
                    "OperationMode": "enable",
                    "Type": "l7",
                    "Instances": unique_hosts[:200],
                }
            ],
        }
    else:
        action = "EnableOriginACL"
        payload = {
            "ZoneId": zone_id,
            "L7EnableMode": "specific",
            "L7Hosts": unique_hosts[:200],
        }
    if origin_acl_family:
        payload["OriginACLFamily"] = origin_acl_family
    return action, payload, client.call(action, payload)


def cmd_enable_origin_acl(args: argparse.Namespace) -> int:
    hosts = split_domain_names(args.hosts)
    payload_preview = {
        "ZoneId": args.zone_id,
        "L7Hosts": hosts,
        "OriginACLFamily": args.origin_acl_family,
    }
    print(json.dumps({"Action": "EnableOrModifyOriginACL", "Payload": payload_preview}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to enable origin protection.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to enable origin protection without --yes.")
    client = require_credentials(args)
    action, payload, response = enable_origin_acl_for_l7_hosts(
        client,
        args.zone_id,
        hosts,
        args.origin_acl_family,
    )
    os.makedirs(os.path.dirname(args.response_json) or ".", exist_ok=True)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(
            {"action": action, "payload": payload, "response": response},
            f,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    print(f"{action} response written: {args.response_json}")
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def read_csv_int(record: dict[str, str], key: str, default: int) -> int:
    raw_value = (record.get(key) or "").strip()
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise SystemExit(f"Invalid integer in CSV column {key}: {raw_value}") from exc


def acceleration_domain_origin_ports(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "OriginProtocol": args.origin_protocol,
        "HttpOriginPort": args.http_origin_port,
        "HttpsOriginPort": args.https_origin_port,
    }


def is_create_acceleration_domain_retryable(error: str) -> bool:
    return any(
        token in error
        for token in (
            "OperationDenied.SharedCnameConfigInitializing",
            "OperationDenied.SharedCnameCN2NotMatch",
            "OperationDenied.ResourceLockedTemporary",
            "RequestLimitExceeded",
        )
    )


def csv_acceleration_domain_origin_ports(record: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    return {
        "OriginProtocol": (record.get("origin_protocol") or "").strip() or args.origin_protocol,
        "HttpOriginPort": read_csv_int(record, "http_origin_port", args.http_origin_port),
        "HttpsOriginPort": read_csv_int(record, "https_origin_port", args.https_origin_port),
    }


def translated_custom_host_header(
    host_header: str,
    old_domain: str,
    new_domain: str,
    template_zone_name: str,
    new_zone_name: str,
) -> str:
    host_header = host_header.strip()
    if not host_header:
        return ""
    if host_header in {"$host", old_domain, new_domain, template_zone_name, new_zone_name}:
        return ""
    if host_header.endswith("." + template_zone_name):
        translated = host_header[: -len(template_zone_name)] + new_zone_name
        if translated in {new_domain, new_zone_name}:
            return ""
        return translated
    return host_header


def template_acceleration_domains(
    origins_csv: str,
    template_zone_name: str,
    new_zone_name: str,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    domains: list[dict[str, Any]] = []
    with open(origins_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for record in reader:
            if record.get("scope") != "acceleration_domain":
                continue
            if record.get("zone_name") != template_zone_name:
                continue
            old_domain = record.get("domain_name") or record.get("resource_name") or ""
            if not old_domain:
                continue
            if old_domain == template_zone_name:
                new_domain = new_zone_name
            elif old_domain == "*." + template_zone_name:
                new_domain = "*." + new_zone_name
            elif old_domain.endswith("." + template_zone_name):
                new_domain = old_domain[: -len(template_zone_name)] + new_zone_name
            else:
                new_domain = old_domain.replace(template_zone_name, new_zone_name)

            origin_info = {
                "OriginType": record.get("origin_type") or "IP_DOMAIN",
                "Origin": record.get("origin") or "",
            }
            host_header = translated_custom_host_header(
                record.get("host_header") or "",
                old_domain,
                new_domain,
                template_zone_name,
                new_zone_name,
            )
            if host_header:
                origin_info["HostHeader"] = host_header
            if record.get("backup_origin"):
                origin_info["BackupOrigin"] = record["backup_origin"]
            domains.append(
                {
                    "DomainName": new_domain,
                    "OriginInfo": origin_info,
                    **csv_acceleration_domain_origin_ports(record, args),
                    "IPv6Status": "follow",
                }
            )
    unique: dict[str, dict[str, Any]] = {}
    for item in domains:
        unique[item["DomainName"]] = item
    return list(unique.values())


def list_acceleration_domain_names(client: TencentCloudClient, zone_id: str, limit: int = DEFAULT_LIMIT) -> set[str]:
    names: set[str] = set()
    try:
        items = paged_call(
            client,
            "DescribeAccelerationDomains",
            {"ZoneId": zone_id},
            ("AccelerationDomains", "Domains"),
            limit,
        )
    except Exception:
        return names
    for item in items:
        name = item.get("DomainName") or item.get("Host") or item.get("Name")
        if name:
            names.add(str(name))
    return names


def cmd_create_acceleration_domains(args: argparse.Namespace) -> int:
    if args.template_zone_name:
        domain_payloads = template_acceleration_domains(args.origins_csv, args.template_zone_name, args.zone_name, args)
    else:
        domain_names = split_domain_names(args.domain_names)
        if not domain_names:
            raise SystemExit("At least one domain name is required.")
        if not args.origin:
            raise SystemExit("--origin is required when --template-zone-name is not provided.")
        domain_payloads = []
        for domain_name in domain_names:
            origin_info = {
                "OriginType": args.origin_type,
                "Origin": args.origin,
            }
            if args.host_header:
                origin_info["HostHeader"] = args.host_header
            domain_payloads.append(
                {
                    "DomainName": domain_name,
                    "OriginInfo": origin_info,
                    **acceleration_domain_origin_ports(args),
                    "IPv6Status": "follow",
                }
            )
    if args.only_domain:
        only = {item.strip() for item in args.only_domain.split(",") if item.strip()}
        domain_payloads = [item for item in domain_payloads if item["DomainName"] in only]
    if not domain_payloads:
        raise SystemExit("No acceleration domains to create.")
    payloads = []
    for item in domain_payloads:
        payload = {"ZoneId": args.zone_id, **item}
        if args.shared_cname:
            payload["SharedCNAME"] = args.shared_cname
        payloads.append(payload)
    print(json.dumps({"Action": "CreateAccelerationDomain", "Payloads": payloads}, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry-run only. Add --apply --yes to create acceleration domains.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to create acceleration domains without --yes.")

    client = require_credentials(args)
    results = []
    failures = 0
    for payload in payloads:
        created = False
        last_error = ""
        for attempt in range(args.create_domain_retries + 1):
            try:
                response = client.call("CreateAccelerationDomain", payload)
                results.append({"domain": payload["DomainName"], "payload": payload, "response": response})
                print(f"Created acceleration domain: {payload['DomainName']}")
                created = True
                break
            except Exception as exc:
                last_error = str(exc)
                if not is_create_acceleration_domain_retryable(last_error) or attempt >= args.create_domain_retries:
                    break
                wait_seconds = args.create_domain_retry_wait_seconds
                print(
                    f"CreateAccelerationDomain not ready for {payload['DomainName']}; "
                    f"retrying in {wait_seconds}s ({attempt + 1}/{args.create_domain_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait_seconds)
        if not created:
            failures += 1
            results.append({"domain": payload["DomainName"], "payload": payload, "error": last_error})
            print(f"FAILED CreateAccelerationDomain {payload['DomainName']}: {last_error}", file=sys.stderr)
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"Wrote create acceleration domains response: {args.response_json}")
    return 3 if failures else 0


def cmd_modify_hosts_certificate(args: argparse.Namespace) -> int:
    hosts = [item.strip() for item in args.hosts.split(",") if item.strip()]
    if not hosts:
        raise SystemExit("At least one host is required.")
    print(
        json.dumps(
            {
                "Action": "ModifyHostsCertificate",
                "ZoneId": args.zone_id,
                "Hosts": hosts,
                "Mode": args.mode,
                "CertId": args.cert_id or ("auto" if args.auto_cert else ""),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if not args.apply:
        print("Dry-run only. Add --apply --yes to configure certificates.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to configure certificates without --yes.")

    client = require_credentials(args)
    ssl_client = require_ssl_client(args) if args.auto_cert and not args.cert_id and args.mode == "sslcert" else None
    results = []
    issues = []
    for host in hosts:
        cert_id = args.cert_id
        cert_match = None
        if not cert_id and args.auto_cert and args.mode == "sslcert":
            try:
                cert_id, cert_match = find_default_certificate_for_host(client, args.zone_id, host)
            except Exception as exc:
                issues.append({"host": host, "status": "eo_lookup_failed", "cert_id": "", "error": str(exc)})
            if not cert_id and ssl_client:
                try:
                    cert_id, cert_match = find_certificate_for_host(ssl_client, host)
                except Exception as exc:
                    issues.append({"host": host, "status": "ssl_lookup_failed", "cert_id": "", "error": str(exc)})
                    continue
        if args.mode == "sslcert" and not cert_id:
            issues.append({"host": host, "status": "missing", "cert_id": "", "error": "No matching certificate found"})
            continue
        payload: dict[str, Any] = {"ZoneId": args.zone_id, "Hosts": [host], "Mode": args.mode}
        if cert_id:
            payload["ServerCertInfo"] = [{"CertId": cert_id}]
        try:
            response = client.call("ModifyHostsCertificate", payload)
            results.append({"host": host, "cert_id": cert_id, "match": cert_match, "payload": payload, "response": response})
        except Exception as exc:
            issues.append({"host": host, "status": "bind_failed", "cert_id": cert_id, "error": str(exc)})
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, ensure_ascii=False, indent=2, sort_keys=True)
    write_certificate_issues(args.issues_csv, issues)
    print(f"ModifyHostsCertificate response written: {args.response_json}")
    print(f"Certificate issues written:             {args.issues_csv}")
    return 0


def root_domain_from_host(host: str) -> str:
    host = host.strip().lstrip("*.").strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def cert_domain_matches(cert_domain: str, host: str) -> bool:
    cert_domain = (cert_domain or "").strip().lower()
    host = host.strip().lower()
    if not cert_domain:
        return False
    names = [item.strip() for item in cert_domain.replace("\n", ",").replace(";", ",").split(",") if item.strip()]
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and host.endswith(name[1:]):
            return True
    return False


def certificate_id(cert: dict[str, Any]) -> str:
    for key in ("CertificateId", "CertId", "Id"):
        if cert.get(key):
            return str(cert[key])
    return ""


def certificate_domain(cert: dict[str, Any]) -> str:
    for key in (
        "Domain",
        "CertSANs",
        "SubjectAltName",
        "SubjectAltNames",
        "Alias",
        "CertificateExtra",
        "DnsNames",
    ):
        value = cert.get(key)
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        if value:
            return str(value)
    return ""


def certificate_is_issued(cert: dict[str, Any]) -> bool:
    status = cert.get("Status")
    status_msg = str(cert.get("StatusMsg") or "").lower()
    if status in (1, "1", "issued", "deployed"):
        return True
    return status_msg in {"", "issued", "deployed"}


def iter_certificate_domain_values(cert: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in cert.items():
        lower = key.lower()
        if any(token in lower for token in ("domain", "san", "subject", "dns")):
            if isinstance(value, list):
                values.extend(str(item) for item in value)
            elif isinstance(value, dict):
                values.extend(str(v) for v in value.values())
            elif value:
                values.append(str(value))
    explicit = certificate_domain(cert)
    if explicit:
        values.append(explicit)
    return values


def find_certificate_for_host(ssl_client: TencentCloudClient, host: str) -> tuple[str, dict[str, Any] | None]:
    root = root_domain_from_host(host)
    search_keys = [host, root, "*." + root]
    seen_ids: set[str] = set()
    candidates: list[dict[str, Any]] = []
    for search_key in search_keys:
        response = ssl_client.call(
            "DescribeCertificates",
            {
                "Offset": 0,
                "Limit": 1000,
                "SearchKey": search_key,
                "CertificateType": "SVR",
            },
        )
        for cert in response.get("Certificates") or []:
            cert_id = certificate_id(cert)
            if cert_id and cert_id not in seen_ids:
                seen_ids.add(cert_id)
                candidates.append(cert)
    matching = [
        cert
        for cert in candidates
        if any(cert_domain_matches(value, host) for value in iter_certificate_domain_values(cert))
    ]
    issued = [cert for cert in matching if certificate_is_issued(cert)]
    chosen = issued[0] if issued else (matching[0] if matching else None)
    return (certificate_id(chosen), chosen) if chosen else ("", None)


def find_default_certificate_for_host(
    teo_client: TencentCloudClient,
    zone_id: str,
    host: str,
) -> tuple[str, dict[str, Any] | None]:
    response = teo_client.call(
        "DescribeDefaultCertificates",
        {
            "ZoneId": zone_id,
            "Offset": 0,
            "Limit": 100,
        },
    )
    candidates = response.get("DefaultServerCertInfo") or []
    matching = [
        cert
        for cert in candidates
        if any(cert_domain_matches(value, host) for value in iter_certificate_domain_values(cert))
    ]
    deployed = [cert for cert in matching if str(cert.get("Status") or "").lower() in {"deployed", "issued", ""}]
    chosen = deployed[0] if deployed else (matching[0] if matching else None)
    return (certificate_id(chosen), chosen) if chosen else ("", None)


def write_certificate_issues(path: str, rows: list[dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "status", "cert_id", "error"])
        writer.writeheader()
        writer.writerows(rows)


def cmd_find_certificate(args: argparse.Namespace) -> int:
    cert_id = ""
    cert = None
    if args.zone_id:
        teo_client = require_credentials(args)
        cert_id, cert = find_default_certificate_for_host(teo_client, args.zone_id, args.host)
    if not cert_id:
        ssl_client = require_ssl_client(args)
        cert_id, cert = find_certificate_for_host(ssl_client, args.host)
    result = {
        "host": args.host,
        "cert_id": cert_id,
        "domain_values": iter_certificate_domain_values(cert or {}) if cert else [],
        "certificate": cert,
    }
    with open(args.response_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"Wrote certificate lookup: {args.response_json}")
    return 0


def write_ownership_csv(path: str, row_data: dict[str, str]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "zone_name",
                "zone_id",
                "subdomain",
                "record_type",
                "record_value",
                "file_path",
                "file_content",
                "name_servers",
                "request_id",
            ],
        )
        writer.writeheader()
        writer.writerow(row_data)


def ownership_csv_has_dns_txt(path: str) -> bool:
    if not os.path.exists(path):
        return False
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if (row.get("subdomain") or "").strip() and (row.get("record_value") or "").strip():
                return True
    return False


def read_batch_rows(path: str) -> list[dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_batch_status(path: str, rows: list[dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "zone_name",
                "old_zone_id",
                "new_zone_id",
                "status",
                "exit_code",
                "error",
                "output_dir",
                "started_at",
                "finished_at",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def existing_successful_batch_zones(status_csv: str) -> set[str]:
    successful: set[str] = set()
    if not os.path.exists(status_csv):
        return successful
    with open(status_csv, "r", encoding="utf-8-sig", newline="") as f:
        for row_data in csv.DictReader(f):
            if row_data.get("status") == "success" and row_data.get("zone_name"):
                successful.add(row_data["zone_name"])
    return successful


def existing_onboard_zone(output_dir: str, zone_name: str) -> tuple[str, str]:
    prefix = safe_filename(zone_name)
    create_json = os.path.join(output_dir, f"create-zone-{prefix}.json")
    ownership_csv = os.path.join(output_dir, f"ownership-{prefix}.csv")
    if not os.path.exists(create_json) or not os.path.exists(ownership_csv):
        return "", ""
    with open(create_json, "r", encoding="utf-8") as f:
        zone_id = str((json.load(f) or {}).get("ZoneId") or "")
    return zone_id, ownership_csv if zone_id else ""


def has_onboard_file(output_dir: str, zone_name: str, prefix: str) -> bool:
    return os.path.exists(os.path.join(output_dir, f"{prefix}-{safe_filename(zone_name)}.json")) or os.path.exists(
        os.path.join(output_dir, f"{prefix}-{safe_filename(zone_name)}.csv")
    )


def is_system_network_error(message: str) -> bool:
    markers = (
        "Connection refused",
        "Remote end closed connection without response",
        "nodename nor servname provided",
        "Name or service not known",
        "Temporary failure in name resolution",
        "Network is unreachable",
        "timed out",
    )
    return any(marker in message for marker in markers)


def find_recent_dns_domain_cache(output_dir: str, target_cache_json: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(output_dir)) or "."
    candidates: list[tuple[float, str]] = []
    for root, _, files in os.walk(base_dir):
        if "dns-domain-cache.json" not in files:
            continue
        path = os.path.join(root, "dns-domain-cache.json")
        if os.path.abspath(path) == os.path.abspath(target_cache_json):
            continue
        candidates.append((os.path.getmtime(path), path))
    return sorted(candidates, reverse=True)[0][1] if candidates else ""


def dns_cache_is_stale(cache_json: str, env_file: str) -> bool:
    if not os.path.exists(cache_json):
        return True
    if env_file and os.path.exists(env_file):
        return os.path.getmtime(env_file) > os.path.getmtime(cache_json)
    return False


def build_dns_domain_cache(args: argparse.Namespace, cache_json: str) -> None:
    dns_cmd = [
        sys.executable,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_txt_verify_tool.py"),
        "--env-file",
        args.dns_env_file,
        "--retries",
        "8",
        "cache-domains",
        "--out",
        cache_json,
        "--no-legacy-dnspod",
    ]
    if args.dns_provider == "alidns":
        dns_cmd.append("--no-dnspod")
    elif args.dns_provider == "dnspod":
        dns_cmd.append("--no-alidns")
    try:
        subprocess.run(dns_cmd, check=True)
    except subprocess.CalledProcessError:
        fallback_cache = find_recent_dns_domain_cache(args.output_dir, cache_json)
        if not fallback_cache:
            raise
        shutil.copy2(fallback_cache, cache_json)
        print(
            f"DNS domain cache build failed; reused recent cache: {fallback_cache}",
            file=sys.stderr,
        )


def cmd_migrate_batch(args: argparse.Namespace) -> int:
    rows = read_batch_rows(args.batch_csv)
    if not rows:
        raise SystemExit(f"Batch CSV has no rows: {args.batch_csv}")

    os.makedirs(args.output_dir, exist_ok=True)
    dns_domain_cache_json = args.dns_domain_cache_json or os.path.join(args.output_dir, "dns-domain-cache.json")
    if args.apply and not args.skip_dns and dns_cache_is_stale(dns_domain_cache_json, args.dns_env_file):
        print(f"Building DNS domain cache: {dns_domain_cache_json}", file=sys.stderr)
        build_dns_domain_cache(args, dns_domain_cache_json)
    status_csv = args.status_csv or os.path.join(args.output_dir, "batch-status.csv")
    previous_success = existing_successful_batch_zones(status_csv) if args.resume else set()
    status_rows: list[dict[str, str]] = []
    failures = 0

    print(
        json.dumps(
            {
                "workflow": "migrate-batch",
                "batch_csv": args.batch_csv,
                "zones": len(rows),
                "shared_cname": args.shared_cname,
                "plan_id": args.plan_id,
                "area": args.area,
                "delete_old_zone": args.delete_old_zone,
                "auto_cert": args.auto_cert,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if not args.apply:
        print("Dry-run only. Add --apply --yes to run this batch.")

    for idx, row_data in enumerate(rows, start=1):
        zone_name = row_data.get("zone_name") or ""
        old_zone_id = row_data.get("zone_id") or ""
        config_file = row_data.get("config_file") or ""
        domains = row_data.get("domains") or ""
        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        output_dir = os.path.join(args.output_dir, f"{idx:03d}-{safe_filename(zone_name)}")

        if args.resume and zone_name in previous_success:
            status_rows.append(
                {
                    "zone_name": zone_name,
                    "old_zone_id": old_zone_id,
                    "new_zone_id": "",
                    "status": "skipped_success",
                    "exit_code": "0",
                    "error": "",
                    "output_dir": output_dir,
                    "started_at": started_at,
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
            continue

        print(f"Batch {idx}/{len(rows)} migrating {zone_name} {old_zone_id}", file=sys.stderr)
        if not zone_name or not config_file or (args.delete_old_zone and not old_zone_id):
            failures += 1
            missing_message = "Missing zone_name or config_file in batch CSV"
            if args.delete_old_zone and not old_zone_id:
                missing_message = "Missing zone_id in batch CSV; required with --delete-old-zone"
            status_rows.append(
                {
                    "zone_name": zone_name,
                    "old_zone_id": old_zone_id,
                    "new_zone_id": "",
                    "status": "failed",
                    "exit_code": "2",
                    "error": missing_message,
                    "output_dir": output_dir,
                    "started_at": started_at,
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
            write_batch_status(status_csv, status_rows)
            continue

        if not args.apply:
            status_rows.append(
                {
                    "zone_name": zone_name,
                    "old_zone_id": old_zone_id,
                    "new_zone_id": "",
                    "status": "dry_run",
                    "exit_code": "0",
                    "error": "",
                    "output_dir": output_dir,
                    "started_at": started_at,
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
            continue

        existing_zone_id, existing_ownership_csv = existing_onboard_zone(output_dir, zone_name)
        onboard_args = copy.copy(args)
        onboard_args.zone_name = zone_name
        onboard_args.existing_zone_id = existing_zone_id or None
        onboard_args.existing_ownership_csv = existing_ownership_csv or None
        onboard_args.alias_zone_name = None
        onboard_args.old_zone_id = old_zone_id
        onboard_args.config_json = config_file
        onboard_args.template_zone_name = zone_name if old_zone_id else None
        onboard_args.domain_names = domains
        onboard_args.output_dir = output_dir
        onboard_args.origin = None if old_zone_id else (row_data.get("primary_origin") or row_data.get("origins") or "")
        onboard_args.only_domain = None
        onboard_args.skip_dns = args.skip_dns or has_onboard_file(output_dir, zone_name, "dns-txt-add")
        onboard_args.dns_domain_cache_json = dns_domain_cache_json
        onboard_args.skip_import_config = False
        onboard_args.skip_existing_domains = True

        try:
            exit_code = cmd_onboard_zone(onboard_args)
            new_zone_id = existing_zone_id
            create_json = os.path.join(output_dir, f"create-zone-{safe_filename(zone_name)}.json")
            if os.path.exists(create_json):
                with open(create_json, "r", encoding="utf-8") as f:
                    new_zone_id = ownership_row(zone_name, json.load(f)).get("zone_id", "")
            if exit_code:
                failures += 1
            status_rows.append(
                {
                    "zone_name": zone_name,
                    "old_zone_id": old_zone_id,
                    "new_zone_id": new_zone_id,
                    "status": "success" if exit_code == 0 else "failed",
                    "exit_code": str(exit_code),
                    "error": "",
                    "output_dir": output_dir,
                    "started_at": started_at,
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
        except Exception as exc:
            failures += 1
            error_message = str(exc)
            new_zone_id = existing_zone_id
            status_rows.append(
                {
                    "zone_name": zone_name,
                    "old_zone_id": old_zone_id,
                    "new_zone_id": new_zone_id,
                    "status": "failed",
                    "exit_code": "1",
                    "error": error_message,
                    "output_dir": output_dir,
                    "started_at": started_at,
                    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
            print(f"FAILED migrate {zone_name}: {exc}", file=sys.stderr)
            if is_system_network_error(error_message):
                print(
                    "System network error detected; stopping this batch to avoid marking more zones failed.",
                    file=sys.stderr,
                )
                write_batch_status(status_csv, status_rows)
                break
        write_batch_status(status_csv, status_rows)
        if args.stop_on_error and failures:
            break

    write_batch_status(status_csv, status_rows)
    print(f"Wrote batch status: {status_csv}")
    print(f"Batch completed with {failures} failure(s).")
    return 3 if failures else 0


def cmd_onboard_zone(args: argparse.Namespace) -> int:
    workspace = args.output_dir or "."
    os.makedirs(workspace, exist_ok=True)
    prefix = safe_filename(args.zone_name)
    create_response_json = os.path.join(workspace, f"create-zone-{prefix}.json")
    ownership_csv = os.path.join(workspace, f"ownership-{prefix}.csv")
    dns_result_csv = os.path.join(workspace, f"dns-txt-add-{prefix}.csv")
    verify_response_json = os.path.join(workspace, f"verify-ownership-{prefix}.json")
    import_response_json = os.path.join(workspace, f"import-zone-config-{prefix}.json")
    create_domains_response_json = os.path.join(workspace, f"create-acceleration-domains-{prefix}.json")
    origin_acl_response_json = os.path.join(workspace, f"enable-origin-acl-{prefix}.json")
    origin_acl_issues_csv = os.path.join(workspace, f"origin-acl-issues-{prefix}.csv")
    certificate_response_json = os.path.join(workspace, f"modify-hosts-certificate-{prefix}.json")
    certificate_issues_csv = os.path.join(workspace, f"certificate-issues-{prefix}.csv")

    create_payload: dict[str, Any] = {
        "Type": args.type,
        "ZoneName": args.zone_name,
    }
    if args.area:
        create_payload["Area"] = args.area
    if args.plan_id:
        create_payload["PlanId"] = args.plan_id
    if args.alias_zone_name:
        create_payload["AliasZoneName"] = args.alias_zone_name

    print(
        json.dumps(
            {
                "workflow": "onboard-zone",
                "steps": [
                    "CreateZone",
                    "Add ownership TXT via dns_txt_verify_tool.py",
                    f"sleep {args.verify_wait_seconds}s",
                    "VerifyOwnership",
                    "ImportZoneConfig",
                    "Delete old zone if requested",
                    "CreateAccelerationDomain with SharedCNAME",
                    "ModifyHostsCertificate",
                ],
                "create_payload": create_payload,
                "config_json": args.config_json,
                "shared_cname": args.shared_cname,
                "domain_names": args.domain_names,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if not args.apply:
        print("Dry-run only. Add --apply --yes to run the workflow.")
        return 0
    if not args.yes:
        raise SystemExit("Refusing to run onboard workflow without --yes.")

    client = require_credentials(args)

    if args.existing_zone_id:
        print("Step 1/6 CreateZone skipped; using existing zone", file=sys.stderr)
        zone_id = args.existing_zone_id
        ownership_csv = args.existing_ownership_csv or ownership_csv
        if not os.path.exists(ownership_csv):
            raise EdgeOneError(f"Ownership CSV does not exist: {ownership_csv}")
        print(f"Using existing zone: {args.zone_name} {zone_id}")
        print(f"Using ownership CSV: {ownership_csv}")
    else:
        print("Step 1/6 CreateZone", file=sys.stderr)
        create_response = client.call("CreateZone", create_payload)
        with open(create_response_json, "w", encoding="utf-8") as f:
            json.dump(create_response, f, ensure_ascii=False, indent=2, sort_keys=True)
        row_data = ownership_row(args.zone_name, create_response)
        write_ownership_csv(ownership_csv, row_data)
        zone_id = row_data["zone_id"]
        if not zone_id:
            raise EdgeOneError(f"CreateZone did not return ZoneId. See {create_response_json}")
        print(f"Created zone: {args.zone_name} {zone_id}")
        print(f"Wrote ownership CSV: {ownership_csv}")

    if args.skip_dns:
        print("Step 2/6 Add ownership TXT skipped", file=sys.stderr)
    elif not ownership_csv_has_dns_txt(ownership_csv):
        print("Step 2/6 Add ownership TXT skipped; no ownership TXT returned by CreateZone", file=sys.stderr)
    else:
        print("Step 2/6 Add ownership TXT", file=sys.stderr)
        dns_cmd = [
            sys.executable,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_txt_verify_tool.py"),
            "--env-file",
            args.dns_env_file,
            "add-txt",
            "--csv",
            ownership_csv,
            "--out",
            dns_result_csv,
            "--ttl",
            str(args.dns_ttl),
            "--no-legacy-dnspod",
            "--apply",
            "--yes",
        ]
        dns_domain_cache_json = getattr(args, "dns_domain_cache_json", "") or ""
        if dns_domain_cache_json:
            dns_cmd.extend(["--domain-cache-json", dns_domain_cache_json])
        if args.dns_provider == "alidns":
            dns_cmd.append("--no-dnspod")
        elif args.dns_provider == "dnspod":
            dns_cmd.append("--no-alidns")
        subprocess.run(dns_cmd, check=True)

    print(f"Step 3/6 Wait {args.verify_wait_seconds}s before VerifyOwnership", file=sys.stderr)
    if args.verify_wait_seconds > 0:
        time.sleep(args.verify_wait_seconds)

    print("Step 4/6 VerifyOwnership", file=sys.stderr)
    verify_response = client.call("VerifyOwnership", {"Domain": args.zone_name})
    with open(verify_response_json, "w", encoding="utf-8") as f:
        json.dump(verify_response, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"Wrote verify response: {verify_response_json}")

    if args.skip_import_config:
        print("Step 5/6 ImportZoneConfig skipped", file=sys.stderr)
    else:
        print("Step 5/6 ImportZoneConfig", file=sys.stderr)
        with open(args.config_json, "r", encoding="utf-8") as f:
            config = json.load(f)
        content = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        import_response = None
        for attempt in range(args.import_config_retries + 1):
            try:
                import_response = client.call("ImportZoneConfig", {"ZoneId": zone_id, "Content": content})
                break
            except EdgeOneError as exc:
                message = str(exc)
                retryable = (
                    "The current zone status does not support importing configurations" in message
                    or "ResourceLockedTemporary" in message
                    or "RequestLimitExceeded" in message
                )
                if not retryable or attempt >= args.import_config_retries:
                    raise
                wait_seconds = args.import_config_retry_wait_seconds
                print(
                    f"ImportZoneConfig not ready for {args.zone_name}; "
                    f"retrying in {wait_seconds}s ({attempt + 1}/{args.import_config_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait_seconds)
        if import_response is None:
            raise EdgeOneError(f"ImportZoneConfig did not return a response for {args.zone_name}")
        with open(import_response_json, "w", encoding="utf-8") as f:
            json.dump(import_response, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"Wrote import response: {import_response_json}")

    old_delete_response_json = os.path.join(workspace, f"delete-old-zone-{prefix}.json")
    old_disable_response_json = os.path.join(workspace, f"disable-old-zone-{prefix}.json")
    if args.delete_old_zone:
        if not args.old_env_file or not args.old_zone_id:
            raise EdgeOneError("--delete-old-zone requires --old-env-file and --old-zone-id.")
        old_client = client_from_env_file(args.old_env_file, args)

        if args.disable_old_before_delete:
            print(f"Step 5.5/7 Disable old zone {args.old_zone_id}", file=sys.stderr)
            try:
                old_disable_response = old_client.call(
                    "ModifyZoneStatus",
                    {"ZoneId": args.old_zone_id, "Paused": args.old_paused_value},
                )
            except EdgeOneError as exc:
                message = str(exc)
                if "ResourceNotFound" not in message and "InvalidParameter" not in message:
                    raise
                old_disable_response = {
                    "Skipped": True,
                    "Reason": f"old zone disable skipped; continue to delete: {message}",
                    "ZoneId": args.old_zone_id,
                }
            with open(old_disable_response_json, "w", encoding="utf-8") as f:
                json.dump(old_disable_response, f, ensure_ascii=False, indent=2, sort_keys=True)
            if old_disable_response.get("Skipped"):
                print(f"Old zone disable skipped; continuing: {args.old_zone_id}")
            else:
                print(f"Disabled old zone request sent: {args.old_zone_id}")
            print(f"Wrote old disable response: {old_disable_response_json}")
            if not old_disable_response.get("Skipped") and args.after_disable_wait_seconds > 0:
                print(f"Waiting {args.after_disable_wait_seconds}s after old zone disable", file=sys.stderr)
                time.sleep(args.after_disable_wait_seconds)
        else:
            print("Step 5.5/7 Disable old zone skipped", file=sys.stderr)

        print(f"Step 5.6/7 Delete old zone {args.old_zone_id}", file=sys.stderr)
        old_delete_response = None
        for attempt in range(args.delete_old_retries + 1):
            try:
                old_delete_response = old_client.call("DeleteZone", {"ZoneId": args.old_zone_id})
                break
            except EdgeOneError as exc:
                message = str(exc)
                if "ResourceNotFound" in message:
                    old_delete_response = {
                        "Skipped": True,
                        "Reason": "old zone not found; treat as already deleted",
                        "ZoneId": args.old_zone_id,
                    }
                    break
                retryable = (
                    "OperationDenied.DisableZoneNotCompleted" in message
                    or "RequestLimitExceeded" in message
                )
                if not retryable or attempt >= args.delete_old_retries:
                    raise
                if args.disable_old_before_delete and "OperationDenied.DisableZoneNotCompleted" in message:
                    try:
                        old_client.call(
                            "ModifyZoneStatus",
                            {"ZoneId": args.old_zone_id, "Paused": args.old_paused_value},
                        )
                    except EdgeOneError:
                        pass
                wait_seconds = args.delete_old_retry_wait_seconds
                print(
                    f"DeleteZone not ready yet; retrying in {wait_seconds}s "
                    f"({attempt + 1}/{args.delete_old_retries})",
                    file=sys.stderr,
                )
                time.sleep(wait_seconds)
        if old_delete_response is None:
            raise EdgeOneError(f"DeleteZone did not return a response for {args.old_zone_id}")
        with open(old_delete_response_json, "w", encoding="utf-8") as f:
            json.dump(old_delete_response, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"Deleted old zone: {args.old_zone_id}")
        print(f"Wrote old delete response: {old_delete_response_json}")
        if args.after_delete_wait_seconds > 0:
            print(f"Waiting {args.after_delete_wait_seconds}s after old zone delete", file=sys.stderr)
            time.sleep(args.after_delete_wait_seconds)
    else:
        print("Step 5.5/7 Delete old zone skipped", file=sys.stderr)

    print("Step 6/7 CreateAccelerationDomain with SharedCNAME", file=sys.stderr)
    if args.template_zone_name:
        domain_payloads = template_acceleration_domains(args.origins_csv, args.template_zone_name, args.zone_name, args)
    else:
        domains = split_domain_names(args.domain_names)
        if not args.origin:
            raise EdgeOneError("--origin is required when --template-zone-name is not provided.")
        domain_payloads = []
        for domain in domains:
            origin_info = {
                "OriginType": args.origin_type,
                "Origin": args.origin,
            }
            if args.host_header:
                origin_info["HostHeader"] = args.host_header
            domain_payloads.append(
                {
                    "DomainName": domain,
                    "OriginInfo": origin_info,
                    **acceleration_domain_origin_ports(args),
                    "IPv6Status": "follow",
                }
            )
    if not domain_payloads:
        raise EdgeOneError("No acceleration domains to create.")
    if args.only_domain:
        only_domains = {item.strip() for item in args.only_domain.split(",") if item.strip()}
        domain_payloads = [item for item in domain_payloads if item["DomainName"] in only_domains]
    if not domain_payloads:
        raise EdgeOneError("No acceleration domains to create.")
    certificate_hosts = [item["DomainName"] for item in domain_payloads]
    if args.skip_existing_domains:
        existing_domain_names = list_acceleration_domain_names(client, zone_id, args.limit)
        if existing_domain_names:
            print(
                f"Existing acceleration domains in new zone: {', '.join(sorted(existing_domain_names))}",
                file=sys.stderr,
            )
            domain_payloads = [item for item in domain_payloads if item["DomainName"] not in existing_domain_names]
    if not domain_payloads:
        print("No missing acceleration domains to create.", file=sys.stderr)
        create_domain_results = []
        with open(create_domains_response_json, "w", encoding="utf-8") as f:
            json.dump({"results": create_domain_results}, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"Wrote create acceleration domains response: {create_domains_response_json}")
    else:
        create_domain_results = []
        create_domain_failures = 0
        for item in domain_payloads:
            payload = {
                "ZoneId": zone_id,
                **item,
                "SharedCNAME": args.shared_cname,
            }
            created = False
            last_error = ""
            for attempt in range(args.create_domain_retries + 1):
                try:
                    response = client.call("CreateAccelerationDomain", payload)
                    create_domain_results.append({"domain": payload["DomainName"], "payload": payload, "response": response})
                    print(f"Created acceleration domain: {payload['DomainName']}")
                    created = True
                    break
                except Exception as exc:
                    last_error = str(exc)
                    retryable = is_create_acceleration_domain_retryable(last_error) or (
                        "ResourceUnavailable.DomainAlreadyExists" in last_error
                    )
                    if not retryable or attempt >= args.create_domain_retries:
                        break
                    wait_seconds = args.create_domain_retry_wait_seconds
                    print(
                        f"CreateAccelerationDomain not ready for {payload['DomainName']}; "
                        f"retrying in {wait_seconds}s ({attempt + 1}/{args.create_domain_retries})",
                        file=sys.stderr,
                    )
                    time.sleep(wait_seconds)
            if not created:
                if "ResourceUnavailable.DomainAlreadyExists" in last_error:
                    existing_after_error = list_acceleration_domain_names(client, zone_id, args.limit)
                    if payload["DomainName"] in existing_after_error:
                        create_domain_results.append(
                            {
                                "domain": payload["DomainName"],
                                "payload": payload,
                                "status": "already_exists_in_new_zone",
                                "error": last_error,
                            }
                        )
                        print(f"Acceleration domain already exists in new zone: {payload['DomainName']}")
                        continue
                create_domain_failures += 1
                create_domain_results.append({"domain": payload["DomainName"], "payload": payload, "error": last_error})
                print(f"FAILED CreateAccelerationDomain {payload['DomainName']}: {last_error}", file=sys.stderr)
        with open(create_domains_response_json, "w", encoding="utf-8") as f:
            json.dump({"results": create_domain_results}, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"Wrote create acceleration domains response: {create_domains_response_json}")
        if create_domain_failures:
            return 3

    if args.enable_origin_acl:
        print("Step 6.5/7 EnableOriginACL", file=sys.stderr)
        origin_acl_issues = []
        try:
            action, payload, origin_acl_response = enable_origin_acl_for_l7_hosts(
                client,
                zone_id,
                certificate_hosts,
                args.origin_acl_family,
            )
            with open(origin_acl_response_json, "w", encoding="utf-8") as f:
                json.dump(
                    {"action": action, "payload": payload, "response": origin_acl_response},
                    f,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            print(f"Configured origin protection for {len(certificate_hosts)} host(s): {action}")
            print(f"Wrote origin protection response: {origin_acl_response_json}")
        except Exception as exc:
            origin_acl_issues.append(
                {
                    "zone_id": zone_id,
                    "zone_name": args.zone_name,
                    "hosts": ";".join(certificate_hosts),
                    "status": "failed",
                    "error": str(exc),
                }
            )
            print(f"Origin protection failed for {args.zone_name}: {exc}", file=sys.stderr)
            if args.origin_acl_strict:
                write_rows_csv(
                    origin_acl_issues_csv,
                    origin_acl_issues,
                    ["zone_id", "zone_name", "hosts", "status", "error"],
                )
                return 4
        write_rows_csv(
            origin_acl_issues_csv,
            origin_acl_issues,
            ["zone_id", "zone_name", "hosts", "status", "error"],
        )
        print(f"Wrote origin protection issues:  {origin_acl_issues_csv}")
    else:
        print("Step 6.5/7 EnableOriginACL skipped; use --enable-origin-acl", file=sys.stderr)

    if args.cert_id or args.cert_mode == "eofreecert" or args.auto_cert:
        print("Step 7/7 ModifyHostsCertificate", file=sys.stderr)
        hosts = certificate_hosts
        certificate_results = []
        certificate_issues = []
        ssl_client = require_ssl_client(args) if args.auto_cert and not args.cert_id and args.cert_mode == "sslcert" else None
        for host in hosts:
            cert_id = args.cert_id
            cert_match: dict[str, Any] | None = None
            if not cert_id and args.auto_cert and args.cert_mode == "sslcert":
                try:
                    cert_id, cert_match = find_default_certificate_for_host(client, zone_id, host)
                except Exception as exc:
                    certificate_issues.append({"host": host, "status": "eo_lookup_failed", "cert_id": "", "error": str(exc)})
                    print(f"EdgeOne certificate lookup failed for {host}: {exc}", file=sys.stderr)
                if not cert_id and ssl_client:
                    try:
                        cert_id, cert_match = find_certificate_for_host(ssl_client, host)
                    except Exception as exc:
                        certificate_issues.append({"host": host, "status": "ssl_lookup_failed", "cert_id": "", "error": str(exc)})
                        print(f"SSL certificate lookup failed for {host}: {exc}", file=sys.stderr)
                        continue
            if args.cert_mode == "sslcert" and not cert_id:
                certificate_issues.append({"host": host, "status": "missing", "cert_id": "", "error": "No matching certificate found"})
                print(f"No matching certificate found for {host}; skipping HTTPS certificate.", file=sys.stderr)
                continue

            certificate_payload = {
                "ZoneId": zone_id,
                "Hosts": [host],
                "Mode": args.cert_mode,
            }
            if cert_id:
                certificate_payload["ServerCertInfo"] = [{"CertId": cert_id}]
            try:
                certificate_response = client.call("ModifyHostsCertificate", certificate_payload)
                certificate_results.append(
                    {
                        "host": host,
                        "cert_id": cert_id,
                        "match": cert_match,
                        "payload": certificate_payload,
                        "response": certificate_response,
                    }
                )
                print(f"Configured certificate for {host}: {cert_id or args.cert_mode}")
            except Exception as exc:
                certificate_issues.append({"host": host, "status": "bind_failed", "cert_id": cert_id, "error": str(exc)})
                print(f"Certificate bind failed for {host}: {exc}", file=sys.stderr)
        with open(certificate_response_json, "w", encoding="utf-8") as f:
            json.dump({"results": certificate_results}, f, ensure_ascii=False, indent=2, sort_keys=True)
        write_certificate_issues(certificate_issues_csv, certificate_issues)
        print(f"Wrote certificate response: {certificate_response_json}")
        print(f"Wrote certificate issues:   {certificate_issues_csv}")
    else:
        print("Step 7/7 ModifyHostsCertificate skipped; use --auto-cert or --cert-id", file=sys.stderr)
    print(f"Onboard completed: {args.zone_name} {zone_id}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export and batch-replace Tencent EdgeOne origin settings.")
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE, help=f"Local credential env file. Default: {DEFAULT_ENV_FILE}")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help=f"API endpoint. Default: {DEFAULT_ENDPOINT}")
    parser.add_argument("--retries", type=int, default=6)
    parser.add_argument("--sleep", type=float, default=0.15, help="Sleep between API calls to avoid rate limits.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Pagination limit. Tencent currently caps many APIs at 100.")

    sub = parser.add_subparsers(dest="command", required=True)

    def add_origin_protocol_args(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--origin-protocol",
            default="FOLLOW",
            choices=["FOLLOW", "HTTP", "HTTPS"],
            help="Origin protocol. Default: FOLLOW. Use HTTP for origins that only listen on port 80.",
        )
        command.add_argument("--http-origin-port", type=int, default=80, help="HTTP origin port. Default: 80")
        command.add_argument("--https-origin-port", type=int, default=443, help="HTTPS origin port. Default: 443")

    export = sub.add_parser("export", help="Export EdgeOne origin settings.")
    export.add_argument("--json", default="eo-origins.json")
    export.add_argument("--csv", default="eo-origins.csv")
    export.add_argument(
        "--scope",
        default="acceleration_domain",
        help="Comma-separated scopes: acceleration_domain,origin_group,l7_rule,all. Default: acceleration_domain",
    )
    export.add_argument("--workers", type=int, default=8, help="Concurrent zone exports. Default: 8")
    export.add_argument(
        "--no-checkpoint",
        action="store_false",
        dest="checkpoint",
        help="Only write output files after the full export completes.",
    )
    export.set_defaults(checkpoint=True)
    export.set_defaults(func=cmd_export)

    zone_config = sub.add_parser(
        "export-zone-config",
        help="Export official EdgeOne site config files via ExportZoneConfig.",
    )
    zone_config.add_argument(
        "--types",
        default="L7AccelerationConfig",
        help=(
            "Comma-separated config types. Default: L7AccelerationConfig. "
            "Supported: L7AccelerationConfig,AccelerationDomain,Origin,WebSecurity,all"
        ),
    )
    zone_config.add_argument("--output-dir", default="eo-zone-configs")
    zone_config.add_argument("--summary-csv", default="eo-zone-configs.csv")
    zone_config.add_argument("--workers", type=int, default=6, help="Concurrent zone exports. Default: 6")
    zone_config.add_argument("--zone-id", help="Export only one zone id for testing.")
    zone_config.add_argument("--zone-name", help="Optional display name when --zone-id is used.")
    zone_config.set_defaults(func=cmd_export_zone_config)

    batches = sub.add_parser(
        "make-migration-batches",
        help="Create migration batch CSV files grouped by primary origin.",
    )
    batches.add_argument("--origins-csv", default="eo-origins.csv")
    batches.add_argument("--config-summary", default="eo-zone-configs.csv")
    batches.add_argument("--output-dir", default="eo-migration-batches")
    batches.add_argument("--max-size", type=int, default=30, help="Max zones per batch. Default: 30")
    batches.add_argument(
        "--exclude",
        default="",
        help="Comma-separated patterns. Zones matching zone name, origin, or domain are excluded.",
    )
    batches.set_defaults(func=cmd_make_migration_batches)

    list_web_sec = sub.add_parser(
        "list-web-security-templates",
        help="List Web security policy templates and their owning ZoneIds.",
    )
    list_web_sec.add_argument("--zone-ids", default="", help="Optional comma-separated ZoneIds. Default: scan all zones.")
    list_web_sec.add_argument("--output-json", default="web-security-templates-list.json")
    list_web_sec.add_argument("--output-csv", default="web-security-templates-list.csv")
    list_web_sec.set_defaults(func=cmd_list_web_security_templates)

    audit_protected = sub.add_parser(
        "audit-protected-zones",
        help="Find old zones that should be kept for last handling, such as shared CNAME or Web security template owners.",
    )
    audit_protected.add_argument("--output-dir", default="protected-zones")
    audit_protected.add_argument(
        "--completed-status-csvs",
        default="",
        help="Optional comma-separated batch-status CSVs. Successful old zones are also excluded from future batches.",
    )
    audit_protected.add_argument("--source-all-zones-csv", help="Optional all-zones CSV used to generate safe batches.")
    audit_protected.add_argument("--safe-batch-dir", help="Optional output directory for batches excluding protected zones.")
    audit_protected.add_argument("--max-size", type=int, default=15)
    audit_protected.set_defaults(func=cmd_audit_protected_zones)

    export_web_sec = sub.add_parser(
        "export-web-security-templates",
        help="Export Web security policy templates from one zone.",
    )
    export_web_sec.add_argument("--zone-id", required=True)
    export_web_sec.add_argument("--names", default="", help="Optional comma-separated template names or IDs to export.")
    export_web_sec.add_argument("--output-json", default="web-security-templates-export.json")
    export_web_sec.add_argument("--summary-csv", default="web-security-templates-summary.csv")
    export_web_sec.set_defaults(func=cmd_export_web_security_templates)

    import_web_sec = sub.add_parser(
        "import-web-security-templates",
        help="Create Web security policy templates in a target zone from an export JSON.",
    )
    import_web_sec.add_argument("--input-json", required=True)
    import_web_sec.add_argument("--target-zone-id", required=True)
    import_web_sec.add_argument("--overwrite", action="store_true", help="Delete same-name target templates before creating.")
    import_web_sec.add_argument(
        "--raw-security-policy",
        action="store_true",
        help="Send SecurityPolicy exactly as exported instead of stripping output-only fields.",
    )
    import_web_sec.add_argument("--response-json", default="web-security-templates-import.json")
    import_web_sec.add_argument("--summary-csv", default="web-security-templates-summary.csv")
    import_web_sec.add_argument("--apply", action="store_true", help="Actually create templates.")
    import_web_sec.add_argument("--yes", action="store_true", help="Required with --apply.")
    import_web_sec.set_defaults(func=cmd_import_web_security_templates)

    migrate_web_sec = sub.add_parser(
        "migrate-web-security-templates",
        help="Export Web security templates from the old account and create them in the new account.",
    )
    migrate_web_sec.add_argument("--old-env-file", required=True)
    migrate_web_sec.add_argument("--old-zone-id", required=True)
    migrate_web_sec.add_argument("--new-zone-id", required=True)
    migrate_web_sec.add_argument("--zone-name", help="Only used in output file names.")
    migrate_web_sec.add_argument("--names", default="", help="Optional comma-separated template names or IDs to migrate.")
    migrate_web_sec.add_argument("--overwrite", action="store_true", help="Delete same-name target templates before creating.")
    migrate_web_sec.add_argument(
        "--raw-security-policy",
        action="store_true",
        help="Send SecurityPolicy exactly as exported instead of stripping output-only fields.",
    )
    migrate_web_sec.add_argument("--output-dir", default="web-security-template-results")
    migrate_web_sec.add_argument("--apply", action="store_true", help="Actually create templates.")
    migrate_web_sec.add_argument("--yes", action="store_true", help="Required with --apply.")
    migrate_web_sec.set_defaults(func=cmd_migrate_web_security_templates)

    migrate_batch = sub.add_parser(
        "migrate-batch",
        help="Migrate zones from one batch CSV, continuing after per-zone failures.",
    )
    migrate_batch.add_argument("--batch-csv", required=True)
    migrate_batch.add_argument("--type", default="partial", choices=["partial", "full", "dnsPodAccess", "noDomainAccess"])
    migrate_batch.add_argument("--area", default="overseas", choices=["global", "mainland", "overseas", ""])
    migrate_batch.add_argument("--plan-id", required=True)
    migrate_batch.add_argument("--dns-env-file", default="dns-providers.env")
    migrate_batch.add_argument("--dns-provider", default="auto", choices=["auto", "alidns", "dnspod"])
    migrate_batch.add_argument("--dns-ttl", type=int, default=600)
    migrate_batch.add_argument(
        "--dns-domain-cache-json",
        help="Default: OUTPUT_DIR/dns-domain-cache.json. Reuse DNS provider domain list for the whole batch.",
    )
    migrate_batch.add_argument("--skip-dns", action="store_true", help="Skip adding ownership TXT.")
    migrate_batch.add_argument("--verify-wait-seconds", type=int, default=10)
    migrate_batch.add_argument("--delete-old-zone", action="store_true", help="Delete old account zones before creating acceleration domains.")
    migrate_batch.add_argument("--old-env-file", help="Old account credential env file. Required with --delete-old-zone.")
    migrate_batch.add_argument("--disable-old-before-delete", action="store_true", default=True)
    migrate_batch.add_argument("--no-disable-old-before-delete", action="store_false", dest="disable_old_before_delete")
    migrate_batch.add_argument("--old-paused-value", action=argparse.BooleanOptionalAction, default=True)
    migrate_batch.add_argument("--after-disable-wait-seconds", type=int, default=30)
    migrate_batch.add_argument("--delete-old-retries", type=int, default=20)
    migrate_batch.add_argument("--delete-old-retry-wait-seconds", type=int, default=30)
    migrate_batch.add_argument("--after-delete-wait-seconds", type=int, default=5)
    migrate_batch.add_argument("--import-config-retries", type=int, default=20)
    migrate_batch.add_argument("--import-config-retry-wait-seconds", type=int, default=10)
    migrate_batch.add_argument("--shared-cname", required=True)
    migrate_batch.add_argument("--create-domain-retries", type=int, default=30)
    migrate_batch.add_argument("--create-domain-retry-wait-seconds", type=int, default=20)
    migrate_batch.add_argument("--origins-csv", default="eo-origins.csv")
    migrate_batch.add_argument("--origin-type", default="IP_DOMAIN")
    add_origin_protocol_args(migrate_batch)
    migrate_batch.add_argument("--host-header", help="Optional custom origin HostHeader. Omit to use acceleration domain.")
    migrate_batch.add_argument("--enable-origin-acl", action="store_true", help="Enable origin protection for created L7 hosts.")
    migrate_batch.add_argument("--origin-acl-family", default="", choices=["", "IPv4", "IPv6", "all"])
    migrate_batch.add_argument("--origin-acl-strict", action="store_true", help="Mark zone failed if origin protection cannot be enabled.")
    migrate_batch.add_argument("--cert-id")
    migrate_batch.add_argument("--auto-cert", action="store_true")
    migrate_batch.add_argument("--cert-mode", default="sslcert", choices=["sslcert", "eofreecert", "disable"])
    migrate_batch.add_argument("--output-dir", default="batch-results")
    migrate_batch.add_argument("--status-csv", help="Default: OUTPUT_DIR/batch-status.csv")
    migrate_batch.add_argument("--resume", action="store_true", default=True, help="Skip zones already marked success in status CSV.")
    migrate_batch.add_argument("--no-resume", action="store_false", dest="resume")
    migrate_batch.add_argument("--stop-on-error", action="store_true")
    migrate_batch.add_argument("--apply", action="store_true", help="Actually run the batch.")
    migrate_batch.add_argument("--yes", action="store_true", help="Required with --apply.")
    migrate_batch.set_defaults(func=cmd_migrate_batch)

    create_zone = sub.add_parser("create-zone", help="Create one EdgeOne zone for testing.")
    create_zone.add_argument("--zone-name", required=True)
    create_zone.add_argument("--type", default="partial", choices=["partial", "full", "dnsPodAccess", "noDomainAccess"])
    create_zone.add_argument("--area", default="global", choices=["global", "mainland", "overseas", ""])
    create_zone.add_argument("--plan-id", help="Target EdgeOne plan/package id.")
    create_zone.add_argument("--alias-zone-name", help="Optional identical site identifier.")
    create_zone.add_argument("--response-json", default="create-zone-response.json")
    create_zone.add_argument("--ownership-csv", default="ownership.csv")
    create_zone.add_argument("--apply", action="store_true", help="Actually call CreateZone.")
    create_zone.add_argument("--yes", action="store_true", help="Required with --apply.")
    create_zone.set_defaults(func=cmd_create_zone)

    verify_ownership = sub.add_parser("verify-ownership", help="Verify ownership for one EdgeOne zone.")
    verify_ownership.add_argument("--zone-id", help="Ignored by VerifyOwnership; kept for command compatibility.")
    verify_ownership.add_argument("--domain", required=True)
    verify_ownership.add_argument("--response-json", default="verify-ownership-response.json")
    verify_ownership.add_argument("--apply", action="store_true", help="Actually call VerifyOwnership.")
    verify_ownership.add_argument("--yes", action="store_true", help="Required with --apply.")
    verify_ownership.set_defaults(func=cmd_verify_ownership)

    import_config = sub.add_parser("import-zone-config", help="Import one exported EdgeOne zone config JSON.")
    import_config.add_argument("--zone-id", required=True)
    import_config.add_argument("--config-json", required=True)
    import_config.add_argument("--response-json", default="import-zone-config-response.json")
    import_config.add_argument("--apply", action="store_true", help="Actually call ImportZoneConfig.")
    import_config.add_argument("--yes", action="store_true", help="Required with --apply.")
    import_config.set_defaults(func=cmd_import_zone_config)

    bind_shared_cname = sub.add_parser("bind-shared-cname", help="Bind domains to a shared CNAME.")
    bind_shared_cname.add_argument("--zone-id", required=True)
    bind_shared_cname.add_argument("--shared-cname", required=True)
    bind_shared_cname.add_argument("--domain-names", required=True, help="Comma-separated domain names.")
    bind_shared_cname.add_argument("--bind-type", default="bind", choices=["bind", "unbind"])
    bind_shared_cname.add_argument("--response-json", default="bind-shared-cname-response.json")
    bind_shared_cname.add_argument("--apply", action="store_true", help="Actually call BindSharedCNAME.")
    bind_shared_cname.add_argument("--yes", action="store_true", help="Required with --apply.")
    bind_shared_cname.set_defaults(func=cmd_bind_shared_cname)

    onboard_zone = sub.add_parser(
        "onboard-zone",
        help="Create a zone, add DNS TXT, verify ownership, import config, and bind shared CNAME.",
    )
    onboard_zone.add_argument("--zone-name", required=True)
    onboard_zone.add_argument("--existing-zone-id", help="Continue workflow with an already-created zone.")
    onboard_zone.add_argument("--existing-ownership-csv", help="Ownership CSV from a previous CreateZone run.")
    onboard_zone.add_argument("--type", default="partial", choices=["partial", "full", "dnsPodAccess", "noDomainAccess"])
    onboard_zone.add_argument("--area", default="overseas", choices=["global", "mainland", "overseas", ""])
    onboard_zone.add_argument("--plan-id", required=True)
    onboard_zone.add_argument("--alias-zone-name")
    onboard_zone.add_argument("--dns-env-file", default="dns-providers.env")
    onboard_zone.add_argument("--dns-provider", default="auto", choices=["auto", "alidns", "dnspod"])
    onboard_zone.add_argument("--dns-ttl", type=int, default=600)
    onboard_zone.add_argument("--dns-domain-cache-json", help="Reuse or write DNS provider domain list cache.")
    onboard_zone.add_argument("--skip-dns", action="store_true", help="Skip adding ownership TXT.")
    onboard_zone.add_argument("--verify-wait-seconds", type=int, default=10)
    onboard_zone.add_argument("--delete-old-zone", action="store_true", help="Delete the old account zone before creating acceleration domains.")
    onboard_zone.add_argument("--old-env-file", help="Old account credential env file. Required with --delete-old-zone.")
    onboard_zone.add_argument("--old-zone-id", help="Old account ZoneId. Required with --delete-old-zone.")
    onboard_zone.add_argument("--disable-old-before-delete", action="store_true", default=True)
    onboard_zone.add_argument("--no-disable-old-before-delete", action="store_false", dest="disable_old_before_delete")
    onboard_zone.add_argument("--old-paused-value", action=argparse.BooleanOptionalAction, default=True)
    onboard_zone.add_argument("--after-disable-wait-seconds", type=int, default=30)
    onboard_zone.add_argument("--delete-old-retries", type=int, default=20)
    onboard_zone.add_argument("--delete-old-retry-wait-seconds", type=int, default=30)
    onboard_zone.add_argument("--after-delete-wait-seconds", type=int, default=5)
    onboard_zone.add_argument("--config-json", required=True)
    onboard_zone.add_argument("--skip-import-config", action="store_true", help="Skip ImportZoneConfig on reruns.")
    onboard_zone.add_argument("--import-config-retries", type=int, default=20)
    onboard_zone.add_argument("--import-config-retry-wait-seconds", type=int, default=10)
    onboard_zone.add_argument("--shared-cname", required=True)
    onboard_zone.add_argument("--domain-names", required=True, help="Comma-separated domain names for BindSharedCNAME.")
    onboard_zone.add_argument("--create-domain-retries", type=int, default=30)
    onboard_zone.add_argument("--create-domain-retry-wait-seconds", type=int, default=20)
    onboard_zone.add_argument("--skip-existing-domains", action="store_true", default=True)
    onboard_zone.add_argument("--no-skip-existing-domains", action="store_false", dest="skip_existing_domains")
    onboard_zone.add_argument("--only-domain", help="Only create these comma-separated acceleration domains.")
    onboard_zone.add_argument("--template-zone-name", help="Copy acceleration domain origin settings from this old zone name.")
    onboard_zone.add_argument("--origins-csv", default="eo-origins.csv")
    onboard_zone.add_argument("--origin", help="Origin value used when --template-zone-name is not provided.")
    onboard_zone.add_argument("--origin-type", default="IP_DOMAIN")
    add_origin_protocol_args(onboard_zone)
    onboard_zone.add_argument("--host-header", help="Optional custom origin HostHeader. Omit to use acceleration domain.")
    onboard_zone.add_argument("--enable-origin-acl", action="store_true", help="Enable origin protection for created L7 hosts.")
    onboard_zone.add_argument("--origin-acl-family", default="", choices=["", "IPv4", "IPv6", "all"])
    onboard_zone.add_argument("--origin-acl-strict", action="store_true", help="Fail the zone if origin protection cannot be enabled.")
    onboard_zone.add_argument("--cert-id", help="SSL certificate ID to deploy to created acceleration domains.")
    onboard_zone.add_argument("--auto-cert", action="store_true", help="Find uploaded SSL certificates by host automatically.")
    onboard_zone.add_argument("--cert-mode", default="sslcert", choices=["sslcert", "eofreecert", "disable"])
    onboard_zone.add_argument("--output-dir", default="onboard-results")
    onboard_zone.add_argument("--apply", action="store_true", help="Actually run the workflow.")
    onboard_zone.add_argument("--yes", action="store_true", help="Required with --apply.")
    onboard_zone.set_defaults(func=cmd_onboard_zone)

    create_acc_domain = sub.add_parser("create-acceleration-domains", help="Create acceleration domains from a template zone.")
    create_acc_domain.add_argument("--zone-id", required=True)
    create_acc_domain.add_argument("--zone-name", required=True)
    create_acc_domain.add_argument("--template-zone-name")
    create_acc_domain.add_argument("--origins-csv", default="eo-origins.csv")
    create_acc_domain.add_argument("--shared-cname")
    create_acc_domain.add_argument("--domain-names", default="")
    create_acc_domain.add_argument("--only-domain", help="Only create these comma-separated domains from the template.")
    create_acc_domain.add_argument("--origin")
    create_acc_domain.add_argument("--origin-type", default="IP_DOMAIN")
    add_origin_protocol_args(create_acc_domain)
    create_acc_domain.add_argument("--host-header", help="Optional custom origin HostHeader. Omit to use acceleration domain.")
    create_acc_domain.add_argument("--create-domain-retries", type=int, default=30)
    create_acc_domain.add_argument("--create-domain-retry-wait-seconds", type=int, default=20)
    create_acc_domain.add_argument("--response-json", default="create-acceleration-domains-response.json")
    create_acc_domain.add_argument("--apply", action="store_true", help="Actually call CreateAccelerationDomain.")
    create_acc_domain.add_argument("--yes", action="store_true", help="Required with --apply.")
    create_acc_domain.set_defaults(func=cmd_create_acceleration_domains)

    delete_acc_domain = sub.add_parser("delete-acceleration-domains", help="Delete acceleration domains from one zone.")
    delete_acc_domain.add_argument("--zone-id", required=True)
    delete_acc_domain.add_argument("--domain-names", required=True, help="Comma/semicolon-separated domain names.")
    delete_acc_domain.add_argument("--force", action="store_true", help="Force delete associated resources if Tencent allows it.")
    delete_acc_domain.add_argument("--response-json", default="delete-acceleration-domains-response.json")
    delete_acc_domain.add_argument("--apply", action="store_true", help="Actually call DeleteAccelerationDomains.")
    delete_acc_domain.add_argument("--yes", action="store_true", help="Required with --apply.")
    delete_acc_domain.set_defaults(func=cmd_delete_acceleration_domains)

    origin_acl = sub.add_parser("enable-origin-acl", help="Enable origin protection for L7 acceleration hosts.")
    origin_acl.add_argument("--zone-id", required=True)
    origin_acl.add_argument("--hosts", required=True, help="Comma/semicolon-separated L7 hosts.")
    origin_acl.add_argument("--origin-acl-family", default="", choices=["", "IPv4", "IPv6", "all"])
    origin_acl.add_argument("--response-json", default="enable-origin-acl-response.json")
    origin_acl.add_argument("--apply", action="store_true", help="Actually call EnableOriginACL/ModifyOriginACL.")
    origin_acl.add_argument("--yes", action="store_true", help="Required with --apply.")
    origin_acl.set_defaults(func=cmd_enable_origin_acl)

    cert = sub.add_parser("modify-hosts-certificate", help="Configure HTTPS certificate for acceleration hosts.")
    cert.add_argument("--zone-id", required=True)
    cert.add_argument("--hosts", required=True, help="Comma-separated hosts.")
    cert.add_argument("--mode", default="sslcert", choices=["sslcert", "eofreecert", "disable"])
    cert.add_argument("--cert-id", help="Required when --mode sslcert.")
    cert.add_argument("--auto-cert", action="store_true", help="Find uploaded SSL certificates by host automatically.")
    cert.add_argument("--response-json", default="modify-hosts-certificate-response.json")
    cert.add_argument("--issues-csv", default="certificate-issues.csv")
    cert.add_argument("--apply", action="store_true", help="Actually call ModifyHostsCertificate.")
    cert.add_argument("--yes", action="store_true", help="Required with --apply.")
    cert.set_defaults(func=cmd_modify_hosts_certificate)

    find_cert = sub.add_parser("find-certificate", help="Find an uploaded SSL certificate matching a host.")
    find_cert.add_argument("--host", required=True)
    find_cert.add_argument("--zone-id", help="Prefer EdgeOne certificates available in this zone before SSL global lookup.")
    find_cert.add_argument("--response-json", default="find-certificate-response.json")
    find_cert.set_defaults(func=cmd_find_certificate)

    replace = sub.add_parser("replace", help="Replace exact origin values from a CSV mapping. Defaults to dry-run.")
    replace.add_argument("--mapping", required=True, help="CSV with headers: old,new")
    replace.add_argument("--plan", default="eo-origin-change-plan.json")
    replace.add_argument(
        "--scope",
        default="all",
        help="Comma-separated scopes: acceleration_domain,origin_group,l7_rule,all. Default: all",
    )
    replace.add_argument("--workers", type=int, default=10, help="Concurrent zone exports before replacement. Default: 10")
    replace.add_argument("--apply", action="store_true", help="Actually call modify APIs.")
    replace.add_argument("--yes", action="store_true", help="Required with --apply.")
    replace.set_defaults(func=cmd_replace)

    fix_host = sub.add_parser(
        "fix-acceleration-domain-host-headers",
        help="Batch-fix acceleration domains to use the acceleration domain as origin HostHeader.",
    )
    fix_host.add_argument("--plan", default="eo-host-header-fix-plan.json")
    fix_host.add_argument(
        "--domain-names",
        default="",
        help="Optional comma/semicolon-separated acceleration domains to fix. Default: scan all.",
    )
    fix_host.add_argument(
        "--from-host-header",
        default="",
        help="Optional comma/semicolon-separated current HostHeader values to fix, such as old root domains.",
    )
    fix_host.add_argument("--scope", default="acceleration_domain", help=argparse.SUPPRESS)
    fix_host.add_argument("--workers", type=int, default=10, help="Concurrent zone exports before repair. Default: 10")
    add_origin_protocol_args(fix_host)
    fix_host.add_argument("--apply", action="store_true", help="Actually call ModifyAccelerationDomain.")
    fix_host.add_argument("--yes", action="store_true", help="Required with --apply.")
    fix_host.set_defaults(checkpoint=False)
    fix_host.set_defaults(func=cmd_fix_acceleration_domain_host_headers)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
