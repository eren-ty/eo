#!/usr/bin/env python3
"""
Add EdgeOne ownership TXT records to Alibaba Cloud DNS or Tencent DNSPod.

Default mode is dry-run. Use --apply --yes to create records.

CSV input fields, flexible names:
  zone_name, subdomain, record_value

Also accepted:
  domain / zone, host / rr / sub_domain / record_name, value / txt / txt_value

Environment file default:
  ./dns-providers.env
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any


DEFAULT_ENV_FILE = "dns-providers.env"
DEFAULT_CONFIG_FILE = "dns-providers.yaml"


class ApiError(RuntimeError):
    pass


def load_yaml_file(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        return load_limited_dns_yaml(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid YAML config: {path}")
    return data


def load_limited_dns_yaml(path: str) -> dict[str, Any]:
    """Parse the small dns_providers.dnspod.accounts YAML shape without PyYAML."""
    config: dict[str, Any] = {"dns_providers": {"dnspod": {"accounts": {}}}}
    dnspod = config["dns_providers"]["dnspod"]
    accounts = dnspod["accounts"]
    in_ns = False
    in_accounts = False
    current_account: dict[str, Any] | None = None
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            line = raw_line.strip()
            if "#" in line:
                line = line.split("#", 1)[0].rstrip()
            if not line:
                continue

            if indent == 4 and line.startswith("request_interval:"):
                dnspod["request_interval"] = clean_yaml_scalar(line.split(":", 1)[1])
                continue
            if indent == 4 and line.startswith("retry_delay:"):
                dnspod["retry_delay"] = clean_yaml_scalar(line.split(":", 1)[1])
                continue
            if indent == 4 and line == "NS:":
                dnspod["NS"] = []
                in_ns = True
                in_accounts = False
                continue
            if in_ns and indent >= 6 and line.startswith("- "):
                dnspod.setdefault("NS", []).append(clean_yaml_scalar(line[2:]))
                continue
            if indent == 4 and line == "accounts:":
                in_ns = False
                in_accounts = True
                continue
            if in_accounts and indent == 6 and line.endswith(":"):
                account_name = line[:-1].strip()
                current_account = {}
                accounts[account_name] = current_account
                continue
            if in_accounts and current_account is not None and indent >= 8 and ":" in line:
                key, value = line.split(":", 1)
                current_account[key.strip()] = clean_yaml_scalar(value)
                continue
    return config


def clean_yaml_scalar(value: str) -> str:
    return value.strip().strip('"').strip("'")


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


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


class TencentCloudClient:
    def __init__(
        self,
        secret_id: str,
        secret_key: str,
        service: str,
        version: str,
        endpoint: str,
        token: str | None = None,
        retries: int = 3,
        sleep_seconds: float = 0.15,
    ) -> None:
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.service = service
        self.version = version
        self.endpoint = endpoint
        self.token = token
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
                time.sleep(min(2**attempt, 8) + random.uniform(0.1, 0.4))
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                response = data.get("Response", {})
                if "Error" in response:
                    err = response["Error"]
                    raise ApiError(f"{action} failed: {err.get('Code')}: {err.get('Message')}")
                if self.sleep_seconds:
                    time.sleep(self.sleep_seconds)
                return response
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                TimeoutError,
                http.client.IncompleteRead,
                http.client.RemoteDisconnected,
                OSError,
                ApiError,
            ) as exc:
                last_error = exc
                if isinstance(exc, ApiError):
                    raise
        raise ApiError(f"{action} failed after retries: {last_error}")

    def _headers(self, action: str, body: bytes) -> dict[str, str]:
        timestamp = int(time.time())
        date = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%d")
        canonical_headers = (
            f"content-type:application/json; charset=utf-8\n"
            f"host:{self.endpoint}\n"
            f"x-tc-action:{action.lower()}\n"
        )
        signed_headers = "content-type;host;x-tc-action"
        hashed_payload = hashlib.sha256(body).hexdigest()
        canonical_request = "\n".join(["POST", "/", "", canonical_headers, signed_headers, hashed_payload])
        algorithm = "TC3-HMAC-SHA256"
        credential_scope = f"{date}/{self.service}/tc3_request"
        hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join([algorithm, str(timestamp), credential_scope, hashed_canonical_request])
        secret_date = hmac_sha256(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = hmac_sha256(secret_date, self.service)
        secret_signing = hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "Authorization": (
                f"{algorithm} Credential={self.secret_id}/{credential_scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "Content-Type": "application/json; charset=utf-8",
            "Host": self.endpoint,
            "X-TC-Action": action,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": self.version,
        }
        if self.token:
            headers["X-TC-Token"] = self.token
        return headers


class AliDnsClient:
    def __init__(
        self,
        access_key_id: str,
        access_key_secret: str,
        endpoint: str = "alidns.aliyuncs.com",
        retries: int = 3,
    ) -> None:
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.endpoint = endpoint
        self.retries = retries

    def call(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(min(2**attempt, 8) + random.uniform(0.1, 0.4))
            full_params: dict[str, Any] = {
                "Action": action,
                "Version": "2015-01-09",
                "Format": "JSON",
                "AccessKeyId": self.access_key_id,
                "SignatureMethod": "HMAC-SHA1",
                "SignatureVersion": "1.0",
                "SignatureNonce": str(uuid.uuid4()),
                "Timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            full_params.update({k: v for k, v in params.items() if v is not None and v != ""})
            query = self._signed_query(full_params)
            url = f"https://{self.endpoint}/?{query}"
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if "SignatureNonceUsed" in body and attempt < self.retries:
                    last_error = exc
                    continue
                raise ApiError(f"AliDNS {action} failed: HTTP {exc.code}: {body}") from exc
            except (urllib.error.URLError, TimeoutError, http.client.IncompleteRead, OSError) as exc:
                last_error = exc
                continue
        raise ApiError(f"AliDNS {action} failed after retries: {last_error}")

    def _signed_query(self, params: dict[str, Any]) -> str:
        canonical = "&".join(f"{percent_encode(k)}={percent_encode(str(params[k]))}" for k in sorted(params))
        string_to_sign = "GET&%2F&" + percent_encode(canonical)
        digest = hmac.new(
            (self.access_key_secret + "&").encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
        signature = base64.b64encode(digest).decode("utf-8")
        signed = dict(params)
        signed["Signature"] = signature
        return urllib.parse.urlencode(signed)


class DNSPodLegacyClient:
    def __init__(
        self,
        login_token_id: str,
        login_token: str,
        endpoint: str = "https://dnsapi.cn/",
        retries: int = 3,
        sleep_seconds: float = 1.0,
    ) -> None:
        self.login_token = f"{login_token_id},{login_token}"
        self.endpoint = endpoint.rstrip("/") + "/"
        self.retries = retries
        self.sleep_seconds = sleep_seconds

    def call(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "login_token": self.login_token,
            "format": "json",
            **{k: v for k, v in params.items() if v is not None and v != ""},
        }
        body = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint + action,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "eo-migration-dns-tool/1.0",
            },
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(min(2**attempt, 8) + random.uniform(0.1, 0.4))
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                status = data.get("status") or {}
                code = str(status.get("code") or "")
                if code and code != "1":
                    if action == "Record.Create" and code == "104":
                        return data
                    raise ApiError(f"DNSPod legacy {action} failed: {code}: {status.get('message')}")
                if self.sleep_seconds:
                    time.sleep(self.sleep_seconds)
                return data
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, http.client.IncompleteRead, ApiError) as exc:
                last_error = exc
                if isinstance(exc, ApiError):
                    raise
        raise ApiError(f"DNSPod legacy {action} failed after retries: {last_error}")


def percent_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="~")


def make_dnspod_client(args: argparse.Namespace) -> TencentCloudClient | None:
    secret_id = os.environ.get("DNSPOD_SECRET_ID") or os.environ.get("TENCENT_DNSPOD_SECRET_ID")
    secret_key = os.environ.get("DNSPOD_SECRET_KEY") or os.environ.get("TENCENT_DNSPOD_SECRET_KEY")
    if not secret_id or not secret_key:
        return None
    return TencentCloudClient(
        secret_id=secret_id,
        secret_key=secret_key,
        token=os.environ.get("DNSPOD_TOKEN"),
        service="dnspod",
        version="2021-03-23",
        endpoint=args.dnspod_endpoint,
        retries=args.retries,
        sleep_seconds=args.sleep,
    )


def make_dnspod_legacy_clients(config: dict[str, Any], args: argparse.Namespace) -> dict[str, DNSPodLegacyClient]:
    clients: dict[str, DNSPodLegacyClient] = {}
    dnspod_config = ((config.get("dns_providers") or {}).get("dnspod") or {}) if config else {}
    accounts = dnspod_config.get("accounts") or {}
    if not isinstance(accounts, dict):
        return clients
    default_interval = float(dnspod_config.get("request_interval") or args.sleep or 1)
    for account_name, account in accounts.items():
        if not isinstance(account, dict):
            continue
        token_id = str(account.get("login_token_id") or "")
        token = str(account.get("login_token") or "")
        if not token_id or not token:
            continue
        endpoint = str(account.get("endpoint") or "https://dnsapi.cn/")
        key = f"dnspod_legacy:{account_name}"
        clients[key] = DNSPodLegacyClient(
            login_token_id=token_id,
            login_token=token,
            endpoint=endpoint,
            retries=args.retries,
            sleep_seconds=default_interval,
        )
    return clients


def make_alidns_client(args: argparse.Namespace) -> AliDnsClient | None:
    access_key_id = os.environ.get("ALIYUN_ACCESS_KEY_ID") or os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
    access_key_secret = os.environ.get("ALIYUN_ACCESS_KEY_SECRET") or os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
    if not access_key_id or not access_key_secret:
        return None
    return AliDnsClient(access_key_id, access_key_secret, retries=args.retries)


def make_alidns_clients(args: argparse.Namespace) -> dict[str, AliDnsClient]:
    clients: dict[str, AliDnsClient] = {}
    default_client = make_alidns_client(args)
    if default_client:
        clients["alidns"] = default_client

    suffixes: set[str] = set()
    for key in os.environ:
        for prefix in ("ALIYUN_ACCESS_KEY_ID_", "ALIBABA_CLOUD_ACCESS_KEY_ID_"):
            if key.startswith(prefix):
                suffix = key[len(prefix) :].strip()
                if suffix:
                    suffixes.add(suffix)
    for suffix in sorted(suffixes):
        access_key_id = (
            os.environ.get(f"ALIYUN_ACCESS_KEY_ID_{suffix}")
            or os.environ.get(f"ALIBABA_CLOUD_ACCESS_KEY_ID_{suffix}")
        )
        access_key_secret = (
            os.environ.get(f"ALIYUN_ACCESS_KEY_SECRET_{suffix}")
            or os.environ.get(f"ALIBABA_CLOUD_ACCESS_KEY_SECRET_{suffix}")
        )
        if not access_key_id or not access_key_secret:
            continue
        endpoint = os.environ.get(f"ALIYUN_ALIDNS_ENDPOINT_{suffix}") or "alidns.aliyuncs.com"
        clients[f"alidns:{suffix.lower()}"] = AliDnsClient(
            access_key_id,
            access_key_secret,
            endpoint=endpoint,
            retries=args.retries,
        )
    return clients


def list_dnspod_domains(client: TencentCloudClient) -> set[str]:
    domains: set[str] = set()
    offset = 0
    limit = 100
    while True:
        resp = client.call("DescribeDomainList", {"Type": "ALL", "Offset": offset, "Limit": limit})
        items = resp.get("DomainList") or resp.get("Domains") or []
        if not isinstance(items, list) or not items:
            break
        for item in items:
            name = item.get("Name") or item.get("Domain") or item.get("DomainName") or item.get("Punycode")
            if name:
                domains.add(str(name).strip(".").lower())
        offset += len(items)
        total_info = resp.get("DomainCountInfo") or {}
        total = total_info.get("DomainTotal") or total_info.get("AllTotal") or resp.get("TotalCount")
        if total is not None and offset >= int(total):
            break
        if len(items) < limit:
            break
    return domains


def list_dnspod_legacy_domains(client: DNSPodLegacyClient) -> set[str]:
    domains: set[str] = set()
    offset = 0
    length = 100
    while True:
        resp = client.call("Domain.List", {"type": "all", "offset": offset, "length": length})
        items = resp.get("domains") or []
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("punycode") or item.get("domain") or item.get("name")
            if name:
                domains.add(str(name).strip(".").lower())
        offset += len(items)
        info = resp.get("info") or {}
        total = info.get("domain_total") or info.get("all_total")
        if total is not None and offset >= int(total):
            break
        if len(items) < length:
            break
    return domains


def list_alidns_domains(client: AliDnsClient) -> set[str]:
    domains: set[str] = set()
    page = 1
    page_size = 100
    while True:
        resp = client.call("DescribeDomains", {"PageNumber": page, "PageSize": page_size})
        container = resp.get("Domains") or {}
        items = container.get("Domain") if isinstance(container, dict) else container
        if not isinstance(items, list) or not items:
            break
        for item in items:
            name = item.get("DomainName") or item.get("PunyCode")
            if name:
                domains.add(str(name).strip(".").lower())
        total = int(resp.get("TotalCount") or 0)
        if page * page_size >= total:
            break
        page += 1
    return domains


def find_managed_domain(zone_name: str, provider_domains: dict[str, set[str]]) -> tuple[str, str] | tuple[None, None]:
    name = zone_name.strip(".").lower()
    matches: list[tuple[int, str, str]] = []
    for provider, domains in provider_domains.items():
        for domain in domains:
            if name == domain or name.endswith("." + domain):
                matches.append((len(domain), provider, domain))
    if not matches:
        return None, None
    _, provider, domain = sorted(matches, reverse=True)[0]
    return provider, domain


def build_provider_domains(
    args: argparse.Namespace,
) -> tuple[
    dict[str, set[str]],
    dict[str, DNSPodLegacyClient],
    TencentCloudClient | None,
    dict[str, AliDnsClient],
]:
    config = load_yaml_file(args.config_file)
    dnspod = None if args.no_dnspod else make_dnspod_client(args)
    dnspod_legacy_clients = {} if args.no_legacy_dnspod else make_dnspod_legacy_clients(config, args)
    alidns_clients = {} if args.no_alidns else make_alidns_clients(args)

    provider_domains: dict[str, set[str]] = {}
    if dnspod:
        provider_domains["dnspod"] = list_dnspod_domains(dnspod)
    for key, client in dnspod_legacy_clients.items():
        provider_domains[key] = list_dnspod_legacy_domains(client)
    for key, client in alidns_clients.items():
        provider_domains[key] = list_alidns_domains(client)
    return provider_domains, dnspod_legacy_clients, dnspod, alidns_clients


def read_domain_cache(path: str) -> dict[str, set[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    raw_providers = data.get("providers") if isinstance(data, dict) else data
    if not isinstance(raw_providers, dict):
        raise SystemExit(f"Invalid domain cache file: {path}")
    provider_domains: dict[str, set[str]] = {}
    for provider, domains in raw_providers.items():
        if isinstance(domains, list):
            provider_domains[str(provider)] = {str(domain).strip(".").lower() for domain in domains if domain}
    return provider_domains


def write_domain_cache(path: str, provider_domains: dict[str, set[str]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "providers": {
            provider: sorted(domains)
            for provider, domains in sorted(provider_domains.items())
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


def cmd_cache_domains(args: argparse.Namespace) -> int:
    load_env_file(args.env_file)
    provider_domains, _, _, _ = build_provider_domains(args)
    if not provider_domains:
        raise SystemExit(f"No DNS credentials found. Fill {args.env_file}.")
    write_domain_cache(args.out, provider_domains)
    print(
        "Loaded DNS domains: "
        + ", ".join(f"{provider}={len(domains)}" for provider, domains in provider_domains.items()),
        file=sys.stderr,
    )
    print(f"Wrote DNS domain cache: {args.out}")
    return 0


def record_rr(subdomain: str, zone_name: str, root_domain: str) -> str:
    subdomain = (subdomain or "").strip().strip(".")
    zone_name = zone_name.strip().strip(".")
    root_domain = root_domain.strip().strip(".")
    if not subdomain or subdomain == "@":
        fqdn = zone_name
    elif subdomain.endswith(root_domain):
        fqdn = subdomain
    else:
        fqdn = f"{subdomain}.{zone_name}"
    if fqdn == root_domain:
        return "@"
    suffix = "." + root_domain
    if fqdn.endswith(suffix):
        return fqdn[: -len(suffix)]
    return subdomain


def pick(record: dict[str, str], names: list[str]) -> str:
    lower = {k.lower(): v for k, v in record.items()}
    for name in names:
        value = lower.get(name.lower())
        if value:
            return value.strip()
    return ""


def read_txt_rows(path: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for line_no, record in enumerate(reader, start=2):
            zone_name = pick(record, ["zone_name", "domain", "zone"])
            subdomain = pick(record, ["subdomain", "sub_domain", "host", "rr", "record_name"])
            value = pick(record, ["record_value", "value", "txt", "txt_value"])
            if not zone_name or not subdomain or not value:
                print(f"Skipping line {line_no}: missing zone_name/subdomain/record_value", file=sys.stderr)
                continue
            rows.append({"zone_name": zone_name, "subdomain": subdomain, "record_value": value})
    if not rows:
        raise SystemExit("No usable TXT rows found.")
    return rows


def add_dnspod_txt(client: TencentCloudClient, domain: str, rr: str, value: str, ttl: int) -> str:
    payload = {
        "Domain": domain,
        "SubDomain": rr,
        "RecordType": "TXT",
        "RecordLine": "默认",
        "Value": value,
        "TTL": ttl,
        "Status": "ENABLE",
    }
    try:
        resp = client.call("CreateTXTRecord", payload)
    except ApiError:
        resp = client.call("CreateRecord", payload)
    return str(resp.get("RecordId") or "")


def add_dnspod_legacy_txt(client: DNSPodLegacyClient, domain: str, rr: str, value: str, ttl: int) -> str:
    resp = client.call(
        "Record.Create",
        {
            "domain": domain,
            "sub_domain": rr,
            "record_type": "TXT",
            "record_line": "默认",
            "value": value,
            "ttl": ttl,
        },
    )
    record = resp.get("record") or {}
    return str(record.get("id") or "")


def add_alidns_txt(client: AliDnsClient, domain: str, rr: str, value: str, ttl: int) -> str:
    resp = client.call(
        "AddDomainRecord",
        {
            "DomainName": domain,
            "RR": rr,
            "Type": "TXT",
            "Value": value,
            "TTL": ttl,
            "Line": "default",
        },
    )
    return str(resp.get("RecordId") or "")


def cmd_add_txt(args: argparse.Namespace) -> int:
    load_env_file(args.env_file)
    config = load_yaml_file(args.config_file)
    dnspod = None if args.no_dnspod else make_dnspod_client(args)
    dnspod_legacy_clients = {} if args.no_legacy_dnspod else make_dnspod_legacy_clients(config, args)
    alidns_clients = {} if args.no_alidns else make_alidns_clients(args)
    if args.domain_cache_json and os.path.exists(args.domain_cache_json):
        provider_domains = read_domain_cache(args.domain_cache_json)
    else:
        provider_domains: dict[str, set[str]] = {}
        if dnspod:
            provider_domains["dnspod"] = list_dnspod_domains(dnspod)
        for key, client in dnspod_legacy_clients.items():
            provider_domains[key] = list_dnspod_legacy_domains(client)
        for key, client in alidns_clients.items():
            provider_domains[key] = list_alidns_domains(client)
        if args.domain_cache_json:
            write_domain_cache(args.domain_cache_json, provider_domains)
    if not provider_domains:
        raise SystemExit(f"No DNS credentials found. Fill {args.env_file}.")

    print(
        "Loaded DNS domains: "
        + ", ".join(f"{provider}={len(domains)}" for provider, domains in provider_domains.items()),
        file=sys.stderr,
    )
    rows = read_txt_rows(args.csv)
    results: list[dict[str, str]] = []
    failures = 0
    for item in rows:
        provider, root_domain = find_managed_domain(item["zone_name"], provider_domains)
        result = {
            **item,
            "provider": provider or "",
            "root_domain": root_domain or "",
            "rr": "",
            "record_id": "",
            "status": "planned",
            "error": "",
        }
        if not provider or not root_domain:
            failures += 1
            result["status"] = "failed"
            result["error"] = "No matching domain found in AliDNS or DNSPod account"
            results.append(result)
            continue
        rr = record_rr(item["subdomain"], item["zone_name"], root_domain)
        result["rr"] = rr
        print(f"{provider} {root_domain} TXT {rr} = {item['record_value']}")
        if args.apply:
            if not args.yes:
                raise SystemExit("Refusing to apply without --yes.")
            try:
                if provider == "dnspod":
                    if not dnspod:
                        raise ApiError("DNSPod client is not configured")
                    result["record_id"] = add_dnspod_txt(dnspod, root_domain, rr, item["record_value"], args.ttl)
                elif provider and provider.startswith("dnspod_legacy:"):
                    client = dnspod_legacy_clients.get(provider)
                    if not client:
                        raise ApiError(f"DNSPod legacy client is not configured: {provider}")
                    result["record_id"] = add_dnspod_legacy_txt(
                        client,
                        root_domain,
                        rr,
                        item["record_value"],
                        args.ttl,
                    )
                elif provider and provider.startswith("alidns"):
                    client = alidns_clients.get(provider)
                    if not client:
                        raise ApiError(f"AliDNS client is not configured: {provider}")
                    result["record_id"] = add_alidns_txt(client, root_domain, rr, item["record_value"], args.ttl)
                result["status"] = "created"
            except Exception as exc:
                failures += 1
                result["status"] = "failed"
                result["error"] = str(exc)
        results.append(result)

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "zone_name",
                "subdomain",
                "record_value",
                "provider",
                "root_domain",
                "rr",
                "record_id",
                "status",
                "error",
            ],
        )
        writer.writeheader()
        writer.writerows(results)
    print(f"Wrote result CSV: {args.out}")
    if not args.apply:
        print("Dry-run only. Add --apply --yes to create TXT records.")
    return 2 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Add ownership TXT records to AliDNS or DNSPod.")
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--config-file", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("--dnspod-endpoint", default="dnspod.tencentcloudapi.com")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--sleep", type=float, default=0.15)
    sub = parser.add_subparsers(dest="command", required=True)

    add_txt = sub.add_parser("add-txt", help="Add TXT records from a verification CSV.")
    add_txt.add_argument("--csv", required=True, help="CSV with zone_name,subdomain,record_value.")
    add_txt.add_argument("--out", default="dns-txt-add-result.csv")
    add_txt.add_argument("--ttl", type=int, default=600)
    add_txt.add_argument("--no-dnspod", action="store_true", help="Skip Tencent DNSPod API 3.0.")
    add_txt.add_argument("--no-alidns", action="store_true", help="Skip Alibaba Cloud DNS.")
    add_txt.add_argument("--no-legacy-dnspod", action="store_true", help="Ignore DNSPod legacy token config.")
    add_txt.add_argument("--domain-cache-json", help="Reuse or write DNS provider domain list cache.")
    add_txt.add_argument("--apply", action="store_true")
    add_txt.add_argument("--yes", action="store_true")
    add_txt.set_defaults(func=cmd_add_txt)

    cache_domains = sub.add_parser("cache-domains", help="Cache managed domains from DNS providers.")
    cache_domains.add_argument("--out", required=True)
    cache_domains.add_argument("--no-dnspod", action="store_true", help="Skip Tencent DNSPod API 3.0.")
    cache_domains.add_argument("--no-alidns", action="store_true", help="Skip Alibaba Cloud DNS.")
    cache_domains.add_argument("--no-legacy-dnspod", action="store_true", help="Ignore DNSPod legacy token config.")
    cache_domains.set_defaults(func=cmd_cache_domains)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
