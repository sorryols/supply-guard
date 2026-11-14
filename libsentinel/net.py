"""HTTP-клієнти для PyPI, GitHub та OSV з кешуванням."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from .cache import Cache


class NetError(Exception):
    pass


class Http:
    def __init__(self, cfg: Dict[str, Any], cache: Cache):
        self.cfg = cfg
        self.cache = cache
        self.s = requests.Session()
        self.s.headers["User-Agent"] = cfg["network"]["user_agent"]
        self.timeout = cfg["network"]["timeout_seconds"]
        self.ttl = cfg["cache"]["http_ttl_hours"]

    def get_json(self, url: str, headers: Optional[dict] = None, use_cache: bool = True,
                 allow_404: bool = False) -> Optional[Any]:
        if use_cache:
            hit = self.cache.get_http(url, self.ttl)
            if hit is not None:
                return hit
        try:
            r = self.s.get(url, headers=headers or {}, timeout=self.timeout)
        except requests.RequestException as e:
            raise NetError(f"{url}: {e}") from e
        if r.status_code == 404 and allow_404:
            if use_cache:
                self.cache.put_http(url, {"__404__": True})
            return {"__404__": True}
        if r.status_code != 200:
            raise NetError(f"{url}: HTTP {r.status_code}")
        data = r.json()
        if use_cache:
            self.cache.put_http(url, data)
        return data

    def post_json(self, url: str, payload: dict) -> Any:
        try:
            r = self.s.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise NetError(f"{url}: {e}") from e
        if r.status_code != 200:
            raise NetError(f"{url}: HTTP {r.status_code}")
        return r.json()

    def download(self, url: str, dest) -> None:
        try:
            with self.s.get(url, stream=True, timeout=self.timeout) as r:
                if r.status_code != 200:
                    raise NetError(f"{url}: HTTP {r.status_code}")
                with open(dest, "wb") as f:
                    for chunk in r.iter_content(1 << 16):
                        f.write(chunk)
        except requests.RequestException as e:
            raise NetError(f"{url}: {e}") from e


class PyPI:
    BASE = "https://pypi.org"

    def __init__(self, http: Http):
        self.http = http

    def project(self, name: str) -> Dict[str, Any]:
        d = self.http.get_json(f"{self.BASE}/pypi/{quote(name)}/json", allow_404=True)
        if d.get("__404__"):
            raise NetError(f"Пакет {name} не знайдено в PyPI")
        return d

    def release(self, name: str, version: str) -> Dict[str, Any]:
        d = self.http.get_json(f"{self.BASE}/pypi/{quote(name)}/{quote(version)}/json", allow_404=True)
        if d.get("__404__"):
            raise NetError(f"Версію {name}=={version} не знайдено в PyPI")
        return d

    def exists(self, name: str) -> Optional[Dict[str, Any]]:
        d = self.http.get_json(f"{self.BASE}/pypi/{quote(name)}/json", allow_404=True)
        return None if d.get("__404__") else d

    def provenance(self, name: str, version: str, filename: str) -> Optional[Dict[str, Any]]:
        """Атестації PEP 740 через Integrity API."""
        url = f"{self.BASE}/integrity/{quote(name)}/{quote(version)}/{quote(filename)}/provenance"
        try:
            d = self.http.get_json(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"},
                                   allow_404=True)
        except NetError:
            return None
        return None if d.get("__404__") else d


class GitHub:
    API = "https://api.github.com"

    def __init__(self, http: Http):
        self.http = http
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str, allow_404: bool = True) -> Any:
        return self.http.get_json(f"{self.API}{path}", headers=self.headers, allow_404=allow_404)

    @staticmethod
    def parse_repo(url: Optional[str]) -> Optional[Tuple[str, str]]:
        if not url:
            return None
        m = re.search(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$", url.strip())
        if not m:
            return None
        owner, repo = m.group(1), m.group(2)
        if owner.lower() in {"sponsors", "orgs"}:
            return None
        return owner, repo


class OSV:
    URL = "https://api.osv.dev/v1/query"

    def __init__(self, http: Http):
        self.http = http

    def query(self, name: str, version: Optional[str]) -> List[Dict[str, Any]]:
        payload: Dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
        if version:
            payload["version"] = version
        key = f"osv::{name}::{version}"
        hit = self.http.cache.get_http(key, self.http.ttl)
        if hit is not None:
            return hit
        data = self.http.post_json(self.URL, payload)
        vulns = data.get("vulns", [])
        self.http.cache.put_http(key, vulns)
        return vulns
