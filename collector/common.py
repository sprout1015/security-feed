"""수집기 공통 도구: 경로, 시간, HTTP, 텍스트 변환, ID 추출, 감시 목록 대조."""
from __future__ import annotations

import datetime as dt
import gzip
import html
import json
import os
import re
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
STATE = ROOT / "state"
RUNS = ROOT / "runs"
INVENTORY = ROOT / "inventory"

KST = dt.timezone(dt.timedelta(hours=9))
USER_AGENT = "security-feed-collector/1.0 (+https://github.com/; scheduled security advisory mirror)"


def now_kst() -> dt.datetime:
    return dt.datetime.now(KST)


def today_kst() -> str:
    return os.environ.get("FEED_DATE") or now_kst().strftime("%Y-%m-%d")


def run_dir(date: str | None = None) -> Path:
    d = RUNS / (date or today_kst())
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")


class FetchError(Exception):
    pass


def http_get(url: str, *, headers: dict | None = None, timeout: int = 45, retries: int = 2) -> bytes:
    """GET 요청. 실패하면 FetchError(사유 포함)를 던진다."""
    hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if headers:
        hdrs.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return body
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in (401, 403, 404, 410):
                break
        except Exception as e:  # 네트워크 오류, 시간 초과 등
            last = f"{type(e).__name__}: {e}"
        time.sleep(2 * (attempt + 1))
    raise FetchError(last or "unknown error")


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer"}
    BLOCK = {"p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "table", "dt", "dd", "pre"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")
        elif tag in ("td", "th"):
            self.out.append(" | ")
        if tag == "a" and not self.skip:
            href = dict(attrs).get("href")
            if href and ("advisor" in href or "CVE-" in href or "GHSA-" in href or "security" in href):
                self.out.append(f" <{href}> ")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def to_text(raw: bytes, kind: str) -> str:
    """원문을 비교용 텍스트로 바꾼다. HTML은 본문만, JSON은 정렬된 들여쓰기, XML/RSS는 원문 그대로."""
    s = raw.decode("utf-8", errors="replace")
    if kind == "html":
        p = _TextExtractor()
        p.feed(s)
        s = "".join(p.out)
    elif kind in ("json", "github_advisories"):
        try:
            s = json.dumps(json.loads(s), ensure_ascii=False, indent=1, sort_keys=True)
        except json.JSONDecodeError:
            pass
    else:
        s = html.unescape(s)
        s = re.sub(r">\s*<", ">\n<", s)
    lines = [re.sub(r"[ \t ]+", " ", ln).strip() for ln in s.splitlines()]
    return "\n".join(ln for ln in lines if ln) + "\n"


_ID_PATTERNS = [
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I),
    re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b", re.I),
    re.compile(r"\bGO-\d{4}-\d{4}\b"),
]
# nginx XML처럼 cve="2026-123634" 로 접두어 없이 적는 경우와 "CVE-CVE-..." 오기를 함께 처리
_CVE_ATTR = re.compile(r'cve="(?:CVE-)*(\d{4}-\d{4,})"', re.I)


def extract_ids(text: str) -> list[str]:
    found = set()
    for pat in _ID_PATTERNS:
        for m in pat.findall(text):
            found.add(m.upper() if not m.upper().startswith("GHSA") else "GHSA" + m[4:].lower())
    for m in _CVE_ATTR.findall(text):
        found.add(f"CVE-{m}")
    return sorted(found)


# ---------- 감시 목록 대조 ----------

def load_watchlist() -> dict:
    return load_json(CONFIG / "watchlist.json", {"rules": {}, "products": []})


def _word_in(needle: str, hay: str) -> bool:
    return re.search(r"(?<![a-z0-9])" + re.escape(needle.lower()) + r"(?![a-z0-9])", hay.lower()) is not None


def match_watch(vendor: str | None, product: str | None, watch: dict) -> list[dict]:
    """vendor/product 문자열이 감시 목록 항목에 해당하면 그 항목들을 돌려준다."""
    vendor = (vendor or "").strip()
    product = (product or "").strip()
    if not product and not vendor:
        return []
    hits = []
    for item in watch.get("products", []):
        if not any(_word_in(p, product) for p in item.get("product", [])):
            continue
        vendors = item.get("vendor") or []
        if vendors and not any(v.lower() in vendor.lower() for v in vendors):
            continue
        hits.append(item)
    return hits
