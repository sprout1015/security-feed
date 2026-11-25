"""1층: 공식 소스 원문 수집.

각 소스를 내려받아 state/latest/ 에 원문과 비교용 텍스트를 저장하고,
어제 텍스트와 비교해 바뀐 줄(diff)과 처음 본 식별자(CVE/GHSA 등)를 기록한다.
원문은 가공하지 않고 그대로 저장한다. 해석은 루틴(AI)이 한다.
"""
from __future__ import annotations

import concurrent.futures as cf
import difflib
import re
import hashlib
import json
import os

from common import (CONFIG, STATE, FetchError, extract_ids, http_get, load_json,
                    now_kst, run_dir, save_json, to_text, today_kst)

LATEST = STATE / "latest"
SEEN_PATH = STATE / "seen_ids.json"
MAX_DIFF_LINES = 400
EXT = {"html": "html", "xml": "xml", "rss": "xml", "json": "json", "github_advisories": "json"}


# 내용 없는 변경 판별: 바뀐 줄이 전부 시각 표시이거나, 식별자·보안 낱말·버전 번호가 없는 문구(배너 등)면 "noise".
_TIMESTAMP = re.compile(r"(lastBuildDate|pubDate|updated_at|last_updated|lastModified|dateModified|generated_at|\"updated\"|^Date:|Last updated|최종 수정)", re.I)
_SIGNAL = re.compile(r"(CVE-\d{4}-\d+|GHSA-|RUSTSEC-|GO-\d{4}-|vulnerab|security|advisory|exploit|patch|fix|release|update|보안|취약|\b\d+\.\d+(\.\d+)?\b)", re.I)


def _is_noise(changed_lines: list[str]) -> bool:
    if not changed_lines:
        return True
    for ln in changed_lines:
        body = ln.strip()
        if not body or _TIMESTAMP.search(body):
            continue
        if _SIGNAL.search(body):
            return False
    return True


def _fetch(src: dict) -> bytes:
    if src["type"] == "github_advisories":
        url = f"https://api.github.com/repos/{src['repo']}/security-advisories?per_page=50&sort=published&direction=desc"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        raw = http_get(url, headers=headers)
        # 비교에 필요 없는 자주 바뀌는 필드를 빼고 저장
        items = json.loads(raw)
        keep = ("ghsa_id", "cve_id", "summary", "description", "severity", "cvss", "published_at",
                "updated_at", "withdrawn_at", "vulnerabilities", "html_url", "cwe_ids")
        trimmed = [{k: it.get(k) for k in keep} for it in items]
        return json.dumps(trimmed, ensure_ascii=False, indent=1).encode()
    url = src["url"].replace("{year}", today_kst()[:4])
    return http_get(url)


def collect() -> dict:
    date = today_kst()
    out_dir = run_dir(date)
    diff_dir = out_dir / "diffs"
    sources = load_json(CONFIG / "sources.json", {}).get("sources", [])
    seen = load_json(SEEN_PATH, {})
    LATEST.mkdir(parents=True, exist_ok=True)

    results = {}
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_fetch, s): s for s in sources}
        for fut in cf.as_completed(futs):
            src = futs[fut]
            try:
                results[src["id"]] = ("ok", fut.result())
            except FetchError as e:
                results[src["id"]] = ("error", str(e))
            except Exception as e:
                results[src["id"]] = ("error", f"{type(e).__name__}: {e}")

    report = []
    for src in sources:
        sid = src["id"]
        entry = {"id": sid, "name": src["name"], "products": src.get("products", ""), "url": src["url"]}
        state, payload = results[sid]
        if state == "error":
            entry.update(status="error", error=payload)
            report.append(entry)
            continue

        raw: bytes = payload
        ext = EXT.get(src["type"], "txt")
        text = to_text(raw, src["type"])
        prev_txt_path = LATEST / f"{sid}.txt"
        prev_text = prev_txt_path.read_text(encoding="utf-8") if prev_txt_path.exists() else None

        (LATEST / f"{sid}.{ext}").write_bytes(raw)
        prev_txt_path.write_text(text, encoding="utf-8")

        ids = extract_ids(text)
        src_seen = seen.setdefault(sid, {"_baseline": None, "ids": {}})
        new_ids = []
        if src_seen["_baseline"] is None:
            # 처음 수집한 날: 이미 있던 식별자는 '기존'으로 기록하고 새 항목으로 세지 않는다
            src_seen["_baseline"] = date
            for i in ids:
                src_seen["ids"].setdefault(i, f"{date} (baseline)")
        else:
            for i in ids:
                if i not in src_seen["ids"]:
                    src_seen["ids"][i] = date
                    new_ids.append(i)

        entry.update(sha256=hashlib.sha256(raw).hexdigest()[:16], bytes=len(raw),
                     text_path=f"state/latest/{sid}.txt", raw_path=f"state/latest/{sid}.{ext}",
                     id_count=len(ids), new_ids=new_ids)

        if prev_text is None:
            entry["status"] = "first"
        elif prev_text == text:
            entry["status"] = "unchanged"
        else:
            entry["status"] = "changed"
            diff = list(difflib.unified_diff(prev_text.splitlines(), text.splitlines(),
                                             fromfile="yesterday", tofile=date, lineterm="", n=2))
            added = [ln[1:] for ln in diff if ln.startswith("+") and not ln.startswith("+++")]
            removed = [ln for ln in diff if ln.startswith("-") and not ln.startswith("---")]
            entry.update(added_lines=len(added), removed_lines=len(removed))
            if _is_noise(added + [r[1:] for r in removed]) and not new_ids:
                entry["status"] = "noise"  # 시각·배너만 바뀜. diff는 남기되 '바뀐 소스'로 세지 않는다
            diff_dir.mkdir(parents=True, exist_ok=True)
            body = diff[:MAX_DIFF_LINES]
            if len(diff) > MAX_DIFF_LINES:
                body.append(f"... ({len(diff) - MAX_DIFF_LINES}줄 생략. 전체 텍스트: state/latest/{sid}.txt)")
            (diff_dir / f"{sid}.diff").write_text("\n".join(body) + "\n", encoding="utf-8")
            entry["diff_path"] = f"runs/{date}/diffs/{sid}.diff"
        report.append(entry)

    save_json(SEEN_PATH, seen)
    summary = {
        "date": date,
        "collected_at": now_kst().isoformat(timespec="seconds"),
        "total": len(sources),
        "ok": sum(1 for r in report if r["status"] != "error"),
        "changed": sum(1 for r in report if r["status"] == "changed"),
        "noise": sum(1 for r in report if r["status"] == "noise"),
        "error": sum(1 for r in report if r["status"] == "error"),
        "sources": report,
    }
    save_json(out_dir / "sources.json", summary)
    return summary


if __name__ == "__main__":
    s = collect()
    print(f"sources: ok={s['ok']} changed={s['changed']} error={s['error']}")
