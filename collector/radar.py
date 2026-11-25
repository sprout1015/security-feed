"""2층: 넓은 레이더.

① CISA KEV: 최근 N일 신규 등재를 제품과 상관없이 전부 기록하고, 모든 CVE를 조회할 수 있는 색인을 만든다.
② CVE.org 공식 목록: 지난 실행 이후 새로 공개된 CVE 중, 감시 목록 제품에 해당하면서
   CVSS가 기준 이상이거나 EPSS가 기준 이상이거나 KEV에 있는 것만 남긴다.
"""
from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import json

from common import (STATE, FetchError, http_get, load_json, load_watchlist, match_watch,
                    now_kst, run_dir, save_json, today_kst)

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CVE_DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CURSOR_PATH = STATE / "cve_cursor.json"
KEV_INDEX_PATH = STATE / "kev_index.json"


def kev_layer(watch: dict) -> dict:
    date = today_kst()
    window = int(watch.get("rules", {}).get("kev_window_days", 7))
    try:
        data = json.loads(http_get(KEV_URL, timeout=90))
    except FetchError as e:
        return {"status": "error", "error": str(e)}

    index = {}
    for v in data.get("vulnerabilities", []):
        index[v["cveID"]] = {
            "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
            "vendor": v.get("vendorProject"), "product": v.get("product"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
        }
    save_json(KEV_INDEX_PATH, {"catalogVersion": data.get("catalogVersion"),
                               "dateReleased": data.get("dateReleased"), "count": len(index), "cves": index})

    since = (dt.date.fromisoformat(date) - dt.timedelta(days=window)).isoformat()
    recent = []
    for v in data.get("vulnerabilities", []):
        if (v.get("dateAdded") or "") >= since:
            hits = match_watch(v.get("vendorProject"), v.get("product"), watch)
            recent.append({
                "cve": v["cveID"], "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
                "vendor": v.get("vendorProject"), "product": v.get("product"),
                "name": v.get("vulnerabilityName"), "ransomware": v.get("knownRansomwareCampaignUse"),
                "action": v.get("requiredAction"),
                "watch": [h["label"] for h in hits], "watch_group": sorted({h["group"] for h in hits}),
            })
    recent.sort(key=lambda x: x["dateAdded"], reverse=True)
    return {"status": "ok", "catalogVersion": data.get("catalogVersion"), "count": len(index),
            "window_days": window, "since": since, "recent": recent}


def _scores(cve: dict) -> dict:
    """CNA와 ADP(CISA 보강) 지표에서 가장 높은 CVSS 기본 점수를 고른다."""
    best = None
    containers = [cve.get("containers", {}).get("cna", {})] + cve.get("containers", {}).get("adp", [])
    for c in containers:
        for m in c.get("metrics", []) or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in m and isinstance(m[key], dict) and m[key].get("baseScore") is not None:
                    s = float(m[key]["baseScore"])
                    if best is None or s > best["score"]:
                        best = {"score": s, "version": key, "severity": m[key].get("baseSeverity")}
    return best or {}


def _affected_versions(cna: dict, limit: int = 6) -> list[str]:
    """CVE 레코드의 affected[] 를 '벤더/제품: 범위' 문자열로 요약 (루틴이 레코드를 다시 받지 않게)."""
    out = []
    for a in cna.get("affected", []) or []:
        name = f"{a.get('vendor') or ''}/{a.get('product') or a.get('packageName') or ''}".strip("/")
        parts = []
        for v in a.get("versions", []) or []:
            if v.get("status") not in (None, "affected"):
                continue
            ver = v.get("version") or ""
            if v.get("lessThan"):
                parts.append(f"{ver} ~ <{v['lessThan']}" if ver not in ("", "0", "*") else f"<{v['lessThan']}")
            elif v.get("lessThanOrEqual"):
                parts.append(f"{ver} ~ <={v['lessThanOrEqual']}" if ver not in ("", "0", "*") else f"<={v['lessThanOrEqual']}")
            elif ver:
                parts.append(ver)
        if a.get("defaultStatus") == "affected" and not parts:
            parts.append("전 버전(기본값 affected)")
        out.append(f"{name}: {', '.join(parts[:8]) or '범위 미기재'}")
        if len(out) >= limit:
            break
    return out


def _cve_record_url(cid: str) -> str:
    _, year, num = cid.split("-")
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{int(num) // 1000}xxx/{cid}.json"


def cve_details(ids: list[str], limit: int = 60) -> dict:
    """오늘 공식 소스 diff에서 처음 본 CVE의 공식 레코드 요약. 루틴 환경에서는 CVE·벤더 상세 페이지가 막혀 있어 미리 받아 둔다."""
    ids = sorted(set(ids))[:limit]

    def get(cid):
        try:
            rec = json.loads(http_get(_cve_record_url(cid), timeout=30, retries=1))
        except Exception as ex:
            return cid, {"error": str(ex)[:120]}
        cna = rec.get("containers", {}).get("cna", {})
        desc = next((d.get("value") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
        return cid, {"state": rec.get("cveMetadata", {}).get("state"), "title": cna.get("title"),
                     "cvss": _scores(rec), "affected_versions": _affected_versions(cna),
                     "description": (desc or "")[:300]}

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(get, ids))


def _epss(cves: list[str]) -> dict:
    out = {}
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        try:
            data = json.loads(http_get(EPSS_URL + ",".join(chunk), timeout=30, retries=1))
            for row in data.get("data", []):
                out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        except Exception:
            return {"_error": "EPSS API 접속 실패"} | out
    return out


def cve_layer(watch: dict, kev_index: dict) -> dict:
    rules = watch.get("rules", {})
    min_cvss = float(rules.get("cve_min_cvss", 9.0))
    min_epss = float(rules.get("cve_min_epss", 0.5))
    cursor = load_json(CURSOR_PATH, {}).get("last_fetch_time")
    if not cursor:
        cursor = (now_kst() - dt.timedelta(days=1)).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    try:
        delta = json.loads(http_get(CVE_DELTA_URL, timeout=90))
    except FetchError as e:
        return {"status": "error", "error": str(e)}

    new = {}
    latest_time = cursor
    for e in delta:
        t = e.get("fetchTime", "")
        if t <= cursor:
            continue
        latest_time = max(latest_time, t)
        for item in e.get("new", []):
            new[item["cveId"]] = item["githubLink"]

    def get(cid_link):
        cid, link = cid_link
        try:
            return cid, json.loads(http_get(link, timeout=30, retries=1))
        except Exception as ex:
            return cid, {"_error": str(ex)}

    records = {}
    with cf.ThreadPoolExecutor(max_workers=16) as pool:
        for cid, rec in pool.map(get, new.items()):
            records[cid] = rec

    fetch_errors = [c for c, r in records.items() if "_error" in r]
    candidates = []
    for cid, rec in records.items():
        if "_error" in rec or rec.get("cveMetadata", {}).get("state") != "PUBLISHED":
            continue
        cna = rec.get("containers", {}).get("cna", {})
        labels, groups, prods = set(), set(), []
        for a in cna.get("affected", []) or []:
            v, p = a.get("vendor"), a.get("product") or a.get("packageName")
            prods.append(f"{v} / {p}")
            for h in match_watch(v, p, watch):
                labels.add(h["label"])
                groups.add(h["group"])
        if not labels:
            continue
        desc = next((d.get("value") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
        candidates.append({
            "cve": cid, "published": rec.get("cveMetadata", {}).get("datePublished"),
            "assigner": rec.get("cveMetadata", {}).get("assignerShortName"),
            "affected": prods[:5], "affected_versions": _affected_versions(cna), "watch": sorted(labels), "watch_group": sorted(groups),
            "cvss": _scores(rec), "kev": cid in kev_index, "title": cna.get("title"),
            "description": (desc or "")[:500],
            "link": f"https://www.cve.org/CVERecord?id={cid}",
            "record_url": new.get(cid),
        })

    inv_min = float(rules.get("inventory_min_cvss", min_cvss))
    inv_unscored = bool(rules.get("inventory_include_unscored", True))
    epss = _epss([c["cve"] for c in candidates]) if candidates else {}
    hits, below = [], 0
    for c in candidates:
        c["epss"] = epss.get(c["cve"])
        score = (c["cvss"] or {}).get("score")
        is_inv = "inventory" in c["watch_group"]
        reasons = []
        if score is not None and score >= (inv_min if is_inv else min_cvss):
            reasons.append(f"CVSS {score}" + (" (인벤토리 제품)" if is_inv and score < min_cvss else ""))
        if score is None and is_inv and inv_unscored:
            reasons.append("인벤토리 제품, 점수 미공개")
        if c["epss"] and c["epss"]["epss"] >= min_epss:
            reasons.append(f"EPSS {c['epss']['epss']:.2f}")
        if c["kev"]:
            reasons.append("KEV 등재")
        if reasons:
            c["reasons"] = reasons
            hits.append(c)
        else:
            below += 1

    save_json(CURSOR_PATH, {"last_fetch_time": latest_time, "updated_at": now_kst().isoformat(timespec="seconds")})
    hits.sort(key=lambda x: (0 if "inventory" in x["watch_group"] else 1, -((x["cvss"] or {}).get("score") or 0)))
    return {
        "status": "ok", "since_utc": cursor, "until_utc": latest_time,
        "new_cves": len(new), "fetch_errors": len(fetch_errors),
        "watch_matched": len(candidates), "below_threshold": below,
        "thresholds": {"cvss": min_cvss, "inventory_cvss": inv_min, "inventory_unscored": inv_unscored, "epss": min_epss},
        "epss_status": "error" if epss.get("_error") else ("ok" if candidates else "skipped"),
        "hits": hits,
        "matched_below_threshold": [
            {"cve": c["cve"], "watch": c["watch"], "cvss": (c["cvss"] or {}).get("score"), "title": c["title"]}
            for c in candidates if c not in hits
        ],
    }


def run() -> dict:
    watch = load_watchlist()
    out = run_dir()
    kev = kev_layer(watch)
    save_json(out / "kev_recent.json", kev)
    kev_index = (load_json(KEV_INDEX_PATH, {}) or {}).get("cves", {})
    cve = cve_layer(watch, kev_index)
    save_json(out / "cve_radar.json", cve)
    # 공식 소스(벤더 공지)에서 오늘 처음 본 CVE의 공식 레코드 요약 → runs/D/cve_details.json
    src = load_json(out / "sources.json", {}) or {}
    new_ids = [i for s in src.get("sources", []) if s.get("status") in ("changed", "first")
               for i in s.get("new_ids", []) if i.startswith("CVE-")]
    radar_ids = {h["cve"] for h in cve.get("hits", [])}
    details = cve_details([i for i in new_ids if i not in radar_ids])
    save_json(out / "cve_details.json", {"count": len(details), "cves": details})
    return {"kev": kev, "cve": cve}


if __name__ == "__main__":
    r = run()
    k, c = r["kev"], r["cve"]
    print(f"KEV: {k.get('status')} recent={len(k.get('recent', []))}")
    print(f"CVE: {c.get('status')} new={c.get('new_cves')} matched={c.get('watch_matched')} hits={len(c.get('hits', []))}")
