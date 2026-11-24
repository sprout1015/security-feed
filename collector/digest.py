"""루틴(AI)이 가장 먼저 읽는 요약 파일 runs/<날짜>/digest.md 와 status.json 을 만든다."""
from __future__ import annotations

from pathlib import Path

from common import load_json, now_kst, run_dir, save_json, today_kst

MAX_EXCERPT = 25


def _added_excerpt(diff_path: Path) -> list[str]:
    if not diff_path.exists():
        return []
    lines = [ln[1:] for ln in diff_path.read_text(encoding="utf-8").splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    return lines[:MAX_EXCERPT]


def build(step_errors: dict) -> str:
    date = today_kst()
    out = run_dir(date)
    src = load_json(out / "sources.json", {}) or {}
    kev = load_json(out / "kev_recent.json", {}) or {}
    cve = load_json(out / "cve_radar.json", {}) or {}
    lib = load_json(out / "library_matches.json", {}) or {}
    prj = load_json(out / "projects.json", {}) or {}
    root = out.parent.parent

    L = [f"# 보안 수집 요약 — {date}", "",
         f"수집 시각: {now_kst().isoformat(timespec='minutes')} (KST)", "",
         "이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.", ""]

    if step_errors:
        L += ["## 수집 단계 오류", ""] + [f"- {k}: {v}" for k, v in step_errors.items()] + [""]

    # 1층
    sources = src.get("sources", [])
    L += ["## 1. 공식 소스 원문",
          f"전체 {src.get('total', 0)} · 수집 성공 {src.get('ok', 0)} · 바뀜 {src.get('changed', 0)} · 실패 {src.get('error', 0)}", ""]
    changed = [s for s in sources if s.get("status") == "changed"]
    if changed:
        L += ["### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)", ""]
        for s in changed:
            L.append(f"#### {s['name']} (`{s['id']}`) — 대상: {s['products']}")
            L.append(f"- 원문: {s['url']}")
            L.append(f"- 추가 {s.get('added_lines', 0)}줄 / 삭제 {s.get('removed_lines', 0)}줄 · diff: `{s.get('diff_path')}` · 전체 텍스트: `{s['text_path']}`")
            if s.get("new_ids"):
                L.append(f"- 오늘 처음 본 식별자: {', '.join(s['new_ids'])}")
            ex = _added_excerpt(root / s["diff_path"]) if s.get("diff_path") else []
            if ex:
                L += ["", "```text"] + ex + ["```"]
            L.append("")
    first = [s for s in sources if s.get("status") == "first"]
    if first:
        L += ["### 처음 수집한 소스 (비교 기준만 저장, 새 항목으로 세지 않음)", ""]
        L += [f"- {s['name']} (`{s['id']}`) · 식별자 {s.get('id_count', 0)}개 · `{s['text_path']}`" for s in first] + [""]
    errors = [s for s in sources if s.get("status") == "error"]
    if errors:
        L += ["### 수집 실패", ""] + [f"- {s['name']} (`{s['id']}`): {s.get('error')}" for s in errors] + [""]
    unchanged = [s["name"] for s in sources if s.get("status") == "unchanged"]
    if unchanged:
        L += ["### 변화 없음", "", ", ".join(unchanged), ""]

    # 2층 KEV
    L += ["## 2. CISA KEV (실제 악용 중)", ""]
    if kev.get("status") != "ok":
        L += [f"수집 실패: {kev.get('error')}", ""]
    else:
        L += [f"카탈로그 {kev.get('catalogVersion')} · 전체 {kev.get('count')}건 · 최근 {kev.get('window_days')}일 신규 {len(kev.get('recent', []))}건",
              "모든 CVE의 KEV 여부는 `state/kev_index.json`에서 조회한다.", ""]
        if kev.get("recent"):
            L += ["| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |", "|---|---|---|---|---|---|"]
            for v in kev["recent"]:
                w = ", ".join(v["watch"]) or "-"
                L.append(f"| {v['dateAdded']} | {v['cve']} | {v['vendor']} / {v['product']} | {w} | {v['ransomware']} | {v['dueDate']} |")
            L.append("")

    # 2층 CVE
    L += ["## 3. 새 CVE 레이더 (CVE.org 공식 목록)", ""]
    if cve.get("status") != "ok":
        L += [f"수집 실패: {cve.get('error')}", ""]
    else:
        th = cve.get("thresholds", {})
        L += [f"대상 구간(UTC) {cve.get('since_utc')} ~ {cve.get('until_utc')} · 새 CVE {cve.get('new_cves')}건 · "
              f"감시 제품 해당 {cve.get('watch_matched')}건 · 기준 통과 {len(cve.get('hits', []))}건 · EPSS 조회 {cve.get('epss_status')}",
              f"기준: 인벤토리 제품은 CVSS ≥ {th.get('inventory_cvss')} 또는 점수 미공개, 기반 구성요소는 CVSS ≥ {th.get('cvss')}, "
              f"공통으로 EPSS ≥ {th.get('epss')} 또는 KEV 등재", ""]
        for grp, title in (("inventory", "### 인벤토리 제품"), ("baseline", "### 기반 구성요소")):
            rows = [h for h in cve.get("hits", []) if grp in h["watch_group"] and (grp == "inventory" or "inventory" not in h["watch_group"])]
            if not rows:
                continue
            L += [title, ""]
            for h in rows:
                L.append(f"- **{h['cve']}** [{', '.join(h['watch'])}] {' · '.join(h['reasons'])} · {h.get('title') or (h.get('description') or '')[:120]}")
                L.append(f"  - 영향 제품: {'; '.join(h['affected'])} · {h['link']}")
            L.append("")
        below = cve.get("matched_below_threshold") or []
        if below:
            from collections import Counter
            cnt = Counter(w for m in below for w in m["watch"])
            L += ["기준 미달(보고 안 함) 제품별 건수: " + ", ".join(f"{k} {v}" for k, v in cnt.most_common()), ""]

    # 3층
    L += ["## 4. 라이브러리 대조 (lock 파일 × OSV)", ""]
    if prj.get("projects"):
        L += ["감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):"]
        for p in prj["projects"]:
            extra = ""
            if p.get("status") in ("ok", "partial"):
                g = ", ".join(f"{x['path']} {'✓' if x['ok'] else '✗ lock 생성 실패'}" for x in p.get("gradle", []))
                extra = f" · 커밋 {p.get('commit', '')[:7]} · lock {len(p.get('lockfiles', []))}개" + (f" · Gradle: {g}" if g else "") + (f" · 없음: {', '.join(p['missing'])}" if p.get("missing") else "")
            elif p.get("reason"):
                extra = f" · {p['reason'][:120]}"
            L.append(f"- {p['name']} ({p['repo']}@{p.get('ref')}): {p['status']}{extra}")
        L.append("")
    if lib.get("status") == "ok":
        L += [f"lock 파일 {lib.get('scanned_lockfiles')}개 · 발견 {lib.get('total_findings')}건", ""]
        for s in lib.get("services", []):
            L.append(f"### 서비스: {s['service']} ({s['count']}건)")
            for f in s["findings"]:
                alias = ", ".join(a for a in f["aliases"] if a.startswith("CVE-")) or "-"
                L.append(f"- {f['package']} {f['installed']} → 수정 {', '.join(f['fixed']) or '없음'} · {f['id']} ({alias}) · {f.get('severity') or '심각도 미상'} · {f.get('summary') or ''}")
            L.append("")
    else:
        L += [f"{lib.get('status')}: {lib.get('reason') or lib.get('error')}", ""]

    text = "\n".join(L) + "\n"
    (out / "digest.md").write_text(text, encoding="utf-8")
    save_json(out / "status.json", {
        "date": date, "finished_at": now_kst().isoformat(timespec="seconds"),
        "step_errors": step_errors,
        "sources": {k: src.get(k) for k in ("total", "ok", "changed", "error")},
        "kev": {"status": kev.get("status"), "recent": len(kev.get("recent", []))},
        "cve": {"status": cve.get("status"), "new": cve.get("new_cves"), "hits": len(cve.get("hits", []))},
        "libraries": {"status": lib.get("status"), "findings": lib.get("total_findings", 0)},
        "projects": {p["id"]: p.get("status") for p in prj.get("projects", [])},
    })
    return text
