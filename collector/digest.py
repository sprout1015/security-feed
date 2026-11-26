"""루틴(AI)이 가장 먼저 읽는 요약 파일 runs/<날짜>/digest.md 와 status.json 을 만든다."""
from __future__ import annotations

from pathlib import Path

from common import STATE, extract_ids, load_json, now_kst, run_dir, save_json, today_kst

MAX_EXCERPT = 25


def _added_excerpt(diff_path: Path) -> list[str]:
    if not diff_path.exists():
        return []
    lines = [ln[1:] for ln in diff_path.read_text(encoding="utf-8").splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    return lines[:MAX_EXCERPT]


def _kev_lookup(out, cve: dict, lib: dict) -> dict:
    """오늘 자료에 나온 모든 CVE의 KEV 등재 정보. 루틴이 34만 바이트짜리 kev_index.json 을 통째로 읽지 않게 한다."""
    import re
    ids = set()
    for f in (out / "diffs").glob("*.diff") if (out / "diffs").exists() else []:
        ids.update(i for i in extract_ids(f.read_text(encoding="utf-8", errors="ignore")) if i.startswith("CVE-"))
    for h in (cve.get("hits") or []) + (cve.get("matched_below_threshold") or []):
        if h.get("cve"):
            ids.add(h["cve"])
    for svc in lib.get("services", []) or []:
        for g in svc.get("by_package", []) or []:
            ids.update(g.get("cves", []))
    idx = (load_json(STATE / "kev_index.json", {}) or {}).get("cves", {})
    look = {i: idx.get(i) for i in sorted(ids)}
    save_json(out / "kev_lookup.json", {"count": len(look), "kev_listed": sum(1 for v in look.values() if v), "cves": look})
    return look


def build(step_errors: dict) -> str:
    date = today_kst()
    out = run_dir(date)
    src = load_json(out / "sources.json", {}) or {}
    kev = load_json(out / "kev_recent.json", {}) or {}
    cve = load_json(out / "cve_radar.json", {}) or {}
    lib = load_json(out / "library_matches.json", {}) or {}
    prj = load_json(out / "projects.json", {}) or {}
    kev_look = _kev_lookup(out, cve, lib)
    root = out.parent.parent

    L = [f"# 보안 수집 요약 — {date}", "",
         f"수집 시각: {now_kst().isoformat(timespec='minutes')} (KST)", "",
         "이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.",
         "KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.", ""]

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
    det = (load_json(out / "cve_details.json", {}) or {}).get("cves", {})
    if det:
        L += ["### 오늘 처음 본 CVE — 공식 레코드 요약 (cve_details.json, 벤더·CVE 상세 페이지를 따로 열지 않는다)", ""]
        for cid, d in det.items():
            if d.get("error"):
                L.append(f"- {cid}: 레코드 없음/조회 실패 ({d['error'][:60]}) — 원문 공지 내용으로만 판단")
                continue
            sc = d.get("cvss") or {}
            L.append(f"- **{cid}** {sc.get('severity') or '점수 없음'} {sc.get('score') or ''} · {d.get('title') or d.get('description', '')[:80]}"
                     f" · 영향: {'; '.join(d.get('affected_versions') or []) or '미기재'}")
        L.append("")
    noise = [s for s in sources if s.get("status") == "noise"]
    if noise:
        L += ["### 형식만 바뀜 (시각·배너 등. 판단 불필요, 읽지 않는다)", "",
              ", ".join(f"{s['name']} (`{s['id']}`)" for s in noise), ""]
    unchanged = [s["name"] for s in sources if s.get("status") == "unchanged"]
    if unchanged:
        L += ["### 변화 없음", "", ", ".join(unchanged), ""]

    # 2층 KEV
    L += ["## 2. CISA KEV (실제 악용 중)", ""]
    if kev.get("status") != "ok":
        L += [f"수집 실패: {kev.get('error')}", ""]
    else:
        L += [f"카탈로그 {kev.get('catalogVersion')} · 전체 {kev.get('count')}건 · 최근 {kev.get('window_days')}일 신규 {len(kev.get('recent', []))}건",
              "모든 CVE의 KEV 여부는 `runs/D/kev_lookup.json`에서 조회한다(오늘 자료에 나온 CVE만 담김).", ""]
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
                L.append(f"  - 영향 범위(공식 레코드): {'; '.join(h.get('affected_versions') or h['affected'])} · {h['link']}")
            L.append("")
        below = cve.get("matched_below_threshold") or []
        if below:
            from collections import Counter
            cnt = Counter(w for m in below for w in m["watch"])
            L += ["기준 미달(보고 안 함) 제품별 건수: " + ", ".join(f"{k} {v}" for k, v in cnt.most_common()), ""]

    # 3층
    L += ["## 4. 라이브러리 대조 (lock 파일 × OSV)", ""]
    dep = (load_json(out / "dependency_index.json", {}) or {}).get("services", {})
    if dep:
        L += ["실제 의존성 목록: `runs/D/dependency_index.json` (서비스별 패키지 이름→버전, 전이 의존성 포함). "
              "공지 제품이 프레임워크의 하위 모듈(예: Spring Security, Spring LDAP, Twig)일 때 여기서 이름을 찾아 실제로 쓰는지 확인한다. "
              "예: `jq -r '.services[\"alpha-match\"] | keys[] | select(test(\"spring-security\"))'`",
              "서비스별 패키지 수: " + ", ".join(f"{k} {len(v)}개" for k, v in dep.items()), ""]
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
            L.append(f"### 서비스: {s['service']} ({s['count']}건 · 패키지 {s.get('packages', '?')}개 · lock {len(s['lockfiles'])}개)")
            if s.get("by_package") is not None:
                dl = s.get("delta") or {}
                L.append(f"전체: 패키지 {len(s['by_package'])}개에 권고 {s['count']}건 · CVSS 7.0 이상 패키지 {s.get('high_or_above_packages', 0)}개")
                def line(g):
                    cv = ", ".join(g["cves"][:3]) + (f" 외 {len(g['cves']) - 3}" if len(g["cves"]) > 3 else "")
                    kev_hit = [c for c in g["cves"] if kev_look.get(c)]
                    return (f"- {g['package']} {g['installed']} → {g['fix_to'] or '수정 버전 없음'} · 최고 CVSS {g['max_cvss'] if g['max_cvss'] is not None else '미상'} · 권고 {g['count']}건 · {cv or '-'}"
                            + (f" · ⚠️ KEV: {', '.join(kev_hit)}" if kev_hit else ""))
                if dl.get("first_seen"):
                    L.append(f"(이 서비스는 오늘 처음 대조됨 — 전 항목이 새 항목)")
                L += ["", f"**새로 생김 (기준 {dl.get('since') or '없음'} 대비, {len(dl.get('new', []))}개)** — 루틴은 이것만 새로 판단한다"]
                L += [line(g) for g in dl.get("new", [])] or ["- 없음"]
                if dl.get("new_advisories"):
                    L += ["", "**기존 패키지에 권고 추가**"] + [f"- {k}: {', '.join(v)}" for k, v in dl["new_advisories"].items()]
                L += ["", f"**해결됨 ({len(dl.get('resolved', []))}개)**"] + ([f"- {r['package']} {r['installed']}" for r in dl.get("resolved", [])] or ["- 없음"])
                known = [g for g in s["by_package"] if g not in dl.get("new", [])]
                if known:
                    L += ["", f"**기존 미조치 {len(known)}개** (이미 보고됨, 상위 5개만 표시. 전체는 library_matches.json)"]
                    L += [line(g) for g in known[:5]]
            else:
                for f in s["findings"]:
                    alias = ", ".join(a for a in f["aliases"] if a.startswith("CVE-")) or "-"
                    L.append(f"- {f['package']} {f['installed']} → 수정 {', '.join(f['fixed']) or '없음'} · {f['id']} ({alias}) · {f.get('severity') or '심각도 미상'} · {f.get('summary') or ''}")
            L.append("")
    else:
        L += [f"{lib.get('status')}: {lib.get('reason') or lib.get('error')}", ""]

    # 0절: 오늘의 변화 (루틴이 가장 먼저 본다)
    prev_kev = set()
    prev_dirs = sorted(d for d in out.parent.iterdir() if d.is_dir() and d.name < date)
    if prev_dirs:
        pk = load_json(prev_dirs[-1] / "kev_recent.json", {}) or {}
        prev_kev = {v["cve"] for v in pk.get("recent", [])}
    new_kev = [v["cve"] for v in kev.get("recent", []) if v["cve"] not in prev_kev] if prev_dirs else [v["cve"] for v in kev.get("recent", [])]
    lib_new = sum(len((x.get("delta") or {}).get("new", [])) + len((x.get("delta") or {}).get("new_advisories", {})) for x in lib.get("services", []))
    lib_resolved = sum(len((x.get("delta") or {}).get("resolved", [])) for x in lib.get("services", []))
    changed_src = int(src.get("changed") or 0)
    cve_hits = len(cve.get("hits", []))
    quiet = (changed_src == 0 and cve_hits == 0 and not new_kev and lib_new == 0 and not step_errors and not src.get("error"))
    head = ["## 0. 오늘의 변화", "",
            f"- 바뀐 공식 소스 {changed_src}개 · 새 KEV {len(new_kev)}건{(' (' + ', '.join(new_kev[:5]) + ')') if new_kev else ''} · 레이더 대상 CVE {cve_hits}건 · 라이브러리 새 항목 {lib_new}건 · 해결 {lib_resolved}건",
            f"- 조용한 날: {'예 — 새로 판단할 것이 없다. 짧은 보고서로 끝낸다.' if quiet else '아니오'}", ""]
    idx = next(i for i, l in enumerate(L) if l.startswith("## 1."))
    L[idx:idx] = head
    text = "\n".join(L) + "\n"
    (out / "digest.md").write_text(text, encoding="utf-8")
    save_json(out / "status.json", {
        "date": date, "finished_at": now_kst().isoformat(timespec="seconds"),
        "step_errors": step_errors,
        "sources": {k: src.get(k) for k in ("total", "ok", "changed", "noise", "error")},
        "kev": {"status": kev.get("status"), "recent": len(kev.get("recent", []))},
        "cve": {"status": cve.get("status"), "new": cve.get("new_cves"), "hits": len(cve.get("hits", []))},
        "libraries": {"status": lib.get("status"), "findings": lib.get("total_findings", 0)},
        "projects": {p["id"]: p.get("status") for p in prj.get("projects", [])},
        "today": {"quiet": quiet, "changed_sources": changed_src, "new_kev": new_kev, "cve_hits": cve_hits,
                  "library_new": lib_new, "library_resolved": lib_resolved},
    })
    return text
