"""3층: 라이브러리 대조.

inventory/<서비스명>/ 아래의 lock 파일을 osv-scanner로 검사해,
서비스별로 영향받는 패키지·설치 버전·권고·수정 버전을 기록한다.
버전 비교는 osv-scanner(코드)가 한다. 루틴은 결과를 읽고 권고 원문을 요약만 한다.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from common import INVENTORY, run_dir, save_json

LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "pom.xml",
             "gradle.lockfile", "requirements.txt", "poetry.lock", "Pipfile.lock", "go.mod",
             "Gemfile.lock", "Cargo.lock", "packages.lock.json"}


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    fixed = set()
    for a in vuln.get("affected", []) or []:
        if (a.get("package") or {}).get("name") not in (None, name):
            continue
        for r in a.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    return sorted(fixed)


def _severity(vuln: dict, groups: list[dict]) -> str | None:
    for g in groups:
        if vuln.get("id") in (g.get("ids") or []) and g.get("max_severity"):
            return g["max_severity"]
    return (vuln.get("database_specific") or {}).get("severity")


def run() -> dict:
    out = run_dir()
    services = sorted(p for p in INVENTORY.iterdir() if p.is_dir()) if INVENTORY.exists() else []
    lockfiles = [f for s in services for f in s.rglob("*") if f.name in LOCKFILES]
    if not lockfiles:
        result = {"status": "skipped", "reason": "inventory/ 아래에 lock 파일이 없음", "services": []}
        save_json(out / "library_matches.json", result)
        return result

    binary = os.environ.get("OSV_SCANNER") or shutil.which("osv-scanner")
    if not binary:
        result = {"status": "error", "error": "osv-scanner를 찾을 수 없음", "services": []}
        save_json(out / "library_matches.json", result)
        return result

    # --no-ignore: inventory/<프로젝트>/는 .gitignore 대상이라 이 옵션이 없으면 건너뜀
    # --all-packages: 취약점이 없는 lock 파일도 결과에 남겨 "검사됨"을 확인할 수 있게 함
    cmd = [binary, "scan", "source", "--recursive", "--no-ignore", "--all-packages", "--format", "json", str(INVENTORY)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    # 종료 코드 0: 취약점 없음, 1: 취약점 발견, 그 밖: 오류
    if proc.returncode not in (0, 1):
        result = {"status": "error", "error": (proc.stderr or proc.stdout)[-1500:], "services": []}
        save_json(out / "library_matches.json", result)
        return result
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        result = {"status": "error", "error": "osv-scanner 출력 해석 실패", "services": []}
        save_json(out / "library_matches.json", result)
        return result

    by_service: dict[str, dict] = {}
    for res in data.get("results", []) or []:
        path = (res.get("source") or {}).get("path", "")
        rel = os.path.relpath(path, INVENTORY) if path else "?"
        service = rel.split(os.sep)[0]
        svc = by_service.setdefault(service, {"service": service, "lockfiles": set(), "packages": 0, "findings": []})
        svc["lockfiles"].add(rel)
        svc["packages"] += len(res.get("packages", []) or [])
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package") or {}
            groups = pkg.get("groups") or []
            for v in pkg.get("vulnerabilities", []) or []:
                svc["findings"].append({
                    "package": p.get("name"), "ecosystem": p.get("ecosystem"), "installed": p.get("version"),
                    "id": v.get("id"), "aliases": v.get("aliases") or [], "summary": v.get("summary"),
                    "severity": _severity(v, groups), "fixed": _fixed_versions(v, p.get("name")),
                    "link": f"https://osv.dev/vulnerability/{v.get('id')}",
                })

    services_out = []
    for svc in by_service.values():
        svc["lockfiles"] = sorted(svc["lockfiles"])
        svc["count"] = len(svc["findings"])
        services_out.append(svc)
    result = {"status": "ok", "scanned_lockfiles": len(lockfiles),
              "total_findings": sum(s["count"] for s in services_out), "services": services_out}
    save_json(out / "library_matches.json", result)
    return result


if __name__ == "__main__":
    r = run()
    print(f"libraries: {r['status']} findings={r.get('total_findings', 0)}")
