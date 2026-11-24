"""0층: 내 프로젝트 가져오기.

config/projects.json의 공개 저장소를 얕게 클론해 lock 파일을 inventory/<id>/ 아래로 복사한다.
Gradle 프로젝트는 대상 저장소를 고치지 않고 init 스크립트로 gradle.lockfile을 만든다.
비공개 저장소는 공개 피드에 버전 정보가 새지 않도록 건너뛴다.
inventory/<id>/는 실행 때마다 새로 만들며 커밋하지 않는다(.gitignore).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request

from common import CONFIG, INVENTORY, ROOT, run_dir, save_json

WORK = ROOT / "work"
INIT_SCRIPT = ROOT / "collector" / "lock-all.init.gradle"


def _is_public(repo: str) -> bool | None:
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}",
                                 headers={"Accept": "application/vnd.github+json"})  # 토큰 없이: 공개일 때만 200
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return not json.load(r).get("private", True)
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def _run(cmd: list[str], cwd, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _gradle_lock(src, gdir: str, dest) -> dict:
    pdir = (src / gdir).resolve()
    wrapper = pdir / "gradlew"
    cmd = ([str(wrapper)] if wrapper.exists() else ["gradle"]) + [
        "--no-daemon", "-q", "--init-script", str(INIT_SCRIPT), "dependencies", "--write-locks"]
    if wrapper.exists():
        wrapper.chmod(0o755)
    p = _run(cmd, pdir, 900)
    made = sorted(pdir.rglob("gradle.lockfile"))
    for f in made:
        target = dest / gdir / f.relative_to(pdir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
    ok = bool(made)
    return {"path": gdir, "ok": ok, "lockfiles": len(made),
            **({} if ok else {"error": (p.stderr or p.stdout)[-800:]})}


def run() -> dict:
    cfg = json.loads((CONFIG / "projects.json").read_text(encoding="utf-8"))
    WORK.mkdir(exist_ok=True)
    out = []
    for pj in cfg.get("projects", []):
        pid = pj["id"]
        rec = {"id": pid, "name": pj.get("name", pid), "repo": pj["repo"], "ref": pj.get("ref")}
        dest = INVENTORY / pid
        shutil.rmtree(dest, ignore_errors=True)
        if pj.get("enabled", True) is False:
            out.append({**rec, "status": "disabled"}); continue
        pub = _is_public(pj["repo"])
        if pub is not True:
            out.append({**rec, "status": "skipped_private" if pub is False else "error",
                        "reason": "비공개 저장소는 공개 피드에 올리지 않음" if pub is False else "공개 여부 확인 실패"})
            continue
        src = WORK / pid
        shutil.rmtree(src, ignore_errors=True)
        p = _run(["git", "clone", "--depth", "1", "--branch", pj.get("ref") or "main",
                  f"https://github.com/{pj['repo']}.git", str(src)], ROOT, 600)
        if p.returncode != 0:
            out.append({**rec, "status": "error", "reason": p.stderr[-500:]}); continue
        rec["commit"] = _run(["git", "rev-parse", "HEAD"], src, 30).stdout.strip()
        copied, missing = [], []
        for lf in pj.get("lockfiles", []):
            f = src / lf
            if f.is_file():
                (dest / lf).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest / lf); copied.append(lf)
            else:
                missing.append(lf)
        gradle = [_gradle_lock(src, g, dest) for g in pj.get("gradle", [])]
        status = "ok" if not missing and all(g["ok"] for g in gradle) else "partial"
        out.append({**rec, "status": status, "lockfiles": copied, "missing": missing, "gradle": gradle})
    result = {"projects": out}
    save_json(run_dir() / "projects.json", result)
    return result


if __name__ == "__main__":
    r = run()
    for p in r["projects"]:
        print(p["id"], p["status"], p.get("lockfiles"), [(g["path"], g["ok"]) for g in p.get("gradle", [])])
