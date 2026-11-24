"""수집기 진입점. 한 단계가 실패해도 나머지는 계속 돌고, 실패 사실은 digest와 status에 남긴다."""
from __future__ import annotations

import shutil
import sys
import traceback

from common import RUNS, today_kst
import collect_sources
import digest
import libraries
import projects
import radar

KEEP_RUNS = 60  # 일


def prune_runs() -> None:
    import datetime as dt
    cutoff = (dt.date.fromisoformat(today_kst()) - dt.timedelta(days=KEEP_RUNS)).isoformat()
    for d in RUNS.glob("*"):
        if d.is_dir() and d.name < cutoff:
            shutil.rmtree(d)


def main() -> int:
    errors = {}
    for name, fn in (("내 프로젝트", projects.run), ("공식 소스", collect_sources.collect), ("레이더", radar.run), ("라이브러리", libraries.run)):
        try:
            fn()
        except Exception as e:
            errors[name] = f"{type(e).__name__}: {e}"
            traceback.print_exc()
    digest.build(errors)
    prune_runs()
    print(f"done: {today_kst()} errors={list(errors)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
