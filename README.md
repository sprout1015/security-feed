# security-feed

사내 보안 경고 데일리 루틴의 **수집 저장소**입니다. GitHub Actions가 매일 06:30(KST)에 공식 보안 정보를 받아 여기에 쌓고, 06:50에 Claude 루틴이 이 저장소만 읽어 판단한 뒤 Notion에 보고합니다. 루틴은 웹에 직접 접속하지 않습니다.

## 역할 분담

| 누가 | 하는 일 |
|---|---|
| 수집기 (코드, 이 저장소) | 원문 내려받기, 어제와 비교, 처음 본 식별자 기록, KEV·CVE 거르기, lock 파일 버전 대조 |
| 루틴 (Claude) | 바뀐 원문을 읽고 내용·조건·영향 버전 판단, 인벤토리 대조, 레벨 분류, Notion 기록 |
| 사람 | 조치, 사람 확인 요청 처리, 인벤토리·lock 파일 최신화 |

## 수집하는 것

1. **공식 소스 원문** (`config/sources.json`): 벤더 보안 페이지·피드를 가공 없이 `state/latest/`에 저장하고, 어제와 달라진 줄을 `runs/<날짜>/diffs/`에 남깁니다. 원문에 나온 CVE·GHSA 등 식별자를 처음 본 날짜를 `state/seen_ids.json`에 기록합니다(날짜 없는 공지 대응).
2. **CISA KEV** (실제 악용 중): 최근 7일 신규 등재를 제품과 무관하게 모두 기록하고, 모든 CVE를 조회할 수 있는 `state/kev_index.json`을 만듭니다.
3. **새 CVE 레이더** (CVE.org 공식 목록): 지난 실행 이후 공개된 CVE 중 `config/watchlist.json` 제품에 해당하는 것만 남깁니다.
   - 인벤토리 제품: CVSS 7.0 이상이거나 점수 미공개(Apache 등은 점수 없이 공개)
   - 기반 구성요소(OpenSSH, OpenSSL, glibc, Linux 커널 등): CVSS 9.0 이상
   - 공통: EPSS 0.5 이상이거나 KEV 등재면 포함
4. **라이브러리 대조**: `inventory/<서비스명>/`의 lock 파일을 osv-scanner로 검사합니다.

## 결과물

```
runs/<날짜>/
  digest.md            루틴이 가장 먼저 읽는 요약
  status.json          단계별 성공·실패
  sources.json         소스별 상태(바뀜/변화 없음/처음/실패)와 새 식별자
  diffs/<소스>.diff    어제와 달라진 부분
  kev_recent.json      KEV 최근 신규
  cve_radar.json       새 CVE 중 기준 통과 항목
  library_matches.json 서비스별 라이브러리 취약점
state/
  latest/<소스>.*      최신 원문과 비교용 텍스트
  seen_ids.json        소스별 식별자 처음 본 날짜
  kev_index.json       KEV 전체 색인
  cve_cursor.json      CVE 목록을 어디까지 읽었는지
```

`runs/`는 60일이 지나면 지웁니다. 이전 원문은 git 기록에 남습니다.

## 공개 저장소 주의사항

이 저장소는 루틴이 인증 없이 읽을 수 있도록 **공개**로 운영합니다. 그래서 다음을 지킵니다.

- **실제 서비스의 lock 파일을 `inventory/`에 넣지 않습니다.** 어떤 서비스가 어떤 취약 버전을 쓰는지 외부에 그대로 드러납니다. `inventory/_sample-notification-service/`는 동작 확인용 가짜 데이터입니다.
- 실제 라이브러리 대조는 각 서비스의 **비공개 저장소 CI**에서 osv-scanner를 돌리는 방식으로 합니다(아래 예시). 결과는 그 저장소의 보안 탭이나 Notion으로 보냅니다.
- `config/watchlist.json`의 제품 목록은 공개됩니다. 버전은 적지 않습니다(버전은 Notion 인벤토리에만 둡니다).

각 서비스 저장소에 넣을 워크플로 예시:

```yaml
name: osv-scan
on: { schedule: [{ cron: "0 21 * * *" }], push: { branches: [main] } }
jobs:
  scan:
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.0.2
```

## 관리 방법

- **소스 추가·변경**: `config/sources.json`을 고칩니다. Notion "공식 소스" 표도 함께 고쳐 주세요. 루틴이 둘이 다르면 보고서에 알려 줍니다.
- **인벤토리 제품 추가**: Notion 인벤토리에 행을 추가하고, 넓은 레이더에서도 보이게 하려면 `config/watchlist.json`에 제품을 추가합니다.
- **lock 파일**: 공개 저장소이므로 실제 lock 파일은 넣지 않습니다(위 주의사항 참고). 나중에 저장소를 비공개로 바꾸면 각 서비스 CI가 lock 파일을 `inventory/<서비스명>/`에 복사해 커밋하는 방식으로 쓸 수 있습니다.
- **수동 실행**: Actions 탭 → collect-security-feed → Run workflow.

## 로컬 실행

```bash
python collector/run.py          # 오늘 날짜로 실행
FEED_DATE=2026-11-20 python collector/run.py
```

## 내 프로젝트 감시 (config/projects.json)

- 수집기는 실행 때마다 목록의 **공개 저장소**를 얕게 클론해 lock 파일을 `inventory/<id>/`에 모으고 osv-scanner로 대조합니다. 비공개 저장소는 공개 피드에 버전이 새지 않도록 자동으로 건너뜁니다.
- Gradle 프로젝트는 대상 저장소를 고치지 않고 `collector/lock-all.init.gradle`로 `gradle.lockfile`을 만들어 전이 의존성까지 검사합니다.
- `inventory/<id>/`는 커밋하지 않습니다(.gitignore). 그래서 osv-scanner는 `--no-ignore`로 실행합니다.
- 결과는 `runs/D/library_matches.json`의 서비스별 `by_package`(패키지@버전 단위 요약: 최고 CVSS, 권고 수, 올릴 버전)로 정리됩니다.
- 현재 등록: Alpha-Match. endfield-attendance-android·RAGDeck은 공개 전환 후 `enabled: true`로 바꿉니다.

