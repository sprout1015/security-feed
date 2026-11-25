# 보안 수집 요약 — 2026-11-25

수집 시각: 2026-11-25T10:11+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.
KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.

## 0. 오늘의 변화

- 바뀐 공식 소스 1개 · 새 KEV 3건 (CVE-2026-132224, CVE-2026-131914, CVE-2026-132165) · 레이더 대상 CVE 0건 · 라이브러리 새 항목 0건 · 해결 0건
- 조용한 날: 아니오

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 1 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### .NET Announcements (`dotnet-announcements`) — 대상: .NET, ASP.NET Core
- 원문: https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity
- 추가 25줄 / 삭제 25줄 · diff: `runs/2026-11-25/diffs/dotnet-announcements.diff` · 전체 텍스트: `state/latest/dotnet-announcements.txt`

```text
Microsoft Security Advisory CVE-2026-114149 - ASP.NET Core Denial of Service Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#511 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114150 - ASP.NET Core Information Disclosure Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#514 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114156 - ASP.NET Core Security Feature Bypass Vulnerability
dotnet/announcements#510 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114147 - ASP.NET Core Denial of Service Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#509 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114157 - ASP.NET Core Security Feature Bypass Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#507 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-109476 - ASP.NET Core Information Disclosure Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#508 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-118749 - ASP.NET Core Denial of Service Vulnerability
dotnet/announcements#505 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-109481 - ASP.NET Core Elevation of Privilege Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#506 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114155 - .NET Elevation of Privilege Vulnerability
.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#502 · Filter by author bribrothers opened on Nov 10, 2026
```

### 형식만 바뀜 (시각·배너 등. 판단 불필요, 읽지 않는다)

Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`), PHP 연도별 공지 (`php-archive`), Symfony Security Advisories (`symfony-advisories`)

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP ChangeLog 8, PHP php-src 보안 권고, Spring Security Advisories, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, RustSec Advisory Database, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고, Kubernetes Official CVE Feed

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.24 · 전체 1795건 · 최근 7일 신규 13건
모든 CVE의 KEV 여부는 `runs/D/kev_lookup.json`에서 조회한다(오늘 자료에 나온 CVE만 담김).

| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |
|---|---|---|---|---|---|
| 2026-11-24 | CVE-2026-132224 | Optimizely / Web Experimentation | - | Unknown | 2026-11-27 |
| 2026-11-24 | CVE-2026-131914 | Idunno / AntiCsrf | - | Unknown | 2026-11-27 |
| 2026-11-24 | CVE-2026-132165 | Drupal / Core | - | Unknown | 2026-11-27 |
| 2026-11-23 | CVE-2026-133968 | Project MONAI / MONAI Label | - | Unknown | 2026-11-26 |
| 2026-11-23 | CVE-2026-134624 | N-able / MailAssure | - | Unknown | 2026-11-26 |
| 2026-11-20 | CVE-2026-129448 | Apache / Roller | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2026-123890 | Broadcom / VMware vCenter | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2025-42884 | SAP / NetWeaver | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2026-76466 | Cisco / Expressway Series | - | Unknown | 2026-11-23 |
| 2026-11-18 | CVE-2024-10441 | Synology / DiskStation Manager (DSM) | - | Known | 2026-11-21 |
| 2026-11-18 | CVE-2026-40217 | BerriAI / LiteLLM | - | Unknown | 2026-12-02 |
| 2026-11-18 | CVE-2026-90817 | Vanderbilt University / Research Electronic Data Capture (REDCap) | - | Unknown | 2026-11-21 |
| 2026-11-18 | CVE-2026-90436 | Apache / Axis | - | Unknown | 2026-11-21 |

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-25T00:52:08.588Z ~ 2026-11-25T00:59:10.732Z · 새 CVE 1건 · 감시 제품 해당 0건 · 기준 통과 0건 · EPSS 조회 skipped
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 5f73a69 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 4개 · 발견 0건

### 서비스: alpha-match (0건 · 패키지 1014개 · lock 4개)
전체: 패키지 0개에 권고 0건 · CVSS 7.0 이상 패키지 0개

**새로 생김 (기준 2026-11-24 대비, 0개)** — 루틴은 이것만 새로 판단한다
- 없음

**해결됨 (0개)**
- 없음

