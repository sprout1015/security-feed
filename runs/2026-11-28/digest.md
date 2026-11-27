# 보안 수집 요약 — 2026-11-28

수집 시각: 2026-11-28T05:48+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.
KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.

## 0. 오늘의 변화

- 바뀐 공식 소스 3개 · 새 KEV 0건 · 레이더 대상 CVE 0건 · 라이브러리 새 항목 0건 · 해결 0건
- 조용한 날: 아니오

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 3 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 5줄 / 삭제 5줄 · diff: `runs/2026-11-28/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`

```text
| HIGH | </security/cve-2026-59330> CVE-2026-59330 | Spring Security | November 19, 2026 | 4 versions
| HIGH | </security/cve-2026-59333> CVE-2026-59333 | Spring Security | November 19, 2026 | 2 versions
| HIGH | </security/cve-2026-59339> CVE-2026-59339 | Spring AI | November 19, 2026 | 4 versions
| MEDIUM | </security/cve-2026-59342> CVE-2026-59342 | Spring Data MongoDB | November 19, 2026 | 7 versions
| MEDIUM | </security/cve-2026-59353> CVE-2026-59353 | Spring Web Services | November 19, 2026 | 5 versions
```

#### .NET Announcements (`dotnet-announcements`) — 대상: .NET, ASP.NET Core
- 원문: https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity
- 추가 26줄 / 삭제 26줄 · diff: `runs/2026-11-28/diffs/dotnet-announcements.diff` · 전체 텍스트: `state/latest/dotnet-announcements.txt`

```text
Microsoft Security Advisory CVE-2026-114149 - ASP.NET Core Denial of Service Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#511 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114150 - ASP.NET Core Information Disclosure Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#514 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-109478 - ASP.NET Core Denial of Service Vulnerability
.NET 8.0.NET 9.0Patch-TuesdaySecurity
dotnet/announcements#515 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114156 - ASP.NET Core Security Feature Bypass Vulnerability
.NET 11.0Patch-TuesdaySecurity
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
Microsoft Security Advisory CVE-2026-114155 - .NET Elevation of Privilege Vulnerability
.NET 10.0.NET 11.0Patch-TuesdaySecurity
```

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 756줄 / 삭제 1865줄 · diff: `runs/2026-11-28/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: GHSA-6xqm-2982-gvrm, GHSA-vc3q-r4qh-vp64, GHSA-whwx-jj37-4gg5, RUSTSEC-2026-0601, RUSTSEC-2026-0602, RUSTSEC-2026-0603

```text
<updated>2026-11-27T12:00:00+00:00</updated>
<entry>
<title>RUSTSEC-2026-0602: Vulnerability in dryoc</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0602.html</id>
<updated>2026-11-27T12:00:00+00:00</updated>
<category term="crypto-failure"/>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0602.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0602: Vulnerability in dryoc"/>
<published>2026-11-27T12:00:00+00:00</published>
<summary xml:lang="en">Ed25519 signing key pairs with an inconsistent embedded public key are accepted</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/dryoc/RUSTSEC-2026-0602.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/dryoc/RUSTSEC-2026-0602.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0602">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0602
</h1>
<span class="subtitle">
<p>Ed25519 signing key pairs with an inconsistent embedded public key are accepted</p>
</span>
</header>
<dl>
```

### 형식만 바뀜 (시각·배너 등. 판단 불필요, 읽지 않는다)

Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`), PHP ChangeLog 8 (`php-changelog-8`), Symfony Security Advisories (`symfony-advisories`), Kubernetes Official CVE Feed (`k8s-cve-feed`)

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP 연도별 공지, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.25 · 전체 1805건 · 최근 7일 신규 15건
모든 CVE의 KEV 여부는 `runs/D/kev_lookup.json`에서 조회한다(오늘 자료에 나온 CVE만 담김).

| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |
|---|---|---|---|---|---|
| 2026-11-25 | CVE-2026-103406 | Hewlett Packard Enterprise (HPE) / Juniper Session Smart Conductor and Session Smart Router | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2026-133469 | Vates / Xen Orchestra | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2025-41450 | Danfoss / AK-SM 800A Series | - | Unknown | 2026-12-09 |
| 2026-11-25 | CVE-2023-25914 | Danfoss / AK-SM 800A Series | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2023-25915 | Danfoss / AK-SM 800A Series | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2026-133324 | Mitel / MiCollab | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2026-133275 | Mitel / MiCollab | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2026-133311 | Mitel / MiCollab | - | Unknown | 2026-12-09 |
| 2026-11-25 | CVE-2026-133303 | Mitel / MiCollab | - | Unknown | 2026-11-28 |
| 2026-11-25 | CVE-2026-133323 | Mitel / MiCollab | - | Unknown | 2026-11-28 |
| 2026-11-24 | CVE-2026-132224 | Optimizely / Web Experimentation | - | Unknown | 2026-11-27 |
| 2026-11-24 | CVE-2026-131914 | Idunno / AntiCsrf | - | Unknown | 2026-11-27 |
| 2026-11-24 | CVE-2026-132165 | Drupal / Core | - | Unknown | 2026-11-27 |
| 2026-11-23 | CVE-2026-133968 | Project MONAI / MONAI Label | - | Unknown | 2026-11-26 |
| 2026-11-23 | CVE-2026-134624 | N-able / MailAssure | - | Unknown | 2026-11-26 |

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-26T23:01:51.157Z ~ 2026-11-27T20:31:28.498Z · 새 CVE 352건 · 감시 제품 해당 0건 · 기준 통과 0건 · EPSS 조회 skipped
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

## 4. 라이브러리 대조 (lock 파일 × OSV)

실제 의존성 목록: `runs/D/dependency_index.json` (서비스별 패키지 이름→버전, 전이 의존성 포함). 공지 제품이 프레임워크의 하위 모듈(예: Spring Security, Spring LDAP, Twig)일 때 여기서 이름을 찾아 실제로 쓰는지 확인한다. 예: `jq -r '.services["alpha-match"] | keys[] | select(test("spring-security"))'`
서비스별 패키지 수: alpha-match 832개

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 5f73a69 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 4개 · 발견 0건

### 서비스: alpha-match (0건 · 패키지 1014개 · lock 4개)
전체: 패키지 0개에 권고 0건 · CVSS 7.0 이상 패키지 0개

**새로 생김 (기준 2026-11-27 대비, 0개)** — 루틴은 이것만 새로 판단한다
- 없음

**해결됨 (0개)**
- 없음

