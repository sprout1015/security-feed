# 보안 수집 요약 — 2026-11-24

수집 시각: 2026-11-24T20:13+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 9 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) — 대상: Node.js
- 원문: https://nodejs.org/en/feed/vulnerability.xml
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/nodejs-vuln-rss.diff` · 전체 텍스트: `state/latest/nodejs-vuln-rss.txt`

```text
<lastBuildDate>Tue, 24 Nov 2026 11:13:08 GMT</lastBuildDate>
```

#### PHP 연도별 공지 (`php-archive`) — 대상: PHP
- 원문: https://www.php.net/archive/{year}.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/php-archive.diff` · 전체 텍스트: `state/latest/php-archive.txt`

```text
Date: May 29-30, 2026
```

#### PHP ChangeLog 8 (`php-changelog-8`) — 대상: PHP 8.x
- 원문: https://www.php.net/ChangeLog-8.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/php-changelog-8.diff` · 전체 텍스트: `state/latest/php-changelog-8.txt`

```text
PHP Conference Kansai 2026 (JAPAN)
```

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 3줄 / 삭제 3줄 · diff: `runs/2026-11-24/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`

```text
| HIGH | </security/cve-2026-123886> CVE-2026-123886 | Spring Data Elasticsearch | November 19, 2026 | 2 versions
| MEDIUM | </security/cve-2026-59273> CVE-2026-59273 | Spring Security | November 19, 2026 | 8 versions
| HIGH | </security/cve-2026-59344> CVE-2026-59344 | Spring AI | November 19, 2026 | 4 versions
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 42줄 / 삭제 42줄 · diff: `runs/2026-11-24/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`
- 오늘 처음 본 식별자: CVE-2026-133774, CVE-2026-133775, CVE-2026-133776, CVE-2026-133777, CVE-2026-133778, CVE-2026-133779, CVE-2026-133780, CVE-2026-133781, CVE-2026-135801, CVE-2026-135802, CVE-2026-55877

```text
CVE-2026-133781 Build-time Code Execution in @symfony/stimulus-bridge via a Controller Package That Maps Its package.json to a Script
Build-time Code Execution in @symfony/stimulus-bridge via a Controller Package That Maps Its package.json to a Script
November 24, 2026
</blog/category/security-advisories> #Security Advisories
#Symfony UX
CVE-2026-133780 @symfony/stimulus-bridge lazy-controller-loader: arbitrary code execution via unsanitized Stimulus magic comments
@symfony/stimulus-bridge lazy-controller-loader: arbitrary code execution via unsanitized Stimulus magic comments
November 24, 2026
</blog/category/security-advisories> #Security Advisories
#Symfony UX
CVE-2026-133779 XSS in symfony/ux-icons via Attribute Names That Browsers Read Differently: Incomplete Fix for CVE-2026-55877
XSS in symfony/ux-icons via Attribute Names That Browsers Read Differently: Incomplete Fix for CVE-2026-55877
November 24, 2026
</blog/category/security-advisories> #Security Advisories
#Symfony UX
CVE-2026-133778 Live Components Configured With a Custom Route Can Still Be Reached Through the Default Route
Live Components Configured With a Custom Route Can Still Be Reached Through the Default Route
November 24, 2026
</blog/category/security-advisories> #Security Advisories
#Symfony UX
CVE-2026-133777 XSS in symfony/ux-icons via SVG Content That Browsers Parse as HTML: Incomplete Fix for CVE-2026-55877
XSS in symfony/ux-icons via SVG Content That Browsers Parse as HTML: Incomplete Fix for CVE-2026-55877
November 24, 2026
</blog/category/security-advisories> #Security Advisories
#Symfony UX
```

#### .NET Announcements (`dotnet-announcements`) — 대상: .NET, ASP.NET Core
- 원문: https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity
- 추가 25줄 / 삭제 25줄 · diff: `runs/2026-11-24/diffs/dotnet-announcements.diff` · 전체 텍스트: `state/latest/dotnet-announcements.txt`

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

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 369줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: GHSA-mmwx-cp2j-wjh2, RUSTSEC-2026-0596, RUSTSEC-2026-0597, RUSTSEC-2026-0598

```text
<updated>2026-11-24T12:00:00+00:00</updated>
<entry>
<title>RUSTSEC-2026-0597: Unsoundness in hugepage-rs</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0597.html</id>
<updated>2026-11-24T12:00:00+00:00</updated>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0597.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0597: Unsoundness in hugepage-rs"/>
<published>2026-11-24T12:00:00+00:00</published>
<summary xml:lang="en">`hugepage_rs::Box::new` may cause undefined behavior when initializing memory</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/hugepage-rs/RUSTSEC-2026-0597.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/hugepage-rs/RUSTSEC-2026-0597.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0597">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0597
</h1>
<span class="subtitle">
<p>
<code>hugepage_rs::Box::new</code> may cause undefined behavior when initializing memory</p>
</span>
</header>
<dl>
```

#### OpenSSL Vulnerabilities (`openssl-vulns`) — 대상: OpenSSL
- 원문: https://openssl-library.org/news/vulnerabilities/
- 추가 182줄 / 삭제 0줄 · diff: `runs/2026-11-24/diffs/openssl-vulns.diff` · 전체 텍스트: `state/latest/openssl-vulns.txt`
- 오늘 처음 본 식별자: CVE-2026-107494, CVE-2026-121482, CVE-2026-84785, CVE-2026-84786

```text
<#CVE-2026-84785>
CVE-2026-84785
Severity
Low
Published at
24 November 2026
Title
Unbounded Out-of-Order Fragment Reassembly in QUIC Streams
Found by
Duc Anh Luu (University of Melbourne) and Jiwoo Kim (Arpe)
Fix developed by
Duc Anh Luu (University of Melbourne)
Affected
from 4.1.0 before 4.1.1
from 4.0.0 before 4.0.4
from 3.5.0 before 3.5.10
References
<https://www.cve.org/CVERecord?id=CVE-2026-84785> CVE Record
OpenSSL Advisory
4.1.1 git commit
4.0.4 git commit
3.5.10 git commit
Issue summary: A QUIC peer that sends many small out-of-order STREAM fragments
while withholding the first byte of the stream may cause OpenSSL to buffer
a large number of reassembly nodes occupying much larger memory than
```

#### Kubernetes Official CVE Feed (`k8s-cve-feed`) — 대상: Kubernetes
- 원문: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/k8s-cve-feed.diff` · 전체 텍스트: `state/latest/k8s-cve-feed.txt`

```text
"updated_at": "2026-11-24T09:09:07Z"
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.23 · 전체 1792건 · 최근 7일 신규 11건
모든 CVE의 KEV 여부는 `state/kev_index.json`에서 조회한다.

| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |
|---|---|---|---|---|---|
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
| 2026-11-17 | CVE-2026-115731 | Perforce / Puppet Enterprise | - | Unknown | 2026-12-01 |

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-24T05:17:02.080Z ~ 2026-11-24T11:03:14.456Z · 새 CVE 86건 · 감시 제품 해당 1건 · 기준 통과 1건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

### 인벤토리 제품

- **CVE-2026-59415** [Spring] CVSS 10.0 · TypesenseVectorStore doDelete filter injection via document ID allows unintended document deletion
  - 영향 제품: Spring / Spring AI · https://www.cve.org/CVERecord?id=CVE-2026-59415

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 59ffc51 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 5개 · 발견 2건

### 서비스: _sample-notification-service (2건)
- body-parser 1.20.3 → 수정 1.20.9, 2.4.0 · GHSA-27r3-jxmh-p828 (CVE-2026-111181) · 7.5 · body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
- body-parser 1.20.3 → 수정 1.20.6, 2.3.0 · GHSA-v422-hmwv-36x6 (CVE-2026-12590) · 3.7 · body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

