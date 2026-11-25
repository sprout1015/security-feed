# 보안 수집 요약 — 2026-11-26

수집 시각: 2026-11-26T07:44+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.
KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.

## 0. 오늘의 변화

- 바뀐 공식 소스 4개 · 새 KEV 0건 · 레이더 대상 CVE 0건 · 라이브러리 새 항목 0건 · 해결 0건
- 조용한 날: 아니오

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 4 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 7줄 / 삭제 7줄 · diff: `runs/2026-11-26/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`

```text
| MEDIUM | </security/cve-2026-59273> CVE-2026-59273 | Spring Security | November 19, 2026 | 8 versions
| LOW | </security/cve-2026-59329> CVE-2026-59329 | Spring Security | November 19, 2026 | 8 versions
| HIGH | </security/cve-2026-59330> CVE-2026-59330 | Spring Security | November 19, 2026 | 4 versions
| HIGH | </security/cve-2026-59331> CVE-2026-59331 | Spring Security | November 19, 2026 | 8 versions
| MEDIUM | </security/cve-2026-59349> CVE-2026-59349 | Spring Web Services | November 19, 2026 | 5 versions
| MEDIUM | </security/cve-2026-59351> CVE-2026-59351 | Spring Web Services | November 19, 2026 | 5 versions
| MEDIUM | </security/cve-2026-59362> CVE-2026-59362 | Spring Integration | November 19, 2026 | 6 versions
```

#### Laravel 보안 권고 (GitHub) (`laravel-ghsa`) — 대상: Laravel
- 원문: https://github.com/laravel/framework/security/advisories
- 추가 38줄 / 삭제 0줄 · diff: `runs/2026-11-26/diffs/laravel-ghsa.diff` · 전체 텍스트: `state/latest/laravel-ghsa.txt`
- 오늘 처음 본 식별자: GHSA-c25c-x5r7-2v5m

```text
{
"cve_id": null,
"cvss": {
"score": 7.5,
"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
},
"cwe_ids": [
"CWE-770"
],
"description": "### Impact\r\n\r\nThe `multiple_of` validation rule, and the `gt`, `gte`, `lt` and `lte` rules when they compare against another numeric field, expand numeric input using arbitrary-precision arithmetic without bounding its exponent. A request containing a very small or very large exponent value, such as one in scientific notation, can cause excessive memory and CPU use and may exhaust PHP's memory limit. Applications are affected when these rules are applied to an unbounded numeric field, with no preceding bounding rule such as `min`, `max` or `between` combined with `bail`. Comparisons against literal numbers, and the `min`, `max`, `between` and `size` rules, are not affected.\r\n\r\n### Patches\r\n\r\nThe fix applies the framework's existing exponent range guard to these rules. It has been merged to the 12.x and 13.x branches: https://github.com/laravel/framework/pull/62589 and https://github.com/laravel/framework/pull/62590.\r\n\r\n### Workarounds\r\n\r\nBound the value before the affected rule and stop on failure, for example `bail|numeric|min:0|max:100|multiple_of:2`. Setting a low PHP memory limit can also make PHP stop early with a fatal error.",
"ghsa_id": "GHSA-c25c-x5r7-2v5m",
"html_url": "https://github.com/laravel/framework/security/advisories/GHSA-c25c-x5r7-2v5m",
"published_at": "2026-11-25T09:13:14Z",
"severity": "high",
"summary": "Numeric validation can exhaust resources via extreme exponent input",
"updated_at": "2026-11-25T10:00:36Z",
"vulnerabilities": [
{
"package": {
"ecosystem": "composer",
"name": "laravel/framework"
},
"patched_versions": ">=12.74.0",
"vulnerable_functions": [],
"vulnerable_version_range": "<12.74.0"
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 42줄 / 삭제 42줄 · diff: `runs/2026-11-26/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`
- 오늘 처음 본 식별자: CVE-2017-16652, CVE-2026-121373, CVE-2026-133756, CVE-2026-133757, CVE-2026-133758, CVE-2026-133759, CVE-2026-133760, CVE-2026-133761, CVE-2026-133762, CVE-2026-134790, CVE-2026-134791, CVE-2026-134792

```text
CVE-2026-134792 HttpClient Lets the Proxy Header of a Request Choose the Proxy of Outgoing Requests in CLI-SAPI HTTP Workers
HttpClient Lets the Proxy Header of a Request Choose the Proxy of Outgoing Requests in CLI-SAPI HTTP Workers
November 25, 2026
#Symfony
CVE-2026-134791 Unclosed Comments Make the Lexer of ExpressionLanguage Quadratic, Letting Untrusted Expressions Hold a Process
Unclosed Comments Make the Lexer of ExpressionLanguage Quadratic, Letting Untrusted Expressions Hold a Process
November 25, 2026
#Symfony
CVE-2026-134790 Login Redirects Can Still Reach Another Host When the Session Cookie Domain Is Set: Incomplete Fix for CVE-2017-16652
Login Redirects Can Still Reach Another Host When the Session Cookie Domain Is Set: Incomplete Fix for CVE-2017-16652
November 25, 2026
#Symfony
CVE-2026-133762 Without APP_RUNTIME_MODE, HTTP Workers Running Under the CLI SAPI Return Full Exception Dumps in Production
Without APP_RUNTIME_MODE, HTTP Workers Running Under the CLI SAPI Return Full Exception Dumps in Production
November 25, 2026
#Symfony
CVE-2026-133761 CsvEncoder Nests Rows Once per Key Separator of a Header, Letting a Small CSV Payload Crash PHP
CsvEncoder Nests Rows Once per Key Separator of a Header, Letting a Small CSV Payload Crash PHP
November 25, 2026
#Symfony
CVE-2026-133760 Nested Short Ternaries Make the Nesting Check of the Expression Parser Exponential, Letting Expressions Hang It
Nested Short Ternaries Make the Nesting Check of the Expression Parser Exponential, Letting Expressions Hang It
November 25, 2026
#Symfony
CVE-2026-133759 Doctrine Remember-Me Token Provider Accepts Outdated Tokens Under the Series of Their Copy, Also After Logout
```

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 147줄 / 삭제 1976줄 · diff: `runs/2026-11-26/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: GHSA-hm5x-4x3m-4w8m, RUSTSEC-2026-0600

```text
<updated>2026-11-25T12:00:00+00:00</updated>
<entry>
<title>RUSTSEC-2026-0600: Vulnerability in kube-client</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0600.html</id>
<updated>2026-11-25T12:00:00+00:00</updated>
<category term="crypto-failure"/>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0600.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0600: Vulnerability in kube-client"/>
<published>2026-11-25T12:00:00+00:00</published>
<summary xml:lang="en">`openssl-tls` trusts OpenSSL&apos;s default CA store in addition to the configured cluster CA</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/kube-client/RUSTSEC-2026-0600.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/kube-client/RUSTSEC-2026-0600.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0600">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0600
</h1>
<span class="subtitle">
<p>
<code>openssl-tls</code> trusts OpenSSL's default CA store in addition to the configured cluster CA</p>
</span>
</header>
```

### 오늘 처음 본 CVE — 공식 레코드 요약 (cve_details.json, 벤더·CVE 상세 페이지를 따로 열지 않는다)

- **CVE-2017-16652** 점수 없음  · An issue was discovered in Symfony 2.7.x before 2.7.38, 2.8.x before 2.8.31, 3.2 · 영향: n/a/n/a: n/a
- **CVE-2026-121373** MEDIUM 5.3 · Symfony: HtmlSanitizer MetaRefreshAttributeSanitizer Matches Only a Narrow Subset of the Browser Refresh Grammar (Incomplete Fix for CVE-2026-48761) · 영향: sensiolabs/symfony: 6.1.0 ~ <6.4.50, 7.0.0 ~ <7.4.23, 8.0.0 ~ <8.1.11
- **CVE-2026-133756** MEDIUM 5.3 · HtmlSanitizer Doesn't Check Meta Refresh URLs Whose Time Follows a Vertical Tab or a Unicode Space: Incomplete Fix for CVE-2026-121373 · 영향: Symfony/symfony/html-sanitizer: 6.1.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 6.1.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-133757** HIGH 8.2 · NoPrivateNetworkHttpClient Sends the Default Credentials of the Client It Decorates to Other Origins on Redirects · 영향: Symfony/symfony/http-client: 5.4.48 ~ <5.4.57, 6.4.16 ~ <6.4.51, 7.1.9 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 5.4.48 ~ <5.4.57, 6.4.16 ~ <6.4.51, 7.1.9 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-133758** MEDIUM 6.3 · NoPrivateNetworkHttpClient Makes the Client It Decorates Ignore Its Own Default Options, Like Certificate Pinning · 영향: Symfony/symfony/http-client: 5.4.48 ~ <5.4.57, 6.4.16 ~ <6.4.51, 7.1.9 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 5.4.48 ~ <5.4.57, 6.4.16 ~ <6.4.51, 7.1.9 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-133759** MEDIUM 6.3 · Doctrine Remember-Me Token Provider Accepts Outdated Tokens Under the Series of Their Copy, Also After Logout · 영향: Symfony/symfony/doctrine-bridge: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-133760** HIGH 8.7 · Nested Short Ternaries Make the Nesting Check of the Expression Parser Exponential, Letting Untrusted Expressions Hang It · 영향: Symfony/symfony/expression-language: 5.4.54 ~ <5.4.57, 6.4.48 ~ <6.4.51, 7.4.21 ~ <7.4.24, 8.1.9 ~ <8.1.12; Symfony/symfony/symfony: 5.4.54 ~ <5.4.57, 6.4.48 ~ <6.4.51, 7.4.21 ~ <7.4.24, 8.1.9 ~ <8.1.12
- **CVE-2026-133761** HIGH 8.7 · CsvEncoder Nests Rows Once per Key Separator of a Header, Letting a Small CSV Payload Crash PHP · 영향: Symfony/symfony/serializer: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-133762** MEDIUM 6.0 · Without APP_RUNTIME_MODE, HTTP Workers Running Under the CLI SAPI Return Full Exception Dumps in Production · 영향: Symfony/symfony/framework-bundle: 7.4.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 7.4.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-134790** MEDIUM 5.3 · Login Redirects Can Still Reach Another Host When the Session Cookie Domain Is Set: Incomplete Fix for CVE-2017-16652 · 영향: Symfony/symfony/security-http: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-134791** HIGH 8.7 · Unclosed Comments Make the Lexer of ExpressionLanguage Quadratic, Letting Untrusted Expressions Hold a Process · 영향: Symfony/symfony/expression-language: 7.2.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 7.2.0 ~ <7.4.24, 8.0.0 ~ <8.1.12
- **CVE-2026-134792** HIGH 8.3 · HttpClient Lets the Proxy Header of a Request Choose the Proxy of Outgoing Requests in HTTP Workers That Run Under the CLI SAPI · 영향: Symfony/symfony/http-client: 4.3.0 ~ <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12; Symfony/symfony/symfony: 4.3.0 ~ <5.4.57, 6.0.0 ~ <6.4.51, 7.0.0 ~ <7.4.24, 8.0.0 ~ <8.1.12

### 형식만 바뀜 (시각·배너 등. 판단 불필요, 읽지 않는다)

Oracle Security Alerts (`oracle-alerts`), Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`), PHP 연도별 공지 (`php-archive`), Django Security Archive (`django-security`), nginx Security Advisories (`nginx-advisories`), Kubernetes Official CVE Feed (`k8s-cve-feed`)

### 변화 없음

Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP ChangeLog 8, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, .NET Announcements, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.24 · 전체 1795건 · 최근 7일 신규 9건
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

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-25T00:59:10.732Z ~ 2026-11-25T22:38:04.707Z · 새 CVE 592건 · 감시 제품 해당 9건 · 기준 통과 0건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

기준 미달(보고 안 함) 제품별 건수: Linux kernel 7, 컨테이너 런타임 2

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 5f73a69 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 4개 · 발견 0건

### 서비스: alpha-match (0건 · 패키지 1014개 · lock 4개)
전체: 패키지 0개에 권고 0건 · CVSS 7.0 이상 패키지 0개

**새로 생김 (기준 2026-11-25 대비, 0개)** — 루틴은 이것만 새로 판단한다
- 없음

**해결됨 (0개)**
- 없음

