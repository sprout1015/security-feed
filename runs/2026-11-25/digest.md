# 보안 수집 요약 — 2026-11-25

수집 시각: 2026-11-25T09:43+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.
KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.

## 0. 오늘의 변화

- 바뀐 공식 소스 7개 · 새 KEV 3건 (CVE-2026-132224, CVE-2026-131914, CVE-2026-132165) · 레이더 대상 CVE 0건 · 라이브러리 새 항목 0건 · 해결 0건
- 조용한 날: 아니오

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 7 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) — 대상: Node.js
- 원문: https://nodejs.org/en/feed/vulnerability.xml
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-25/diffs/nodejs-vuln-rss.diff` · 전체 텍스트: `state/latest/nodejs-vuln-rss.txt`

```text
<lastBuildDate>Wed, 25 Nov 2026 00:39:44 GMT</lastBuildDate>
```

#### PHP ChangeLog 8 (`php-changelog-8`) — 대상: PHP 8.x
- 원문: https://www.php.net/ChangeLog-8.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-25/diffs/php-changelog-8.diff` · 전체 텍스트: `state/latest/php-changelog-8.txt`

```text
PHP Conference Kansai 2026 (JAPAN)
```

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 7줄 / 삭제 7줄 · diff: `runs/2026-11-25/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`
- 오늘 처음 본 식별자: CVE-2026-59365, CVE-2026-59367, CVE-2026-59368

```text
AllMicrometerMicrometer TracingReactor CoreReactor NettySpring AISpring AMQPSpring Authorization ServerSpring BatchSpring BootSpring Cloud CommonsSpring Cloud ConfigSpring Cloud Data FlowSpring Cloud FunctionSpring Cloud GatewaySpring Cloud KubernetesSpring Cloud NetflixSpring Cloud OpenFeignSpring Cloud SleuthSpring Cloud StreamSpring Cloud TaskSpring Data CommonsSpring Data ElasticsearchSpring Data JPASpring Data KeyValueSpring Data MongoDBSpring Data RelationalSpring Data RESTSpring for Apache KafkaSpring for GraphQLSpring FrameworkSpring gRPCSpring HATEOASSpring IntegrationSpring LDAPSpring REST DocsSpring RetrySpring SecuritySpring SessionSpring VaultSpring Web FlowSpring Web Servicesspring-cloud-contractspring-pulsarspring-security-oauthspring-socialspring-statemachine
| HIGH | </security/cve-2026-59344> CVE-2026-59344 | Spring AI | November 19, 2026 | 4 versions
| MEDIUM | </security/cve-2026-59351> CVE-2026-59351 | Spring Web Services | November 19, 2026 | 5 versions
| MEDIUM | </security/cve-2026-59364> CVE-2026-59364 | Spring Integration | November 19, 2026 | 7 versions
| MEDIUM | </security/cve-2026-59365> CVE-2026-59365 | Spring Integration | November 19, 2026 | 7 versions
| CRITICAL | </security/cve-2026-59367> CVE-2026-59367 | Spring LDAP | November 19, 2026 | 7 versions
| MEDIUM | </security/cve-2026-59368> CVE-2026-59368 | Spring LDAP | November 19, 2026 | 6 versions
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 35줄 / 삭제 35줄 · diff: `runs/2026-11-25/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`
- 오늘 처음 본 식별자: CVE-2026-133764, CVE-2026-133765, CVE-2026-133766, CVE-2026-133767, CVE-2026-133768, CVE-2026-133769, CVE-2026-133770, CVE-2026-133771, CVE-2026-133772, CVE-2026-133773

```text
30% off Symfony and Twig certifications
(ends in 5 days)
CVE-2026-133773 Unbounded Converter Memoisation in twig/markdown-extra Keyed on Template-Controlled Options
Unbounded Converter Memoisation in twig/markdown-extra Keyed on Template-Controlled Options
#Twig
CVE-2026-133772 Sandbox Tag Allow-List Bypass via the Branch of a `guard` Tag That Isn't Selected
Sandbox Tag Allow-List Bypass via the Branch of a `guard` Tag That Isn't Selected
#Twig
CVE-2026-133771 Missing autoescaping for a variable named like a macro import alias of another scope
Missing autoescaping for a variable named like a macro import alias of another scope
#Twig
CVE-2026-133770 Sandboxed templates can rewrite application-owned `Markup` objects through their constructor
Sandboxed templates can rewrite application-owned `Markup` objects through their constructor
#Twig
CVE-2026-133769 Sandbox property allow-list bypass via `html_cva()` variant values
Sandbox property allow-list bypass via `html_cva()` variant values
#Twig
CVE-2026-133768 Sandbox property allow-list bypass via the `join` filter on non-iterable objects
Sandbox property allow-list bypass via the `join` filter on non-iterable objects
#Twig
CVE-2026-133767 Sandbox allow-list and `__toString()` bypass via a dynamic `embed` parent expression
Sandbox allow-list and `__toString()` bypass via a dynamic `embed` parent expression
#Twig
CVE-2026-133766 Sandbox `__toString()` policy bypass via spread arguments
Sandbox `__toString()` policy bypass via spread arguments
```

#### Go Vulnerability Database (`go-vulndb`) — 대상: Go
- 원문: https://vuln.go.dev/index/vulns.json
- 추가 16줄 / 삭제 15줄 · diff: `runs/2026-11-25/diffs/go-vulndb.diff` · 전체 텍스트: `state/latest/go-vulndb.txt`
- 오늘 처음 본 식별자: CVE-2026-12681

```text
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"CVE-2026-12681",
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
"modified": "2026-11-24T15:56:00Z"
```

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 146줄 / 삭제 0줄 · diff: `runs/2026-11-25/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: CVE-2026-61727, GHSA-7jmw-29gc-ffx4, RUSTSEC-2026-0599

```text
<p id="license" class="license">Advisory available under <a href="https://spdx.org/licenses/CC0-1.0.html">CC0-1.0</a>
license.
</p>
</article>
</content>
</entry>
<entry>
<title>RUSTSEC-2026-0599: Vulnerability in xmloxide</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0599.html</id>
<updated>2026-11-24T12:00:00+00:00</updated>
<category term="denial-of-service"/>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0599.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0599: Vulnerability in xmloxide"/>
<published>2026-11-24T12:00:00+00:00</published>
<summary xml:lang="en">Stack overflow from unbounded recursion in DTD content-model parsing</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/xmloxide/RUSTSEC-2026-0599.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/xmloxide/RUSTSEC-2026-0599.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0599">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0599
</h1>
```

#### Kubernetes Official CVE Feed (`k8s-cve-feed`) — 대상: Kubernetes
- 원문: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-25/diffs/k8s-cve-feed.diff` · 전체 텍스트: `state/latest/k8s-cve-feed.txt`

```text
"updated_at": "2026-11-24T23:15:06Z"
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP 연도별 공지, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, .NET Announcements, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

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

대상 구간(UTC) 2026-11-24T12:03:10.839Z ~ 2026-11-25T00:34:43.861Z · 새 CVE 699건 · 감시 제품 해당 0건 · 기준 통과 0건 · EPSS 조회 skipped
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): error · 공개 여부 확인 실패
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

skipped: inventory/ 아래에 lock 파일이 없음

