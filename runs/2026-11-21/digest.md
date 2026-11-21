# 보안 수집 요약 — 2026-11-21

수집 시각: 2026-11-21T11:37+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 7 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) — 대상: Node.js
- 원문: https://nodejs.org/en/feed/vulnerability.xml
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-21/diffs/nodejs-vuln-rss.diff` · 전체 텍스트: `state/latest/nodejs-vuln-rss.txt`

```text
<lastBuildDate>Sat, 21 Nov 2026 02:34:40 GMT</lastBuildDate>
```

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 4줄 / 삭제 4줄 · diff: `runs/2026-11-21/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`

```text
AllMicrometerMicrometer TracingReactor CoreReactor NettySpring AISpring AMQPSpring Authorization ServerSpring BatchSpring BootSpring Cloud CommonsSpring Cloud ConfigSpring Cloud Data FlowSpring Cloud FunctionSpring Cloud GatewaySpring Cloud KubernetesSpring Cloud NetflixSpring Cloud OpenFeignSpring Cloud SleuthSpring Cloud StreamSpring Cloud TaskSpring Data CommonsSpring Data ElasticsearchSpring Data JPASpring Data KeyValueSpring Data MongoDBSpring Data RelationalSpring Data RESTSpring for Apache KafkaSpring for Apache PulsarSpring for GraphQLSpring FrameworkSpring gRPCSpring HATEOASSpring IntegrationSpring LDAPSpring REST DocsSpring RetrySpring SecuritySpring SessionSpring VaultSpring Web FlowSpring Web Servicesspring-cloud-contractspring-security-oauthspring-socialspring-statemachine
| LOW | </security/cve-2026-41698> CVE-2026-41698 | Spring Vault | November 19, 2026 | 7 versions
| MEDIUM | </security/cve-2026-59351> CVE-2026-59351 | Spring Web Services | November 19, 2026 | 5 versions
| MEDIUM | </security/cve-2026-59350> CVE-2026-59350 | Spring Web Services | November 19, 2026 | 5 versions
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 2줄 / 삭제 2줄 · diff: `runs/2026-11-21/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`

```text
Online Symfony certification, take it now!
Put the code quality back at the heart of your project
```

#### Express 블로그 피드 (`express-feed`) — 대상: Express 및 미들웨어
- 원문: https://expressjs.com/feed
- 추가 15줄 / 삭제 0줄 · diff: `runs/2026-11-21/diffs/express-feed.diff` · 전체 텍스트: `state/latest/express-feed.txt`

```text
<title>Express is joining the OpenJS CNA end-of-year break</title>
<link>https://expressjs.com/en/blog/2026-11-20-joining-the-openjs-cna-end-of-year-break/</link>
<guid isPermaLink="true">https://expressjs.com/en/blog/2026-11-20-joining-the-openjs-cna-end-of-year-break/</guid>
<description>The Express security team is pausing from December 18, 2026 to January 4, 2027, alongside the OpenJS Foundation CNA.</description>
<pubDate>Fri, 20 Nov 2026 00:00:00 GMT</pubDate>
<content:encoded>
<a href="https://expressjs.com/en/blog/2026-11-20-joining-the-openjs-cna-end-of-year-break/">Express is joining the OpenJS CNA end-of-year break</a>
</content:encoded>
<author>
<name>Express Security Team</name>
<uri>https://github.com/expressjs</uri>
</author>
<category>security</category>
</item>
<item>
```

#### Python security-announce (`python-security-announce`) — 대상: CPython, pip
- 원문: https://mail.python.org/archives/list/security-announce@python.org/feed/
- 추가 23줄 / 삭제 20줄 · diff: `runs/2026-11-21/diffs/python-security-announce.diff` · 전체 텍스트: `state/latest/python-security-announce.txt`
- 오늘 처음 본 식별자: CVE-2026-133949

```text
<lastBuildDate>Fri, 20 Nov 2026 19:08:15 +0000</lastBuildDate>
<item>
<title>[Security-announce][CVE-2026-133949] pip bundles compromised eMudhra certificates via certifi</title>
<link>https://mail.python.org/archives/list/security-announce@python.org/message/4234WU4ONSVWPT3BIGG6TOJO2UFE26Y6/</link>
<description>There is a CRITICAL severity vulnerability affecting pip.
pip prior to v26.2.2 the certifi bundled with pip contains the compromised
eMudhra certificates.
Upgrading to a secure version of pip should be done either by first
upgrading Python to a version that rejects the compromised intermediates (
https://www.cve.org/CVERecord?id=CVE-2026-115557) or use hash pinning with
a known-secure version of pip.
Please see the linked CVE ID for the latest information on affected
versions:
* https://github.com/advisories/ghsa-6q48-6c7w-9gw2
*
https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
* https://www.cve.org/CVERecord?id=CVE-2026-133949
* https://github.com/pypa/pip/pull/14371
</description>
<author>seth＠python.org (Seth Larson)</author>
<pubDate>Fri, 20 Nov 2026 19:08:15 +0000</pubDate>
<guid>https://mail.python.org/archives/list/security-announce@python.org/message/4234WU4ONSVWPT3BIGG6TOJO2UFE26Y6/</guid>
</item>
```

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 828줄 / 삭제 4347줄 · diff: `runs/2026-11-21/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: GHSA-3hj7-mch7-c7cc, GHSA-f2pq-268w-886c, GHSA-r5c9-r265-ccg3, RUSTSEC-2026-0161, RUSTSEC-2026-0166, RUSTSEC-2026-0583, RUSTSEC-2026-0584, RUSTSEC-2026-0585, RUSTSEC-2026-0586, RUSTSEC-2026-0587

```text
<updated>2026-11-20T12:00:00+00:00</updated>
<entry>
<title>RUSTSEC-2026-0583: Vulnerability in sad-rsa</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0583.html</id>
<updated>2026-11-20T12:00:00+00:00</updated>
<category term="denial-of-service"/>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0583.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0583: Vulnerability in sad-rsa"/>
<published>2026-11-20T12:00:00+00:00</published>
<summary xml:lang="en">Panics during RSA private-key construction, validation, or re-encoding</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/sad-rsa/RUSTSEC-2026-0583.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/sad-rsa/RUSTSEC-2026-0583.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0583">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0583
</h1>
<span class="subtitle">
<p>Panics during RSA private-key construction, validation, or re-encoding</p>
</span>
</header>
<dl>
```

#### Kubernetes Official CVE Feed (`k8s-cve-feed`) — 대상: Kubernetes
- 원문: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-21/diffs/k8s-cve-feed.diff` · 전체 텍스트: `state/latest/k8s-cve-feed.txt`

```text
"updated_at": "2026-11-21T00:54:03Z"
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP 연도별 공지, PHP ChangeLog 8, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express Security Updates, Django Security Archive, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, .NET Announcements, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.20 · 전체 1790건 · 최근 7일 신규 9건
모든 CVE의 KEV 여부는 `state/kev_index.json`에서 조회한다.

| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |
|---|---|---|---|---|---|
| 2026-11-20 | CVE-2026-129448 | Apache / Roller | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2026-123890 | Broadcom / VMware vCenter | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2025-42884 | SAP / NetWeaver | - | Unknown | 2026-11-23 |
| 2026-11-20 | CVE-2026-76466 | Cisco / Expressway Series | - | Unknown | 2026-11-23 |
| 2026-11-18 | CVE-2024-10441 | Synology / DiskStation Manager (DSM) | - | Unknown | 2026-11-21 |
| 2026-11-18 | CVE-2026-40217 | BerriAI / LiteLLM | - | Unknown | 2026-12-02 |
| 2026-11-18 | CVE-2026-90817 | Vanderbilt University / Research Electronic Data Capture (REDCap) | - | Unknown | 2026-11-21 |
| 2026-11-18 | CVE-2026-90436 | Apache / Axis | - | Unknown | 2026-11-21 |
| 2026-11-17 | CVE-2026-115731 | Perforce / Puppet Enterprise | - | Unknown | 2026-12-01 |

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-20T03:00:55.231Z ~ 2026-11-21T02:31:40.764Z · 새 CVE 743건 · 감시 제품 해당 239건 · 기준 통과 0건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

기준 미달(보고 안 함) 제품별 건수: Linux kernel 239

## 4. 라이브러리 대조 (lock 파일 × OSV)

lock 파일 1개 · 발견 2건

### 서비스: _sample-notification-service (2건)
- body-parser 1.20.3 → 수정 1.20.9, 2.4.0 · GHSA-27r3-jxmh-p828 (CVE-2026-111181) · 7.5 · body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
- body-parser 1.20.3 → 수정 1.20.6, 2.3.0 · GHSA-v422-hmwv-36x6 (CVE-2026-12590) · 3.7 · body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

