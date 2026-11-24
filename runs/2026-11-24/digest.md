# 보안 수집 요약 — 2026-11-24

수집 시각: 2026-11-24T14:23+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 11 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) — 대상: Node.js
- 원문: https://nodejs.org/en/feed/vulnerability.xml
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/nodejs-vuln-rss.diff` · 전체 텍스트: `state/latest/nodejs-vuln-rss.txt`

```text
<lastBuildDate>Tue, 24 Nov 2026 05:22:10 GMT</lastBuildDate>
```

#### Spring Security Advisories (`spring-security`) — 대상: Spring Framework, Spring Boot
- 원문: https://spring.io/security/
- 추가 2줄 / 삭제 2줄 · diff: `runs/2026-11-24/diffs/spring-security.diff` · 전체 텍스트: `state/latest/spring-security.txt`
- 오늘 처음 본 식별자: CVE-2026-59364

```text
| MEDIUM | </security/cve-2026-59273> CVE-2026-59273 | Spring Security | November 19, 2026 | 8 versions
| MEDIUM | </security/cve-2026-59364> CVE-2026-59364 | Spring Integration | November 19, 2026 | 7 versions
```

#### Laravel 보안 권고 (GitHub) (`laravel-ghsa`) — 대상: Laravel
- 원문: https://github.com/laravel/framework/security/advisories
- 추가 72줄 / 삭제 0줄 · diff: `runs/2026-11-24/diffs/laravel-ghsa.diff` · 전체 텍스트: `state/latest/laravel-ghsa.txt`
- 오늘 처음 본 식별자: GHSA-8h64-cpq2-9h2g, GHSA-cq3g-fj94-c8p3

```text
{
"cve_id": null,
"cvss": {
"score": 5.4,
"vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
},
"cwe_ids": [],
"description": "When validated input contains an array element whose key is an empty string, such as `{\"items\": {\"\": {\"name\": \"...\"}}}` in a JSON request, the rules attached to `items.*` are never applied to that element. `ValidationRuleParser` already matches empty segments with `[^\\.]*`, but `ValidationData::extractValuesForWildcards()` and `Validator::getExplicitKeys()` still use `[^\\.]+`, so the element is never gathered and wildcard parameters such as `required_if:users.*.role,admin` are not resolved for it. Rules like `Rule::forEach()` or `array:name,qty` on `items.*` are silently skipped for that element.",
"ghsa_id": "GHSA-cq3g-fj94-c8p3",
"html_url": "https://github.com/laravel/framework/security/advisories/GHSA-cq3g-fj94-c8p3",
"published_at": "2026-11-23T13:53:01Z",
"severity": "medium",
"summary": "Empty array key validation bypass",
"updated_at": "2026-11-23T13:53:01Z",
"vulnerabilities": [
{
"package": {
"ecosystem": "composer",
"name": "laravel/framework"
},
"patched_versions": ">=13.43.0",
"vulnerable_functions": [],
"vulnerable_version_range": "<13.43.0"
},
{
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 5줄 / 삭제 2줄 · diff: `runs/2026-11-24/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`

```text
Black Friday 2026 deals
30% off Symfony and Twig certifications
(ends in 6 days)
Black Friday: 30% off Symfony and Twig certifications with the CERTIF_30_BF26 code
Black Friday: 30% off SymfonyInsight yearly Business plans with the SFI-BLACKFRIDAY-26 code
```

#### Django Security Archive (`django-security`) — 대상: Django
- 원문: https://docs.djangoproject.com/en/dev/releases/security/
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/django-security.diff` · 전체 텍스트: `state/latest/django-security.txt`

```text
getup8 donated to the Django Software Foundation to support Django development. Donate today!
```

#### Python security-announce (`python-security-announce`) — 대상: CPython, pip
- 원문: https://mail.python.org/archives/list/security-announce@python.org/feed/
- 추가 21줄 / 삭제 54줄 · diff: `runs/2026-11-24/diffs/python-security-announce.diff` · 전체 텍스트: `state/latest/python-security-announce.txt`
- 오늘 처음 본 식별자: CVE-2026-107784

```text
<lastBuildDate>Mon, 23 Nov 2026 12:40:09 +0000</lastBuildDate>
<item>
<title>[Security-announce][CVE-2026-107784] tarfile extraction filters accept drive-relative paths on Windows</title>
<link>https://mail.python.org/archives/list/security-announce@python.org/message/ANUOLPP6MFFJ45RT6XG2BRGZPFHMGDAS/</link>
<description>There is a MEDIUM severity vulnerability affecting CPython.
On Windows, the tarfile "tar" and "data" extraction filters did not reject
member names or link targets that have a drive but no root, such as "C:foo".
When extracting to a relative destination, such a member was written to the
current working directory of that drive instead of the destination, and a
symbolic link with such a target pointed outside the destination.
The filters now refuse these member names and link targets with
AbsolutePathError and AbsoluteLinkError.
Please see the linked CVE ID for the latest information on affected
versions:
* https://www.cve.org/CVERecord?id=CVE-2026-107784
* https://github.com/python/cpython/pull/161334
</description>
<author>stanulbrych＠gmail.com (Stan Ulbrych)</author>
<pubDate>Mon, 23 Nov 2026 12:40:09 +0000</pubDate>
<guid>https://mail.python.org/archives/list/security-announce@python.org/message/ANUOLPP6MFFJ45RT6XG2BRGZPFHMGDAS/</guid>
</item>
```

#### Go Vulnerability Database (`go-vulndb`) — 대상: Go
- 원문: https://vuln.go.dev/index/vulns.json
- 추가 692줄 / 삭제 41줄 · diff: `runs/2026-11-24/diffs/go-vulndb.diff` · 전체 텍스트: `state/latest/go-vulndb.txt`
- 오늘 처음 본 식별자: CVE-2026-102339, CVE-2026-102340, CVE-2026-102657, CVE-2026-102943, CVE-2026-102945, CVE-2026-103025, CVE-2026-103033, CVE-2026-104099, CVE-2026-104129, CVE-2026-105802, CVE-2026-105803, CVE-2026-108262, CVE-2026-115578, CVE-2026-115770, CVE-2026-119298, CVE-2026-119299, CVE-2026-119345, CVE-2026-120472, CVE-2026-121716, CVE-2026-121717, CVE-2026-125323, CVE-2026-125325, CVE-2026-125326, CVE-2026-125327, CVE-2026-125328, CVE-2026-128085, CVE-2026-128086, CVE-2026-129235, CVE-2026-129236, CVE-2026-129237, CVE-2026-130007, CVE-2026-130008, CVE-2026-13318, CVE-2026-28385, CVE-2026-58208, CVE-2026-58209, CVE-2026-58210, CVE-2026-58213, CVE-2026-58214, CVE-2026-58254, CVE-2026-62284, CVE-2026-62336, CVE-2026-62361, CVE-2026-62662, CVE-2026-62683, CVE-2026-62964, CVE-2026-63197, CVE-2026-63198, CVE-2026-68903, CVE-2026-69260, CVE-2026-69261, CVE-2026-71861, CVE-2026-75506, CVE-2026-75521, CVE-2026-76101, CVE-2026-77367, CVE-2026-77369, CVE-2026-77463, CVE-2026-77596, CVE-2026-85737, CVE-2026-86041, CVE-2026-88982, CVE-2026-88983, CVE-2026-88984, CVE-2026-88985, CVE-2026-88986, CVE-2026-95839, CVE-2026-9639, GHSA-2xwh-426q-42c5, GHSA-358w-w75h-x6rx, GHSA-3gq2-x4qg-p4g6, GHSA-47w9-6r3f-938g, GHSA-4g68-3pwx-5vfj, GHSA-4hrh-34w3-5ww8, GHSA-4xr6-hc3h-f6jq, GHSA-56x6-q882-mf27, GHSA-5m6c-38r8-5w76, GHSA-5qg5-rgp6-j5m5, GHSA-5w5g-j6hw-6p8f, GHSA-68g8-gh8f-7rhg, GHSA-6j3h-rp73-6rvf, GHSA-7hvw-3c2q-45qg, GHSA-7mr3-28h5-m5vx, GHSA-7qmq-8cc4-hxwg, GHSA-7rj6-7pqx-v7rm, GHSA-8835-xmqj-354h, GHSA-8cfq-jgf7-8m27, GHSA-8fh7-7q4q-cq52, GHSA-8gwq-33fg-g56p, GHSA-8vf2-hxg5-crqh, GHSA-99h8-29cw-6j59, GHSA-9hq4-hm3j-jmph, GHSA-9j25-mm2h-2f76, GHSA-9qq5-422f-33c2, GHSA-cgm6-wvp9-4g5h, GHSA-f7vj-6669-qvv4, GHSA-fmc8-p6q7-75cc, GHSA-g2rq-85pp-c2j9, GHSA-g3c2-rjq2-c763, GHSA-g3qx-frcg-j979, GHSA-gfwj-45pc-w6r5, GHSA-ghgh-57qv-h687, GHSA-ghwv-vrp2-2975, GHSA-gj7r-p794-hhq5, GHSA-hghq-53p7-c582, GHSA-hq2p-f2vj-v3cm, GHSA-j282-pjg5-j643, GHSA-j8j4-rw65-56r6, GHSA-j93m-3j9p-m5m8, GHSA-jpf8-86f3-wp38, GHSA-jw3m-8q7m-f35r, GHSA-m932-63jc-4jqq, GHSA-p3j5-5hrq-p75h, GHSA-p45x-hwmp-fvrj, GHSA-p74g-f95m-7fx7, GHSA-p957-7v2w-g93g, GHSA-pjff-c2wc-f6jm, GHSA-pp88-jhwj-5qh5, GHSA-q433-mp6c-8v4f, GHSA-q4xm-p75h-h9p3, GHSA-q7gw-24fr-5p69, GHSA-qrcv-3558-gj4f, GHSA-qx75-2p3r-pwm5, GHSA-r4mx-2gr2-8277, GHSA-r72h-j7qq-v6qg, GHSA-rjr3-43j3-4q8g, GHSA-rm8c-2cv8-jwf6, GHSA-rrfc-gjm9-cgrj, GHSA-v6w5-38cf-pcv8, GHSA-v9v2-98xq-627c, GHSA-vc6p-m6vx-6cwq, GHSA-vghh-5rfx-xhq8, GHSA-vq9p-w6wv-cr25, GHSA-vwhp-8p66-mq4f, GHSA-vx32-xf7g-9ghr, GHSA-w278-32qg-48q5, GHSA-w3f2-pr6x-wwjc, GHSA-w42c-h7hr-f67p, GHSA-w437-9mwm-j6vq, GHSA-w6x2-f5m4-xw82, GHSA-wchh-mrv2-5h4q, GHSA-wj7x-58c2-5793, GHSA-wq26-3j2m-4hvv, GHSA-x2qr-3j78-f43f, GHSA-x527-x647-q7gg, GHSA-x72p-hmqp-46hw, GHSA-x7xj-4j4f-88xr, GHSA-x89h-7h96-v88f, GHSA-xgjr-7j9q-2h4r, GHSA-xhv5-8fpq-g7hf, GHSA-xrgv-7vx6-5vx6, GO-2026-6927, GO-2026-6928, GO-2026-6929, GO-2026-6930, GO-2026-6931, GO-2026-6932, GO-2026-6933, GO-2026-6934, GO-2026-6935, GO-2026-6936, GO-2026-6937, GO-2026-6938, GO-2026-6940, GO-2026-6941, GO-2026-6943, GO-2026-6944, GO-2026-6945, GO-2026-6946, GO-2026-6947, GO-2026-6948, GO-2026-6949, GO-2026-6950, GO-2026-6951, GO-2026-6952, GO-2026-6953, GO-2026-6954, GO-2026-6955, GO-2026-6956, GO-2026-6957, GO-2026-6958, GO-2026-6959, GO-2026-6960, GO-2026-6963, GO-2026-6964, GO-2026-6965, GO-2026-6969, GO-2026-6970, GO-2026-6971, GO-2026-6972, GO-2026-6973, GO-2026-6974, GO-2026-6975, GO-2026-6977, GO-2026-6978, GO-2026-6984, GO-2026-6985, GO-2026-6986, GO-2026-6987, GO-2026-6989, GO-2026-6990, GO-2026-6991, GO-2026-6992, GO-2026-6994, GO-2026-6995, GO-2026-6996, GO-2026-6997, GO-2026-6999, GO-2026-7000, GO-2026-7002, GO-2026-7003, GO-2026-7004, GO-2026-7005, GO-2026-7006, GO-2026-7007, GO-2026-7008, GO-2026-7009, GO-2026-7010, GO-2026-7011, GO-2026-7012, GO-2026-7013, GO-2026-7014, GO-2026-7015, GO-2026-7016, GO-2026-7017, GO-2026-7018, GO-2026-7019, GO-2026-7020, GO-2026-7021, GO-2026-7022, GO-2026-7023, GO-2026-7024, GO-2026-7025, GO-2026-7026, GO-2026-7029

```text
"modified": "2026-11-23T20:03:32Z"
"modified": "2026-11-23T20:02:36Z"
"modified": "2026-11-23T20:03:32Z"
"modified": "2026-11-23T20:03:47Z"
"modified": "2026-11-23T20:02:54Z"
"modified": "2026-11-23T20:02:54Z"
"modified": "2026-11-23T20:02:54Z"
"modified": "2026-11-23T20:03:27Z"
"modified": "2026-11-23T20:02:54Z"
"modified": "2026-11-23T20:02:59Z"
"modified": "2026-11-23T20:02:36Z"
"modified": "2026-11-23T20:04:05Z"
"modified": "2026-11-23T20:02:36Z"
"modified": "2026-11-23T20:02:49Z"
"modified": "2026-11-23T20:03:21Z"
"modified": "2026-11-23T20:03:16Z"
"modified": "2026-11-23T20:03:11Z"
"modified": "2026-11-23T20:03:11Z"
"CVE-2026-46595",
"GHSA-x527-x647-q7gg"
"modified": "2026-11-23T20:03:11Z"
"modified": "2026-11-23T20:03:04Z"
"modified": "2026-11-23T20:02:36Z"
"modified": "2026-11-23T20:04:20Z"
"modified": "2026-11-23T20:02:31Z"
```

#### .NET Announcements (`dotnet-announcements`) — 대상: .NET, ASP.NET Core
- 원문: https://github.com/dotnet/announcements/issues?q=is%3Aissue+label%3ASecurity
- 추가 27줄 / 삭제 27줄 · diff: `runs/2026-11-24/diffs/dotnet-announcements.diff` · 전체 텍스트: `state/latest/dotnet-announcements.txt`

```text
Microsoft Security Advisory CVE-2026-114150 - ASP.NET Core Information Disclosure Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#514 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-118750 - ASP.NET Core Denial of Service Vulnerability
Patch-TuesdaySecurity
dotnet/announcements#512 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114149 - ASP.NET Core Denial of Service Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#511 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
November 2026 ASP.NET Core security updates
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#504 · Filter by author bribrothers opened on Nov 10, 2026
Microsoft Security Advisory CVE-2026-109481 - ASP.NET Core Elevation of Privilege Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#506 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-114157 - ASP.NET Core Security Feature Bypass Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#507 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-118749 - ASP.NET Core Denial of Service Vulnerability
.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#505 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-109476 - ASP.NET Core Information Disclosure Vulnerability
.NET 8.0.NET 9.0.NET 10.0.NET 11.0Patch-TuesdaySecurity
dotnet/announcements#508 · by Filter by author bribrothers was closed on Nov 10, 2026 · Duplicate
Microsoft Security Advisory CVE-2026-109475 - .NET Denial of Service Vulnerability
```

#### RustSec Advisory Database (`rustsec-feed`) — 대상: Rust 크레이트
- 원문: https://rustsec.org/feed.xml
- 추가 441줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/rustsec-feed.diff` · 전체 텍스트: `state/latest/rustsec-feed.txt`
- 오늘 처음 본 식별자: CVE-2026-125651, GHSA-8m2j-rv5j-c94f, GHSA-8wcq-xq25-7fhm, RUSTSEC-2026-0594, RUSTSEC-2026-0595

```text
<updated>2026-11-23T12:00:00+00:00</updated>
<entry>
<title>RUSTSEC-2026-0595: Unsoundness in parquet</title>
<id>https://rustsec.org/advisories/RUSTSEC-2026-0595.html</id>
<updated>2026-11-23T12:00:00+00:00</updated>
<category term="crypto-failure"/>
<link href="https://rustsec.org/advisories/RUSTSEC-2026-0595.html" rel="alternate" type="text/html" title="RUSTSEC-2026-0595: Unsoundness in parquet"/>
<published>2026-11-23T12:00:00+00:00</published>
<summary xml:lang="en">Apache Arrow Rust: Bloom filters written as plaintext when writing encrypted Parquet</summary>
<content xml:lang="en" type="html">
<article>
<span class="floating-menu">
<a href="https://github.com/RustSec/advisory-db/commits/main/crates/parquet/RUSTSEC-2026-0595.md">History</a> ⋅
<a href="https://github.com/RustSec/advisory-db/edit/main/crates/parquet/RUSTSEC-2026-0595.md">Edit</a> ⋅
<a href="https://api.osv.dev/v1/vulns/RUSTSEC-2026-0595">JSON (OSV)</a>
</span>
<header>
<h1>
RUSTSEC-2026-0595
</h1>
<span class="subtitle">
<p>Apache Arrow Rust: Bloom filters written as plaintext when writing encrypted Parquet</p>
</span>
</header>
<dl>
```

#### nginx Security Advisories (`nginx-advisories`) — 대상: nginx
- 원문: https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml
- 추가 8줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/nginx-advisories.diff` · 전체 텍스트: `state/latest/nginx-advisories.txt`
- 오늘 처음 본 식별자: CVE-2026-132779

```text
<item name="Excessive CPU usage in TLS 1.3 with ssl_early_data"
severity="medium"
advisory="https://my.f5.com/manage/s/article/K000163947"
cve="2026-132779"
good="1.31.10+, 1.30.8+"
vulnerable="1.21.4-1.31.9">
</item>
cve="2026-121810"
```

#### Kubernetes Official CVE Feed (`k8s-cve-feed`) — 대상: Kubernetes
- 원문: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/k8s-cve-feed.diff` · 전체 텍스트: `state/latest/k8s-cve-feed.txt`

```text
"updated_at": "2026-11-24T01:09:06Z"
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP 연도별 공지, PHP ChangeLog 8, PHP php-src 보안 권고, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Ruby 뉴스 피드, Rails Security Announcements, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고

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

대상 구간(UTC) 2026-11-23T01:38:59.224Z ~ 2026-11-24T05:17:02.080Z · 새 CVE 479건 · 감시 제품 해당 4건 · 기준 통과 2건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

### 인벤토리 제품

- **CVE-2026-123886** [Spring] CVSS 8.8 (인벤토리 제품) · Spring Data Elasticsearch SpEL Expression Injection through String-based Query Method Arguments
  - 영향 제품: Spring / Spring Data Elasticsearch · https://www.cve.org/CVERecord?id=CVE-2026-123886
- **CVE-2026-59442** [Spring] CVSS 7.5 (인벤토리 제품) · Broken Logical Grouping Expression in TypesenseFilterExpressionConverter
  - 영향 제품: Spring / Spring AI · https://www.cve.org/CVERecord?id=CVE-2026-59442

기준 미달(보고 안 함) 제품별 건수: nginx 1, Spring 1

## 4. 라이브러리 대조 (lock 파일 × OSV)

lock 파일 1개 · 발견 2건

### 서비스: _sample-notification-service (2건)
- body-parser 1.20.3 → 수정 1.20.9, 2.4.0 · GHSA-27r3-jxmh-p828 (CVE-2026-111181) · 7.5 · body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
- body-parser 1.20.3 → 수정 1.20.6, 2.3.0 · GHSA-v422-hmwv-36x6 (CVE-2026-12590) · 3.7 · body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

