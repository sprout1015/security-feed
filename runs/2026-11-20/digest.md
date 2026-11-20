# 보안 수집 요약 — 2026-11-20

수집 시각: 2026-11-20T12:14+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 0 · 실패 0

### 처음 수집한 소스 (비교 기준만 저장, 새 항목으로 세지 않음)

- Oracle Security Alerts (`oracle-alerts`) · 식별자 10개 · `state/latest/oracle-alerts.txt`
- Oracle Security Alerts RSS (`oracle-rss`) · 식별자 30개 · `state/latest/oracle-rss.txt`
- OpenJDK Vulnerability Advisories (`openjdk-advisories`) · 식별자 0개 · `state/latest/openjdk-advisories.txt`
- Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) · 식별자 2개 · `state/latest/nodejs-vuln-rss.txt`
- Node.js 보안 릴리스 블로그 (`nodejs-vuln-blog`) · 식별자 0개 · `state/latest/nodejs-vuln-blog.txt`
- PHP 연도별 공지 (`php-archive`) · 식별자 6개 · `state/latest/php-archive.txt`
- PHP ChangeLog 8 (`php-changelog-8`) · 식별자 179개 · `state/latest/php-changelog-8.txt`
- PHP php-src 보안 권고 (`php-src-ghsa`) · 식별자 106개 · `state/latest/php-src-ghsa.txt`
- Spring Security Advisories (`spring-security`) · 식별자 25개 · `state/latest/spring-security.txt`
- Apache Tomcat 9 Security (`tomcat-9`) · 식별자 173개 · `state/latest/tomcat-9.txt`
- Apache Tomcat 10 Security (`tomcat-10`) · 식별자 124개 · `state/latest/tomcat-10.txt`
- Apache Tomcat 11 Security (`tomcat-11`) · 식별자 104개 · `state/latest/tomcat-11.txt`
- Apache Log4j Security (`log4j-security`) · 식별자 29개 · `state/latest/log4j-security.txt`
- Laravel 보안 권고 (Packagist) (`laravel-packagist`) · 식별자 47개 · `state/latest/laravel-packagist.txt`
- Laravel 보안 권고 (GitHub) (`laravel-ghsa`) · 식별자 41개 · `state/latest/laravel-ghsa.txt`
- Symfony Security Advisories (`symfony-advisories`) · 식별자 12개 · `state/latest/symfony-advisories.txt`
- Next.js 보안 권고 (`nextjs-ghsa`) · 식별자 101개 · `state/latest/nextjs-ghsa.txt`
- Express 블로그 피드 (`express-feed`) · 식별자 1개 · `state/latest/express-feed.txt`
- Express Security Updates (`express-security-updates`) · 식별자 18개 · `state/latest/express-security-updates.txt`
- Django Security Archive (`django-security`) · 식별자 175개 · `state/latest/django-security.txt`
- Python security-announce (`python-security-announce`) · 식별자 33개 · `state/latest/python-security-announce.txt`
- Ruby 뉴스 피드 (`ruby-news`) · 식별자 18개 · `state/latest/ruby-news.txt`
- Rails Security Announcements (`rails-security`) · 식별자 68개 · `state/latest/rails-security.txt`
- Go Vulnerability Database (`go-vulndb`) · 식별자 13665개 · `state/latest/go-vulndb.txt`
- .NET Announcements (`dotnet-announcements`) · 식별자 24개 · `state/latest/dotnet-announcements.txt`
- RustSec Advisory Database (`rustsec-feed`) · 식별자 191개 · `state/latest/rustsec-feed.txt`
- nginx Security Advisories (`nginx-advisories`) · 식별자 77개 · `state/latest/nginx-advisories.txt`
- Apache HTTP Server 2.4 Vulnerabilities (`httpd-24`) · 식별자 185개 · `state/latest/httpd-24.txt`
- OpenSSL Vulnerabilities (`openssl-vulns`) · 식별자 308개 · `state/latest/openssl-vulns.txt`
- PostgreSQL Security Information (`postgresql-security`) · 식별자 118개 · `state/latest/postgresql-security.txt`
- Redis 보안 권고 (`redis-ghsa`) · 식별자 92개 · `state/latest/redis-ghsa.txt`
- Kubernetes Official CVE Feed (`k8s-cve-feed`) · 식별자 99개 · `state/latest/k8s-cve-feed.txt`

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.18 · 전체 1786건 · 최근 7일 신규 7건
모든 CVE의 KEV 여부는 `state/kev_index.json`에서 조회한다.

| 등재일 | CVE | 벤더 / 제품 | 감시 목록 | 랜섬웨어 | 조치 기한 |
|---|---|---|---|---|---|
| 2026-11-18 | CVE-2024-10441 | Synology / DiskStation Manager (DSM) | - | Unknown | 2026-11-21 |
| 2026-11-18 | CVE-2026-40217 | BerriAI / LiteLLM | - | Unknown | 2026-12-02 |
| 2026-11-18 | CVE-2026-90817 | Vanderbilt University / Research Electronic Data Capture (REDCap) | - | Unknown | 2026-11-21 |
| 2026-11-18 | CVE-2026-90436 | Apache / Axis | - | Unknown | 2026-11-21 |
| 2026-11-17 | CVE-2026-115731 | Perforce / Puppet Enterprise | - | Unknown | 2026-12-01 |
| 2026-11-13 | CVE-2026-114713 | UnrealIRCd / UnrealIRCd | - | Unknown | 2026-11-16 |
| 2026-11-13 | CVE-2026-123039 | Check Point / Multiple Products | - | Unknown | 2026-11-16 |

## 3. 새 CVE 레이더 (CVE.org 공식 목록)

대상 구간(UTC) 2026-11-19T03:14:23 ~ 2026-11-20T03:00:55.231Z · 새 CVE 1046건 · 감시 제품 해당 275건 · 기준 통과 22건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

### 인벤토리 제품

- **CVE-2026-115560** [PHP] CVSS 9.2 · Session serializer mismatch can lead to remote code execution
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-115560
- **CVE-2026-126714** [PHP] CVSS 9.2 · Partially overwritten session files can lead to remote code execution
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-126714
- **CVE-2026-129182** [PHP] CVSS 9.2 · Use-after-free via repopulation of last_fatal_error_backtrace global after shutdown
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129182
- **CVE-2026-129289** [PHP] CVSS 9.2 · PHP-FPM request smuggling through an unread HTTP request body
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129289
- **CVE-2026-129474** [PHP] CVSS 9.2 · Use-after-free in magic method backtraces can lead to remote code execution
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129474
- **CVE-2026-129481** [PHP] CVSS 9.2 · Use-after-free after interrupted session shutdown
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129481
- **CVE-2026-129496** [PHP] CVSS 9.2 · Timezone cache use-after-free can lead to remote code execution
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129496
- **CVE-2026-129291** [PHP] CVSS 8.8 (인벤토리 제품) · PHP-FPM epoll use-after-free can lead to local privilege escalation
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-129291
- **CVE-2026-127960** [PHP] CVSS 8.7 (인벤토리 제품) · Denial of service through folded HTTP response headers
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-127960
- **CVE-2026-128064** [PHP] CVSS 8.2 (인벤토리 제품) · Mixed-case HTTPS and FTPS URLs can expose data in plaintext
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-128064
- **CVE-2026-128090** [PHP] CVSS 7.7 (인벤토리 제품) · PHAR OpenSSL signature bypass via algorithm downgrade
  - 영향 제품: PHP Group / PHP · https://www.cve.org/CVERecord?id=CVE-2026-128090
- **CVE-2026-121649** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: ExpiresFilter removes existing Cache-Control: private header
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-121649
- **CVE-2026-133325** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Cluster TLS-PSK configured to use TLS 1.3 does not validate peer
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-133325
- **CVE-2026-118233** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Memory leak on HTTP upgrade leads to DoS
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-118233
- **CVE-2026-118436** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: CGIServlet drops chunked POST body and can hang worker thread
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-118436
- **CVE-2026-116561** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Jakarta Authentication secureResponse AuthException sends unprotected HTTP 200 response
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-116561
- **CVE-2026-116600** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Memory leak with OWB integration leads to DoS
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-116600
- **CVE-2026-116830** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: HTTP/2 checks frame type before size leads to DoS
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-116830
- **CVE-2026-117517** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Fix for CVE-2026-25854 was incomplete
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-117517
- **CVE-2026-118028** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: RewriteValve [F]/[G]/[R] rule matches do not stop processing
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-118028
- **CVE-2026-106012** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Incorrect security-role-ref with RequestDispatcher.forward()
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-106012
- **CVE-2026-95517** [Apache Tomcat] 인벤토리 제품, 점수 미공개 · Apache Tomcat: Multiple vulnerabilities in EncryptInterceptor
  - 영향 제품: Apache Software Foundation / Apache Tomcat · https://www.cve.org/CVERecord?id=CVE-2026-95517

기준 미달(보고 안 함) 제품별 건수: Linux kernel 246, PHP 6, glibc 1

## 4. 라이브러리 대조 (lock 파일 × OSV)

lock 파일 1개 · 발견 2건

### 서비스: _sample-notification-service (2건)
- body-parser 1.20.3 → 수정 1.20.9, 2.4.0 · GHSA-27r3-jxmh-p828 (CVE-2026-111181) · 7.5 · body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
- body-parser 1.20.3 → 수정 1.20.6, 2.3.0 · GHSA-v422-hmwv-36x6 (CVE-2026-12590) · 3.7 · body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

