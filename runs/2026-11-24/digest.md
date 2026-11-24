# 보안 수집 요약 — 2026-11-24

수집 시각: 2026-11-24T21:08+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.
KEV 대조는 kev_lookup.json(오늘 자료에 나온 CVE만)을 쓴다. kev_index.json·library_matches.json 은 크므로 통째로 읽지 않는다.

## 0. 오늘의 변화

- 바뀐 공식 소스 5개 · 새 KEV 2건 (CVE-2026-133968, CVE-2026-134624) · 레이더 대상 CVE 0건 · 라이브러리 새 항목 76건 · 해결 0건
- 조용한 날: 아니오

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 5 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### Node.js 보안 릴리스 RSS (`nodejs-vuln-rss`) — 대상: Node.js
- 원문: https://nodejs.org/en/feed/vulnerability.xml
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/nodejs-vuln-rss.diff` · 전체 텍스트: `state/latest/nodejs-vuln-rss.txt`

```text
<lastBuildDate>Tue, 24 Nov 2026 12:03:15 GMT</lastBuildDate>
```

#### PHP 연도별 공지 (`php-archive`) — 대상: PHP
- 원문: https://www.php.net/archive/{year}.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/php-archive.diff` · 전체 텍스트: `state/latest/php-archive.txt`

```text
Date: May 29-30, 2025
```

#### Symfony Security Advisories (`symfony-advisories`) — 대상: Symfony, Twig
- 원문: https://symfony.com/blog/category/security-advisories
- 추가 2줄 / 삭제 2줄 · diff: `runs/2026-11-24/diffs/symfony-advisories.diff` · 전체 텍스트: `state/latest/symfony-advisories.txt`

```text
30% off SymfonyInsight yearly Business plans
Symfony Code Performance Profiling
```

#### Express 블로그 피드 (`express-feed`) — 대상: Express 및 미들웨어
- 원문: https://expressjs.com/feed
- 추가 23줄 / 삭제 0줄 · diff: `runs/2026-11-24/diffs/express-feed.diff` · 전체 텍스트: `state/latest/express-feed.txt`

```text
<title>Contributing to Express in 2026 and beyond: where to start</title>
<link>https://expressjs.com/en/blog/contributing-to-express/</link>
<guid isPermaLink="true">https://expressjs.com/en/blog/contributing-to-express/</guid>
<description>A guide to help you start contributing to Express, with advice from people who started recently and from the people who review contributions.</description>
<pubDate>Tue, 24 Nov 2026 00:00:00 GMT</pubDate>
<content:encoded>
<a href="https://expressjs.com/en/blog/contributing-to-express/">Contributing to Express in 2026 and beyond: where to start</a>
</content:encoded>
<author>
<name>Efe Karasakal</name>
<uri>https://github.com/efekrskl</uri>
</author>
<author>
<name>Sebastian Beltran</name>
<uri>https://github.com/bjohansebas</uri>
</author>
<author>
<name>Ulises Gascon</name>
<uri>https://github.com/UlisesGascon</uri>
</author>
<category>community</category>
</item>
<item>
```

#### PostgreSQL Security Information (`postgresql-security`) — 대상: PostgreSQL
- 원문: https://www.postgresql.org/support/security/
- 추가 1줄 / 삭제 0줄 · diff: `runs/2026-11-24/diffs/postgresql-security.diff` · 전체 텍스트: `state/latest/postgresql-security.txt`

```text
Daniel Gustafsson
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 블로그, PHP ChangeLog 8, PHP php-src 보안 권고, Spring Security Advisories, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Next.js 보안 권고, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, .NET Announcements, RustSec Advisory Database, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, Redis 보안 권고, Kubernetes Official CVE Feed

## 2. CISA KEV (실제 악용 중)

카탈로그 2026.11.23 · 전체 1792건 · 최근 7일 신규 11건
모든 CVE의 KEV 여부는 `runs/D/kev_lookup.json`에서 조회한다(오늘 자료에 나온 CVE만 담김).

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

대상 구간(UTC) 2026-11-24T11:14:37.586Z ~ 2026-11-24T12:03:10.839Z · 새 CVE 23건 · 감시 제품 해당 1건 · 기준 통과 0건 · EPSS 조회 ok
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

기준 미달(보고 안 함) 제품별 건수: OpenSSL 1

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 59ffc51 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 4개 · 발견 288건

### 서비스: alpha-match (288건 · 패키지 1013개 · lock 4개)
전체: 패키지 76개에 권고 288건 · CVSS 7.0 이상 패키지 54개
(이 서비스는 오늘 처음 대조됨 — 전 항목이 새 항목)

**새로 생김 (기준 2026-11-23 대비, 76개)** — 루틴은 이것만 새로 판단한다
- org.springframework:spring-webflux 7.0.2 → 7.0.9 · 최고 CVSS 9.8 · 권고 14건 · CVE-2026-22735, CVE-2026-22737, CVE-2026-22740 외 11
- org.springframework:spring-webflux 7.0.1 → 7.0.9 · 최고 CVSS 9.8 · 권고 14건 · CVE-2026-22735, CVE-2026-22737, CVE-2026-22740 외 11
- anyio 4.9.0 → 4.14.2 · 최고 CVSS 9.3 · 권고 4건 · CVE-2026-63374, CVE-2026-64847
- org.bouncycastle:bcprov-jdk18on 1.80 → 1.85 · 최고 CVSS 9.3 · 권고 5건 · CVE-2025-14813, CVE-2026-0636, CVE-2026-13506 외 2
- h11 0.9.0 → 0.16.0 · 최고 CVSS 9.1 · 권고 2건 · CVE-2025-43859
- io.netty:netty-handler 4.2.9.Final → 4.2.17.Final · 최고 CVSS 9.1 · 권고 5건 · CVE-2026-44249, CVE-2026-45416, CVE-2026-50010 외 2
- io.netty:netty-handler 4.2.7.Final → 4.2.17.Final · 최고 CVSS 9.1 · 권고 5건 · CVE-2026-44249, CVE-2026-45416, CVE-2026-50010 외 2
- org.springframework.boot:spring-boot 4.0.1 → 4.0.6 · 최고 CVSS 9.1 · 권고 2건 · CVE-2026-40973, CVE-2026-40976
- org.springframework.boot:spring-boot 4.0.0 → 4.0.6 · 최고 CVSS 9.1 · 권고 2건 · CVE-2026-40973, CVE-2026-40976
- flatted 3.3.3 → 3.4.2 · 최고 CVSS 8.9 · 권고 2건 · CVE-2026-32141, CVE-2026-33228
- setuptools 9.1.0 → 83.0.0 · 최고 CVSS 8.8 · 권고 8건 · CVE-2022-40897, CVE-2024-6345, CVE-2025-47273 외 1
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 2.21.7 · 최고 CVSS 8.7 · 권고 4건 · CVE-2026-18401, CVE-2026-68494, CVE-2026-89407 외 1
- io.netty:netty-codec-compression 4.2.9.Final → 4.2.16.Final · 최고 CVSS 8.7 · 권고 2건 · CVE-2026-42583, CVE-2026-59901
- io.netty:netty-codec-compression 4.2.7.Final → 4.2.16.Final · 최고 CVSS 8.7 · 권고 2건 · CVE-2026-42583, CVE-2026-59901
- io.netty:netty-codec-http 4.2.9.Final → 4.2.17.Final · 최고 CVSS 8.7 · 권고 16건 · CVE-2026-33870, CVE-2026-41417, CVE-2026-42580 외 13
- io.netty:netty-codec-http 4.2.7.Final → 4.2.17.Final · 최고 CVSS 8.7 · 권고 17건 · CVE-2025-67735, CVE-2026-33870, CVE-2026-41417 외 14
- io.netty:netty-codec-http2 4.2.9.Final → 4.2.16.Final · 최고 CVSS 8.7 · 권고 7건 · CVE-2026-33871, CVE-2026-42587, CVE-2026-47244 외 4
- io.netty:netty-codec-http2 4.2.7.Final → 4.2.16.Final · 최고 CVSS 8.7 · 권고 7건 · CVE-2026-33871, CVE-2026-42587, CVE-2026-47244 외 4
- io.netty:netty-resolver-dns 4.2.9.Final → 4.2.15.Final · 최고 CVSS 8.7 · 권고 3건 · CVE-2026-45673, CVE-2026-45674, CVE-2026-47691
- io.netty:netty-resolver-dns 4.2.7.Final → 4.2.15.Final · 최고 CVSS 8.7 · 권고 3건 · CVE-2026-45673, CVE-2026-45674, CVE-2026-47691
- minimatch 3.1.2 → 3.1.4 · 최고 CVSS 8.7 · 권고 3건 · CVE-2026-26996, CVE-2026-27903, CVE-2026-27904
- source-map-js 1.2.1 → 1.2.2 · 최고 CVSS 8.7 · 권고 1건 · CVE-2026-93749
- starlette 0.32.0.post1 → 1.3.1 · 최고 CVSS 8.7 · 권고 14건 · CVE-2024-47874, CVE-2025-54121, CVE-2026-48710 외 4 · ⚠️ KEV: CVE-2026-48710
- tools.jackson.core:jackson-core 3.0.3 → 3.1.7 · 최고 CVSS 8.7 · 권고 6건 · CVE-2026-18401, CVE-2026-29062, CVE-2026-68494 외 2
- tools.jackson.core:jackson-core 3.0.2 → 3.1.7 · 최고 CVSS 8.7 · 권고 6건 · CVE-2026-18401, CVE-2026-29062, CVE-2026-68494 외 2
- com.google.guava:guava 33.4.8-android → 33.7.2 · 최고 CVSS 8.2 · 권고 1건 · CVE-2026-102554
- com.google.guava:guava 33.4.8-jre → 33.7.2 · 최고 CVSS 8.2 · 권고 1건 · CVE-2026-102554
- org.assertj:assertj-core 3.27.6 → 3.27.7 · 최고 CVSS 8.2 · 권고 1건 · CVE-2026-24400
- org.postgresql:postgresql 42.7.8 → 42.7.12 · 최고 CVSS 8.2 · 권고 2건 · CVE-2026-42198, CVE-2026-54291
- protobuf 4.25.8 → 5.29.6 · 최고 CVSS 8.2 · 권고 2건 · CVE-2026-0994
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 2.21.7 · 최고 CVSS 8.1 · 권고 12건 · CVE-2026-19032, CVE-2026-54512, CVE-2026-54513 외 9
- org.springframework.graphql:spring-graphql 2.0.1 → 2.0.4 · 최고 CVSS 8.1 · 권고 3건 · CVE-2026-41699, CVE-2026-41700, CVE-2026-41856
- org.springframework.graphql:spring-graphql 2.0.0 → 2.0.4 · 최고 CVSS 8.1 · 권고 3건 · CVE-2026-41699, CVE-2026-41700, CVE-2026-41856
- tools.jackson.core:jackson-databind 3.0.3 → 3.1.7 · 최고 CVSS 8.1 · 권고 14건 · CVE-2026-19032, CVE-2026-54512, CVE-2026-54513 외 11
- tools.jackson.core:jackson-databind 3.0.2 → 3.1.7 · 최고 CVSS 8.1 · 권고 14건 · CVE-2026-19032, CVE-2026-54512, CVE-2026-54513 외 11
- brace-expansion 1.1.12 → 1.1.21 · 최고 CVSS 7.7 · 권고 7건 · CVE-2026-102276, CVE-2026-102277, CVE-2026-102278 외 4
- browserslist 4.28.1 → 4.28.7 · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-73088, CVE-2026-73089
- fastapi 0.108.0 → 0.109.1 · 최고 CVSS 7.5 · 권고 1건 · CVE-2024-24762
- io.micrometer:micrometer-core 1.16.0 → 1.16.6 · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-40983, CVE-2026-40984
- io.netty:netty-codec-classes-quic 4.2.9.Final → 4.2.15.Final · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-44894, CVE-2026-50009
- io.netty:netty-codec-classes-quic 4.2.7.Final → 4.2.15.Final · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-44894, CVE-2026-50009
- io.netty:netty-codec-dns 4.2.9.Final → 4.2.16.Final · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-42579, CVE-2026-73508
- io.netty:netty-codec-dns 4.2.7.Final → 4.2.16.Final · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-42579, CVE-2026-73508
- io.netty:netty-codec-http3 4.2.9.Final → 4.2.16.Final · 최고 CVSS 7.5 · 권고 4건 · CVE-2026-42582, CVE-2026-44892, CVE-2026-48748 외 1
- io.netty:netty-codec-http3 4.2.7.Final → 4.2.16.Final · 최고 CVSS 7.5 · 권고 4건 · CVE-2026-42582, CVE-2026-44892, CVE-2026-48748 외 1
- io.netty:netty-transport-classes-epoll 4.2.9.Final → 4.2.13.Final · 최고 CVSS 7.5 · 권고 1건 · CVE-2026-42577
- io.netty:netty-transport-classes-epoll 4.2.7.Final → 4.2.13.Final · 최고 CVSS 7.5 · 권고 1건 · CVE-2026-42577
- js-yaml 4.1.1 → 4.3.2 · 최고 CVSS 7.5 · 권고 4건 · CVE-2026-53550, CVE-2026-59869, CVE-2026-84375
- org.springframework.data:spring-data-commons 4.0.1 → 4.0.6 · 최고 CVSS 7.5 · 권고 4건 · CVE-2026-41695, CVE-2026-41711, CVE-2026-41716 외 1
- org.springframework.data:spring-data-commons 4.0.0 → 4.0.6 · 최고 CVSS 7.5 · 권고 4건 · CVE-2026-41695, CVE-2026-41711, CVE-2026-41716 외 1
- org.springframework:spring-expression 7.0.2 → 7.0.8 · 최고 CVSS 7.5 · 권고 3건 · CVE-2026-41850, CVE-2026-41851, CVE-2026-41852
- org.springframework:spring-expression 7.0.1 → 7.0.8 · 최고 CVSS 7.5 · 권고 3건 · CVE-2026-41850, CVE-2026-41851, CVE-2026-41852
- picomatch 2.3.1 → 2.3.2 · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-33671, CVE-2026-33672
- picomatch 4.0.3 → 4.0.4 · 최고 CVSS 7.5 · 권고 2건 · CVE-2026-33671, CVE-2026-33672
- idna 3.9.0 → 3.15 · 최고 CVSS 6.9 · 권고 2건 · CVE-2026-45409
- org.apache.commons:commons-compress 1.24.0 → 1.26.0 · 최고 CVSS 6.7 · 권고 2건 · CVE-2024-25710, CVE-2024-26308
- org.springframework.data:spring-data-keyvalue 4.0.1 → 4.0.6 · 최고 CVSS 6.4 · 권고 1건 · CVE-2026-41719
- org.apache.logging.log4j:log4j-api 2.25.3 → 2.25.5 · 최고 CVSS 6.3 · 권고 1건 · CVE-2026-49844
- org.apache.logging.log4j:log4j-api 2.25.2 → 2.25.5 · 최고 CVSS 6.3 · 권고 1건 · CVE-2026-49844
- org.springframework.retry:spring-retry 2.0.12 → 2.0.13 · 최고 CVSS 5.9 · 권고 1건 · CVE-2026-41710
- postcss-selector-parser 6.1.2 → 6.1.5 · 최고 CVSS 5.9 · 권고 2건 · CVE-2026-104844, CVE-2026-9358
- @humanfs/node 0.16.7 → 0.16.8 · 최고 CVSS 5.7 · 권고 1건 · -
- ajv 6.12.6 → 6.14.0 · 최고 CVSS 5.5 · 권고 1건 · CVE-2025-69873
- org.springframework.boot:spring-boot-autoconfigure 4.0.1 → 4.0.7 · 최고 CVSS 5.3 · 권고 1건 · CVE-2026-41001
- org.springframework.boot:spring-boot-autoconfigure 4.0.0 → 4.0.7 · 최고 CVSS 5.3 · 권고 1건 · CVE-2026-41001
- org.springframework.data:spring-data-relational 4.0.1 → 4.0.6 · 최고 CVSS 4.8 · 권고 1건 · CVE-2026-41697
- org.springframework:spring-web 7.0.2 → 7.0.8 · 최고 CVSS 4.2 · 권고 1건 · CVE-2026-41854
- org.springframework:spring-web 7.0.1 → 7.0.8 · 최고 CVSS 4.2 · 권고 1건 · CVE-2026-41854
- io.netty:netty-transport-native-epoll 4.2.9.Final → 4.2.15.Final · 최고 CVSS 4.0 · 권고 1건 · CVE-2026-45536
- io.netty:netty-transport-native-epoll 4.2.7.Final → 4.2.15.Final · 최고 CVSS 4.0 · 권고 1건 · CVE-2026-45536
- org.springframework:spring-core 7.0.2 → 7.0.8 · 최고 CVSS 3.7 · 권고 1건 · CVE-2026-41848
- org.springframework:spring-core 7.0.1 → 7.0.8 · 최고 CVSS 3.7 · 권고 1건 · CVE-2026-41848
- ch.qos.logback:logback-core 1.5.22 → 1.5.34 · 최고 CVSS 2.9 · 권고 3건 · CVE-2026-10532, CVE-2026-1225, CVE-2026-9828
- ch.qos.logback:logback-core 1.5.21 → 1.5.34 · 최고 CVSS 2.9 · 권고 3건 · CVE-2026-10532, CVE-2026-1225, CVE-2026-9828
- io.netty:netty-handler-proxy 4.2.9.Final → 4.2.13.Final · 최고 CVSS 2.9 · 권고 1건 · CVE-2026-42578
- io.netty:netty-handler-proxy 4.2.7.Final → 4.2.13.Final · 최고 CVSS 2.9 · 권고 1건 · CVE-2026-42578

**해결됨 (0개)**
- 없음

