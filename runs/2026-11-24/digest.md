# 보안 수집 요약 — 2026-11-24

수집 시각: 2026-11-24T20:16+09:00 (KST)

이 파일은 수집기가 만든 사실 목록이다. 레벨 판정과 해석은 루틴이 원문을 읽고 한다.

## 1. 공식 소스 원문
전체 32 · 수집 성공 32 · 바뀜 2 · 실패 0

### 바뀐 소스 (루틴은 이 소스들의 diff와 원문을 읽는다)

#### PHP 연도별 공지 (`php-archive`) — 대상: PHP
- 원문: https://www.php.net/archive/{year}.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/php-archive.diff` · 전체 텍스트: `state/latest/php-archive.txt`

```text
Date: May 29-30, 2025
```

#### PHP ChangeLog 8 (`php-changelog-8`) — 대상: PHP 8.x
- 원문: https://www.php.net/ChangeLog-8.php
- 추가 1줄 / 삭제 1줄 · diff: `runs/2026-11-24/diffs/php-changelog-8.diff` · 전체 텍스트: `state/latest/php-changelog-8.txt`

```text
PHP 8.6.0 Released!
```

### 변화 없음

Oracle Security Alerts, Oracle Security Alerts RSS, OpenJDK Vulnerability Advisories, Node.js 보안 릴리스 RSS, Node.js 보안 릴리스 블로그, PHP php-src 보안 권고, Spring Security Advisories, Apache Tomcat 9 Security, Apache Tomcat 10 Security, Apache Tomcat 11 Security, Apache Log4j Security, Laravel 보안 권고 (Packagist), Laravel 보안 권고 (GitHub), Symfony Security Advisories, Next.js 보안 권고, Express 블로그 피드, Express Security Updates, Django Security Archive, Python security-announce, Ruby 뉴스 피드, Rails Security Announcements, Go Vulnerability Database, .NET Announcements, RustSec Advisory Database, nginx Security Advisories, Apache HTTP Server 2.4 Vulnerabilities, OpenSSL Vulnerabilities, PostgreSQL Security Information, Redis 보안 권고, Kubernetes Official CVE Feed

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

대상 구간(UTC) 2026-11-24T11:03:14.456Z ~ 2026-11-24T11:03:14.456Z · 새 CVE 0건 · 감시 제품 해당 0건 · 기준 통과 0건 · EPSS 조회 skipped
기준: 인벤토리 제품은 CVSS ≥ 7.0 또는 점수 미공개, 기반 구성요소는 CVSS ≥ 9.0, 공통으로 EPSS ≥ 0.5 또는 KEV 등재

## 4. 라이브러리 대조 (lock 파일 × OSV)

감시 프로젝트 (공개 저장소에서 실행 때마다 가져옴):
- Alpha-Match (Alpha-Match/Alpha-Match@main): ok · 커밋 59ffc51 · lock 2개 · Gradle: Backend/Api-Server ✓, Backend/Batch-Server ✓
- endfield-attendance-android (sprout1015/endfield-attendance-android@main): disabled
- RAGDeck (sprout1015/RAGDeck@develop): disabled

lock 파일 5개 · 발견 311건

### 서비스: _sample-notification-service (2건 · 패키지 2개 · lock 1개)
- body-parser 1.20.3 → 수정 1.20.9, 2.4.0 · GHSA-27r3-jxmh-p828 (CVE-2026-111181) · 7.5 · body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
- body-parser 1.20.3 → 수정 1.20.6, 2.3.0 · GHSA-v422-hmwv-36x6 (CVE-2026-12590) · 3.7 · body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement

### 서비스: alpha-match (309건 · 패키지 1013개 · lock 4개)
- ch.qos.logback:logback-core 1.5.22 → 수정 1.5.34 · GHSA-jhq6-gfmj-v8fx (CVE-2026-10532) · 2.9 · Logback vulnerable to Object Injection through HardenedObjectInputStream modules
- ch.qos.logback:logback-core 1.5.22 → 수정 1.5.33 · GHSA-p47f-322f-whfh (CVE-2026-9828) · 1.2 · QOS.CH Sarl logback logback-core has a deserialization of untrusted data vulnerability
- ch.qos.logback:logback-core 1.5.22 → 수정 1.5.25 · GHSA-qqpg-mvqg-649v (CVE-2026-1225) · 1.8 · Logback allows an attacker to instantiate classes already present on the class path
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.6, 2.21.1 · GHSA-72hv-8253-57qq (CVE-2026-18401) · 6.9 · jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS Condition
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-7hhh-6rmp-j9qf (CVE-2026-89425) · 7.5 · jackson-core: UTF8DataInputJsonParser._reportInvalidToken() missing maxErrorTokenLength limit -> unbounded StringBuilder growth (DoS)
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-p6pp-m3f8-5c89 (CVE-2026-89407) · 7.5 ·  jackson-core: ReDoS: quadratic backtracking in NumberInput.PATTERN_FLOAT via looksLikeValidNumber()
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-r7wm-3cxj-wff9 (CVE-2026-68494) · 8.7 · jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-3pjw-73gf-8qr5 (CVE-2026-59888) · 6.5 · jackson-databind: @JsonIgnore on a Record property is bypassed with a PropertyNamingStrategy
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1 · GHSA-5gvw-p9qm-jgwh (CVE-2026-59889) · 6.5 · jackson-databind: @JsonView bypassed for @JsonUnwrapped container properties on deserialization
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1, 3.1.4 · GHSA-5jmj-h7xm-6q6v (CVE-2026-54515) · 5.3 · jackson-databind has case-insensitive deserialization bypasses per-property @JsonIgnoreProperties
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-cxp5-3px4-pw24 (CVE-2026-91777) · 7.5 · jackson-databind quadratic forward-reference completion 
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-gx83-3vf8-gh7j (CVE-2026-83557) · 5.6 · jackson-databind: Comparable missing from DefaultBaseTypeLimitingValidator's unsafe base types (incomplete PolymorphicTypeValidator denylist)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-hgj6-7826-r7m5 (CVE-2026-54514) · 5.3 · jackson-databind: InetSocketAddress deserialization triggers eager DNS resolution (SSRF)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4, 3.1.4 · GHSA-j3rv-43j4-c7qm (CVE-2026-54512) · 8.1 · jackson-databind has a PolymorphicTypeValidator bypass via generic type parameters that allows arbitrary class instantiation
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-q4xh-88c3-wmh7 (CVE-2026-68497) · 7.5 · jackson-databind: Duration XMLGregorianCalendar Unbounded Number Parse DoS
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4, 3.1.4 · GHSA-rmj7-2vxq-3g9f (CVE-2026-54513) · 8.1 · jackson-databind has an array subtype allowlist bypass in BasicPolymorphicTypeValidator (allowIfSubTypeIsArray)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1 · GHSA-vvgp-rfg2-7rr6 (CVE-2026-77310) · 5.3 · jackson-databind: Incomplete fix for CVE-2026-54514: eager DNS resolution (SSRF) still present in InetAddress deserialization
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-wjgm-6hv5-3cvf (CVE-2026-19032) · 5.3 · jackson-databind: Path Deserialization Missing Scheme Allowlist for FileSystemProvider Resolution
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-wv8q-qhhj-9h54 (CVE-2026-91776) · 7.5 · jackson-databind retains every unknown raw type ID 
- com.google.guava:guava 33.4.8-android → 수정 33.7.2 · GHSA-xxph-c9ww-hj94 (CVE-2026-102554) · 8.2 · Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation
- com.google.guava:guava 33.4.8-jre → 수정 33.7.2 · GHSA-xxph-c9ww-hj94 (CVE-2026-102554) · 8.2 · Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation
- io.netty:netty-codec-classes-quic 4.2.9.Final → 수정 4.2.15.Final · GHSA-cmm3-54f8-px4j (CVE-2026-44894) · 7.5 · Netty's Default QUIC token handler accepts any client-supplied token
- io.netty:netty-codec-classes-quic 4.2.9.Final → 수정 4.2.15.Final · GHSA-cq4q-cv5g-r8q5 (CVE-2026-50009) · 4.8 · Netty: QUIC stateless reset token material exposed through header-visible connection IDs
- io.netty:netty-codec-compression 4.2.9.Final → 수정 4.2.16.Final · GHSA-558v-64gr-wgg4 (CVE-2026-59901) · 8.7 · Netty: [Bzip2Decoder] Infinite Loop in RLE State Machine Leads to Event-Loop Thread Hang
- io.netty:netty-codec-compression 4.2.9.Final → 수정 4.2.13.Final · GHSA-mj4r-2hfc-f8p6 (CVE-2026-42583) · 7.5 · Netty Lz4FrameDecoder is vulnerable to resource exhaustion 
- io.netty:netty-codec-dns 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-cm33-6792-r9fm (CVE-2026-42579) · 7.5 · Netty has a DNS Codec Input Validation Bypass (Encoder + Decoder)
- io.netty:netty-codec-dns 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-mfg7-5gfp-c4w3 (CVE-2026-73508) · 5.3 · Netty: Memory Leak in DNS Record Decoder via Malformed Domain Names
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-38f8-5428-x5cv (CVE-2026-42585) · 6.5 · Netty vulnerable to HTTP Request Smuggling due to malformed Transfer-Encoding
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-4mp9-239f-g9hg (CVE-2026-59898) · 6.3 · Netty: WebSockets V07/V08 handshaker missing Connection/Upgrade validation
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-57rv-r2g8-2cj3 (CVE-2026-42584) · 7.3 · Netty has HttpClientCodec response desynchronization
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-6cqp-g7gg-8hr5 (CVE-2026-56746) · 6.5 · Netty: Security Control Bypass via CORS Short-Circuit Failure
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-6jqx-86gh-f27w (CVE-2026-55831) · 7.5 · Netty SPDY SETTINGS frame count materializes unbounded settings map
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-8c42-7qj2-3j46 (CVE-2026-59903) · 6.5 · Netty Vulnerable to Cache Poisoning and Information Disclosure via CORS Vary Header Overwrite
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-f6hv-jmp6-3vwv (CVE-2026-42587) · 7.5 · Netty: HttpContentDecompressor maxAllocation bypass when Content-Encoding set to br/zstd/snappy leads to decompression bomb DoS
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-gcjf-9mgh-3p7g (CVE-2026-59921) · 5.7 · Netty: CRLF Injection via Multipart Filename in Netty HttpPostRequestEncoder
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-hvcg-qmg6-jm4c (CVE-2026-50020) · 5.3 · Netty: HttpObjectDecoder skips arbitrary initial control characters when only initial CRLF characters are permitted
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-jppx-w49h-x2qq (CVE-2026-56745) · 8.7 · Netty: [SpdyHttpDecoder] ByteBuf Reference Leak on RST_STREAM Leads to Native Memory Exhaustion
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-m4cv-j2px-7723 (CVE-2026-42580) · 6.5 · Netty vulnerable to HTTP Request Smuggling due to incorrect chunk size parsing
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-mvh2-crg5-v77c (CVE-2026-55833) · 7.5 · Netty SPDY zlib header block continues decoded expansion after maxHeaderSize truncation
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.132.Final, 4.2.10.Final · GHSA-pwqr-wmgm-9rr8 (CVE-2026-33870) · 7.5 · Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-q4f6-jm68-57ww (CVE-2026-59899) · 6.9 · Netty: [HttpContentEncoder] Unbounded Per-Connection Queue Growth via HTTP/1.1 Pipelining Leads to Denial of Service
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-v8h7-rr48-vmmv (CVE-2026-41417) · 5.3 · Netty: Start-Line Injection in DefaultHttpRequest.setUri() Allows HTTP Request Smuggling and RTSP Request Injection
- io.netty:netty-codec-http 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-xxqh-mfjm-7mv9 (CVE-2026-42581) · 5.8 · Netty HTTP/1.0 TE+CL Coexistence Bypasses Smuggling Sanitization
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-563q-j3cm-6jxm (CVE-2026-50560) · 6.9 · Netty susceptible to HTTP/2 Reset Attack with different on-the-wire signature
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-5x3r-wrvg-rp6q (CVE-2026-47244) · 5.3 · Netty HTTP/2: Advertised MAX_CONCURRENT_STREAMS are not enforced
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-93wv-jw9v-4972 (CVE-2026-56819) · 7.5 · Netty: HTTP/2 decompression leaks ByteBuf reference count when the decompressor channel is already closed (Direct memory leak / OOM DoS)
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-c2gf-v879-257j (CVE-2026-48043) · 5.3 · netty-codec-http2: ByteBuf Reference-Count Leak in DelegatingDecompressorFrameListener Leads to Memory Exhaustion
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-c69g-56f8-xwqj (CVE-2026-59900) · 6.9 · Netty: [codec-http2] Lack of Host Header Deduplication in HTTP/2→HTTP/1.x Translation Leads to Request Routing Bypass
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-f6hv-jmp6-3vwv (CVE-2026-42587) · 7.5 · Netty: HttpContentDecompressor maxAllocation bypass when Content-Encoding set to br/zstd/snappy leads to decompression bomb DoS
- io.netty:netty-codec-http2 4.2.9.Final → 수정 4.1.132.Final, 4.2.11.Final · GHSA-w9fj-cfpg-grvv (CVE-2026-33871) · 8.7 · Netty HTTP/2 CONTINUATION Frame Flood DoS via Zero-Byte Frame Bypass
- io.netty:netty-codec-http3 4.2.9.Final → 수정 4.2.13.Final · GHSA-2c5c-chwr-9hqw (CVE-2026-42582) · 7.5 · Netty HTTP/3 QPACK literal unbounded allocation
- io.netty:netty-codec-http3 4.2.9.Final → 수정 4.2.15.Final · GHSA-4grm-h2qv-h6w6 (CVE-2026-48748) · 7.5 · Netty HTTP/3 QPACK Blocked Streams Memory Exhaustion
- io.netty:netty-codec-http3 4.2.9.Final → 수정 4.2.15.Final · GHSA-c2rx-5r8w-8xr2 (CVE-2026-44892) · 7.5 · Netty has a Vulnerable Default Configuration Which Leads to Denial of Service via Unbounded HTTP/3 Header Size
- io.netty:netty-codec-http3 4.2.9.Final → 수정 4.2.16.Final · GHSA-hpcc-26xq-25fv (CVE-2026-56816) · 7.5 · Netty: Memory Exhaustion via HTTP/3 Reserved Frame Types
- io.netty:netty-handler 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-3qp7-7mw8-wx86 (CVE-2026-44249) · 8.1 · Netty has an IPv6 Subnet Filter Bypass via Incorrect Comparator Masking
- io.netty:netty-handler 4.2.9.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-c4c3-7fpv-j4q5 (CVE-2026-75595) · 9.1 · Netty: SNI Routing Bypass via Fragmented TLS ClientHello Causing Fallback to Default SslContext
- io.netty:netty-handler 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-c653-97m9-rcg9 (CVE-2026-50010) · 7.5 · Netty: Wrapping plain trust manager silently disables hostname verification
- io.netty:netty-handler 4.2.9.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-fccg-mwvh-qqg4 (CVE-2026-75596) · 6.9 · Netty: Fragmented ClientHello records trigger quadratic pre-handshake reassembly in default SNI parsing
- io.netty:netty-handler 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-x4gw-5cx5-pgmh (CVE-2026-45416) · 7.5 · Netty: SNI handler pre-allocates up to 16 MiB from nine attacker bytes
- io.netty:netty-handler-proxy 4.2.9.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-45q3-82m4-75jr (CVE-2026-42578) · 2.9 · Netty has HTTP Header Injection via HttpProxyHandler Disabled Validation (Incomplete Fix CVE-2025-67735)
- io.netty:netty-resolver-dns 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-5pvg-856g-cp85 (CVE-2026-47691) · 8.7 · Netty has Insufficient Bailiwick Validation for NS Records
- io.netty:netty-resolver-dns 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-676x-f7gg-47vc (CVE-2026-45674) · 8.7 · Netty Vulnerable to DNS Cache Poisoning via Missing Bailiwick Checks in CNAME Records
- io.netty:netty-resolver-dns 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-xmv7-r254-6q78 (CVE-2026-45673) · 6.8 · Netty: DNS Cache Poisoning due to Predictable PRNG and Default Static Source Port
- io.netty:netty-transport-classes-epoll 4.2.9.Final → 수정 4.2.13.Final · GHSA-rwm7-x88c-3g2p (CVE-2026-42577) · 7.5 · Netty epoll transport denial of service via RST on half-closed TCP connection
- io.netty:netty-transport-native-epoll 4.2.9.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-w573-9ffj-6ff9 (CVE-2026-45536) · 4.0 · Netty: Unix-socket fd receive leaks descriptors when peer sends two at once
- org.apache.commons:commons-compress 1.24.0 → 수정 1.26.0 · GHSA-4265-ccf5-phj5 (CVE-2024-26308) · 6.7 · Apache Commons Compress: OutOfMemoryError unpacking broken Pack200 file
- org.apache.commons:commons-compress 1.24.0 → 수정 1.26.0 · GHSA-4g9r-vxhx-9pgx (CVE-2024-25710) · 5.9 · Apache Commons Compress: Denial of service caused by an infinite loop for a corrupted DUMP file
- org.apache.logging.log4j:log4j-api 2.25.3 → 수정 2.25.5, 2.26.1 · GHSA-qv9r-c865-cp47 (CVE-2026-49844) · 6.3 · Apache Log4j API: Improper encoding of non-finite floating-point values during MapMessage JSON serialization
- org.assertj:assertj-core 3.27.6 → 수정 3.27.7 · GHSA-rqfh-9r24-8c9r (CVE-2026-24400) · 8.2 · AssertJ has XML External Entity (XXE) vulnerability when parsing untrusted XML via isXmlEqualTo assertion
- org.postgresql:postgresql 42.7.8 → 수정 42.7.11 · GHSA-98qh-xjc8-98pq (CVE-2026-42198) · 7.5 · pgjdbc: Unbounded PBKDF2 iterations in SCRAM authentication allows CPU exhaustion DoS
- org.postgresql:postgresql 42.7.8 → 수정 42.7.12 · GHSA-j92g-9f8w-j867 (CVE-2026-54291) · 8.2 · PostgreSQL JDBC Driver: Silent channel-binding authentication downgrade via unsupported certificate algorithms
- org.springframework.boot:spring-boot 4.0.1 → 수정 4.0.6 · GHSA-8v8j-3hxp-93wr (CVE-2026-40976) · 9.1 · Spring Boot's default security filter chain has no authorization rule with Actuator but without Health
- org.springframework.boot:spring-boot 4.0.1 → 수정 3.5.14, 4.0.6 · GHSA-wwpq-f5c3-7hvx (CVE-2026-40973) · 7.0 · Spring Boot accepts predictable temp directory without ownership verification
- org.springframework.boot:spring-boot-autoconfigure 4.0.1 → 수정 3.5.15, 4.0.7 · GHSA-ggg2-9786-hwc8 (CVE-2026-41001) · 5.3 · Spring Boot: Predictable Temp Directory in Artemis Auto-configuration
- org.springframework.data:spring-data-commons 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-5m4m-73w9-8433 (CVE-2026-41721) · 5.9 · Spring Data Commons: Denial of Service via excessive memory allocation in projection binding
- org.springframework.data:spring-data-commons 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-5vpf-xvv7-c8vh (CVE-2026-41711) · 5.9 · Spring Data Commons: StackOverflowException when parsing Sort parameters (DoS)
- org.springframework.data:spring-data-commons 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-88fw-v6x4-3f58 (CVE-2026-41695) · 7.5 · Spring Data: Unbounded property-path cache keyed by externally-supplied path string
- org.springframework.data:spring-data-commons 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-9fw2-h3hf-293r (CVE-2026-41716) · 7.5 · Spring Data Commons: Heap exhaustion from unbounded property-lookup cache retaining crafted string keys
- org.springframework.data:spring-data-keyvalue 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-xg2j-3hj6-pc24 (CVE-2026-41719) · 6.4 · Spring Data KeyValue: Remote code execution via SpEL Injection in Sort-based repository queries
- org.springframework.data:spring-data-relational 4.0.1 → 수정 3.5.12, 4.0.6 · GHSA-8r2h-xh92-gq57 (CVE-2026-41697) · 4.8 · Spring Data Relational: Attackers can supply wildcard characters to perform boolean-based blind data inference
- org.springframework.graphql:spring-graphql 2.0.1 → 수정 1.4.6, 2.0.4 · GHSA-m39w-hqxx-3r48 (CVE-2026-41700) · 8.1 · Spring for GraphQL: Cross-Site WebSocket Hijacking
- org.springframework.graphql:spring-graphql 2.0.1 → 수정 1.4.6, 2.0.4 · GHSA-phxq-526m-79px (CVE-2026-41856) · 7.5 · Spring for GraphQL: Annotation Detection Vulnerability
- org.springframework.graphql:spring-graphql 2.0.1 → 수정 1.4.6, 2.0.4 · GHSA-px92-q6rc-6mwv (CVE-2026-41699) · 8.1 · Spring for GraphQL: Unsafe Deserialization
- org.springframework:spring-core 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-659m-px2c-25wj (CVE-2026-41848) · 3.7 · Spring Framework Denial of Service via AntPathMatcher
- org.springframework:spring-expression 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-9f52-rjqv-25qv (CVE-2026-41852) · 3.7 · Spring Framework Arbitrary Method Invocation in SpEL Expressions
- org.springframework:spring-expression 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-r5w3-xv2f-j59q (CVE-2026-41850) · 7.5 · Spring Framework Algorithmic Denial of Service via SpEL Expressions
- org.springframework:spring-expression 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-wxpp-56q6-5pcg (CVE-2026-41851) · 5.3 · Spring Framework Denial of Service via Unbounded Cache in SpEL
- org.springframework:spring-web 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-7m2p-62gw-p8qq (CVE-2026-41854) · 4.2 · Spring Framework Server-Side Request Forgery via UriComponentsBuilder
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.17, 7.0.6 · GHSA-4773-3jfm-qmx3 (CVE-2026-22737) · 5.9 · Spring Framework Improper Path Limitation with Script View Templates
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-4hfh-6x8g-gwpp (CVE-2026-41839) · 4.2 · Spring Framework Escalation via Session Fixation in WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.18, 7.0.7 · GHSA-5843-p793-ghmm (CVE-2026-22740) · 6.5 · Spring Framework DoS with Multipart Temp Files in WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.17, 7.0.6 · GHSA-6hcq-hmm3-jj3c (CVE-2026-22735) · 2.6 · Spring MVC and WebFlux has Server Sent Event stream corruption
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.18, 7.0.7 · GHSA-6p4f-wcwh-5vvm (CVE-2026-22745) · 5.3 · Spring MVC and WebFlux applications are vulnerable to Denial of Service attacks when resolving static resources
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-72pg-x5f8-j25j (CVE-2026-41843) · 5.9 · Spring Framework Path Traversal via Versioned Static Resources in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-83f7-v6px-pp3h (CVE-2026-41840) · 5.9 · Spring Framework Denial of Service via Multipart Requests in WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 7.0.9 · GHSA-9qf2-26p9-2q2q (CVE-2026-47892) · 9.8 · Spring Framework Header Predicate Bypass in WebFlux Functional Endpoints
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-cjpg-rgq5-fr37 (CVE-2026-41853) · 5.3 · Spring Framework Multipart Request Smuggling in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-h3qp-gqrc-q736 (CVE-2026-41844) · 4.2 · Spring Framework Open Redirect in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 7.0.9 · GHSA-j9f9-w8pj-32f8 (CVE-2026-47890) · 9.8 · Spring Framework Server Sent Event stream corruption while rendering fragments
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-mq64-j8f9-9gcj (CVE-2026-41841) · 5.9 · Spring Framework Information Disclosure via Static Resource Cache in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.18, 7.0.7 · GHSA-wg35-8jpf-2xv3 (CVE-2026-22741) · 3.1 · Spring MVC and WebFlux applications are vulnerable to cache poisoning when resolving static resources.
- org.springframework:spring-webflux 7.0.2 → 수정 6.2.19, 7.0.8 · GHSA-x23c-287f-qqv5 (CVE-2026-41842) · 7.5 · Spring Framework Denial of Service via Versioned Resources in Spring MVC and WebFlux
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.1 · GHSA-2m67-wjpj-xhg9 (-) · 7.5 · Jackson Core: Document length constraint bypass in blocking, async, and DataInput parsers
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.0 · GHSA-6v53-7c9g-w56r (CVE-2026-29062) · 8.7 · jackson-core has Nesting Depth Constraint Bypass in `UTF8DataInputJsonParser` potentially allowing Resource Exhaustion
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.0 · GHSA-72hv-8253-57qq (CVE-2026-18401) · 6.9 · jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS Condition
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.7, 3.2.3 · GHSA-7hhh-6rmp-j9qf (CVE-2026-89425) · 7.5 · jackson-core: UTF8DataInputJsonParser._reportInvalidToken() missing maxErrorTokenLength limit -> unbounded StringBuilder growth (DoS)
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.7, 3.2.2 · GHSA-p6pp-m3f8-5c89 (CVE-2026-89407) · 7.5 ·  jackson-core: ReDoS: quadratic backtracking in NumberInput.PATTERN_FLOAT via looksLikeValidNumber()
- tools.jackson.core:jackson-core 3.0.3 → 수정 3.1.4 · GHSA-r7wm-3cxj-wff9 (CVE-2026-68494) · 8.7 · jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-3pjw-73gf-8qr5 (CVE-2026-59888) · 6.5 · jackson-databind: @JsonIgnore on a Record property is bypassed with a PropertyNamingStrategy
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.5, 3.2.1 · GHSA-5gvw-p9qm-jgwh (CVE-2026-59889) · 6.5 · jackson-databind: @JsonView bypassed for @JsonUnwrapped container properties on deserialization
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-5hh8-q8hv-fr38 (CVE-2026-54517) · 5.3 · jackson-databind has @JsonView bypass for setterless creator properties
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-9fxm-vc8v-hj55 (CVE-2026-54516) · 5.3 · jackson-databind's renamed @JsonIgnore'd setters can deserialize via private fields
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.7, 3.2.3 · GHSA-cxp5-3px4-pw24 (CVE-2026-91777) · 7.5 · jackson-databind quadratic forward-reference completion 
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.6, 3.2.2 · GHSA-gx83-3vf8-gh7j (CVE-2026-83557) · 5.6 · jackson-databind: Comparable missing from DefaultBaseTypeLimitingValidator's unsafe base types (incomplete PolymorphicTypeValidator denylist)
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-hgj6-7826-r7m5 (CVE-2026-54514) · 5.3 · jackson-databind: InetSocketAddress deserialization triggers eager DNS resolution (SSRF)
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-j3rv-43j4-c7qm (CVE-2026-54512) · 8.1 · jackson-databind has a PolymorphicTypeValidator bypass via generic type parameters that allows arbitrary class instantiation
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.6, 3.2.2 · GHSA-q4xh-88c3-wmh7 (CVE-2026-68497) · 7.5 · jackson-databind: Duration XMLGregorianCalendar Unbounded Number Parse DoS
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-rcqc-6cw3-h962 (CVE-2026-54518) · 6.5 · jackson-databind has a @JsonView bypass for unwrapped creator parameters
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.4 · GHSA-rmj7-2vxq-3g9f (CVE-2026-54513) · 8.1 · jackson-databind has an array subtype allowlist bypass in BasicPolymorphicTypeValidator (allowIfSubTypeIsArray)
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.5, 3.2.1 · GHSA-vvgp-rfg2-7rr6 (CVE-2026-77310) · 5.3 · jackson-databind: Incomplete fix for CVE-2026-54514: eager DNS resolution (SSRF) still present in InetAddress deserialization
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.6, 3.2.2 · GHSA-wjgm-6hv5-3cvf (CVE-2026-19032) · 5.3 · jackson-databind: Path Deserialization Missing Scheme Allowlist for FileSystemProvider Resolution
- tools.jackson.core:jackson-databind 3.0.3 → 수정 3.1.7, 3.2.3 · GHSA-wv8q-qhhj-9h54 (CVE-2026-91776) · 7.5 · jackson-databind retains every unknown raw type ID 
- ch.qos.logback:logback-core 1.5.21 → 수정 1.5.34 · GHSA-jhq6-gfmj-v8fx (CVE-2026-10532) · 2.9 · Logback vulnerable to Object Injection through HardenedObjectInputStream modules
- ch.qos.logback:logback-core 1.5.21 → 수정 1.5.33 · GHSA-p47f-322f-whfh (CVE-2026-9828) · 1.2 · QOS.CH Sarl logback logback-core has a deserialization of untrusted data vulnerability
- ch.qos.logback:logback-core 1.5.21 → 수정 1.5.25 · GHSA-qqpg-mvqg-649v (CVE-2026-1225) · 1.8 · Logback allows an attacker to instantiate classes already present on the class path
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.6, 2.21.1 · GHSA-72hv-8253-57qq (CVE-2026-18401) · 6.9 · jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS Condition
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-7hhh-6rmp-j9qf (CVE-2026-89425) · 7.5 · jackson-core: UTF8DataInputJsonParser._reportInvalidToken() missing maxErrorTokenLength limit -> unbounded StringBuilder growth (DoS)
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-p6pp-m3f8-5c89 (CVE-2026-89407) · 7.5 ·  jackson-core: ReDoS: quadratic backtracking in NumberInput.PATTERN_FLOAT via looksLikeValidNumber()
- com.fasterxml.jackson.core:jackson-core 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-r7wm-3cxj-wff9 (CVE-2026-68494) · 8.7 · jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-3pjw-73gf-8qr5 (CVE-2026-59888) · 6.5 · jackson-databind: @JsonIgnore on a Record property is bypassed with a PropertyNamingStrategy
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1 · GHSA-5gvw-p9qm-jgwh (CVE-2026-59889) · 6.5 · jackson-databind: @JsonView bypassed for @JsonUnwrapped container properties on deserialization
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1, 3.1.4 · GHSA-5jmj-h7xm-6q6v (CVE-2026-54515) · 5.3 · jackson-databind has case-insensitive deserialization bypasses per-property @JsonIgnoreProperties
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-cxp5-3px4-pw24 (CVE-2026-91777) · 7.5 · jackson-databind quadratic forward-reference completion 
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-gx83-3vf8-gh7j (CVE-2026-83557) · 5.6 · jackson-databind: Comparable missing from DefaultBaseTypeLimitingValidator's unsafe base types (incomplete PolymorphicTypeValidator denylist)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4 · GHSA-hgj6-7826-r7m5 (CVE-2026-54514) · 5.3 · jackson-databind: InetSocketAddress deserialization triggers eager DNS resolution (SSRF)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4, 3.1.4 · GHSA-j3rv-43j4-c7qm (CVE-2026-54512) · 8.1 · jackson-databind has a PolymorphicTypeValidator bypass via generic type parameters that allows arbitrary class instantiation
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-q4xh-88c3-wmh7 (CVE-2026-68497) · 7.5 · jackson-databind: Duration XMLGregorianCalendar Unbounded Number Parse DoS
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.8, 2.21.4, 3.1.4 · GHSA-rmj7-2vxq-3g9f (CVE-2026-54513) · 8.1 · jackson-databind has an array subtype allowlist bypass in BasicPolymorphicTypeValidator (allowIfSubTypeIsArray)
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.9, 2.21.5, 2.22.1 · GHSA-vvgp-rfg2-7rr6 (CVE-2026-77310) · 5.3 · jackson-databind: Incomplete fix for CVE-2026-54514: eager DNS resolution (SSRF) still present in InetAddress deserialization
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.10, 2.21.6, 2.22.2 · GHSA-wjgm-6hv5-3cvf (CVE-2026-19032) · 5.3 · jackson-databind: Path Deserialization Missing Scheme Allowlist for FileSystemProvider Resolution
- com.fasterxml.jackson.core:jackson-databind 2.20.1 → 수정 2.18.11, 2.21.7, 2.22.3 · GHSA-wv8q-qhhj-9h54 (CVE-2026-91776) · 7.5 · jackson-databind retains every unknown raw type ID 
- com.google.guava:guava 33.4.8-android → 수정 33.7.2 · GHSA-xxph-c9ww-hj94 (CVE-2026-102554) · 8.2 · Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation
- com.google.guava:guava 33.4.8-jre → 수정 33.7.2 · GHSA-xxph-c9ww-hj94 (CVE-2026-102554) · 8.2 · Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation
- io.micrometer:micrometer-core 1.16.0 → 수정 1.15.12, 1.16.6 · GHSA-g3pr-3p32-fp23 (CVE-2026-40984) · 7.5 · Micrometer HTTP server instrumentations DoS
- io.micrometer:micrometer-core 1.16.0 → 수정 1.15.12, 1.16.6 · GHSA-w737-wx49-qj23 (CVE-2026-40983) · 7.5 · Micrometer gRPC server instrumentation DoS
- io.netty:netty-codec-classes-quic 4.2.7.Final → 수정 4.2.15.Final · GHSA-cmm3-54f8-px4j (CVE-2026-44894) · 7.5 · Netty's Default QUIC token handler accepts any client-supplied token
- io.netty:netty-codec-classes-quic 4.2.7.Final → 수정 4.2.15.Final · GHSA-cq4q-cv5g-r8q5 (CVE-2026-50009) · 4.8 · Netty: QUIC stateless reset token material exposed through header-visible connection IDs
- io.netty:netty-codec-compression 4.2.7.Final → 수정 4.2.16.Final · GHSA-558v-64gr-wgg4 (CVE-2026-59901) · 8.7 · Netty: [Bzip2Decoder] Infinite Loop in RLE State Machine Leads to Event-Loop Thread Hang
- io.netty:netty-codec-compression 4.2.7.Final → 수정 4.2.13.Final · GHSA-mj4r-2hfc-f8p6 (CVE-2026-42583) · 7.5 · Netty Lz4FrameDecoder is vulnerable to resource exhaustion 
- io.netty:netty-codec-dns 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-cm33-6792-r9fm (CVE-2026-42579) · 7.5 · Netty has a DNS Codec Input Validation Bypass (Encoder + Decoder)
- io.netty:netty-codec-dns 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-mfg7-5gfp-c4w3 (CVE-2026-73508) · 5.3 · Netty: Memory Leak in DNS Record Decoder via Malformed Domain Names
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-38f8-5428-x5cv (CVE-2026-42585) · 6.5 · Netty vulnerable to HTTP Request Smuggling due to malformed Transfer-Encoding
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-4mp9-239f-g9hg (CVE-2026-59898) · 6.3 · Netty: WebSockets V07/V08 handshaker missing Connection/Upgrade validation
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-57rv-r2g8-2cj3 (CVE-2026-42584) · 7.3 · Netty has HttpClientCodec response desynchronization
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-6cqp-g7gg-8hr5 (CVE-2026-56746) · 6.5 · Netty: Security Control Bypass via CORS Short-Circuit Failure
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-6jqx-86gh-f27w (CVE-2026-55831) · 7.5 · Netty SPDY SETTINGS frame count materializes unbounded settings map
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.129.Final, 4.2.8.Final · GHSA-84h7-rjj3-6jx4 (CVE-2025-67735) · 6.5 · Netty has a CRLF Injection vulnerability in io.netty.handler.codec.http.HttpRequestEncoder
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-8c42-7qj2-3j46 (CVE-2026-59903) · 6.5 · Netty Vulnerable to Cache Poisoning and Information Disclosure via CORS Vary Header Overwrite
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-f6hv-jmp6-3vwv (CVE-2026-42587) · 7.5 · Netty: HttpContentDecompressor maxAllocation bypass when Content-Encoding set to br/zstd/snappy leads to decompression bomb DoS
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-gcjf-9mgh-3p7g (CVE-2026-59921) · 5.7 · Netty: CRLF Injection via Multipart Filename in Netty HttpPostRequestEncoder
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-hvcg-qmg6-jm4c (CVE-2026-50020) · 5.3 · Netty: HttpObjectDecoder skips arbitrary initial control characters when only initial CRLF characters are permitted
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-jppx-w49h-x2qq (CVE-2026-56745) · 8.7 · Netty: [SpdyHttpDecoder] ByteBuf Reference Leak on RST_STREAM Leads to Native Memory Exhaustion
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-m4cv-j2px-7723 (CVE-2026-42580) · 6.5 · Netty vulnerable to HTTP Request Smuggling due to incorrect chunk size parsing
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-mvh2-crg5-v77c (CVE-2026-55833) · 7.5 · Netty SPDY zlib header block continues decoded expansion after maxHeaderSize truncation
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.132.Final, 4.2.10.Final · GHSA-pwqr-wmgm-9rr8 (CVE-2026-33870) · 7.5 · Netty: HTTP Request Smuggling via Chunked Extension Quoted-String Parsing
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-q4f6-jm68-57ww (CVE-2026-59899) · 6.9 · Netty: [HttpContentEncoder] Unbounded Per-Connection Queue Growth via HTTP/1.1 Pipelining Leads to Denial of Service
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-v8h7-rr48-vmmv (CVE-2026-41417) · 5.3 · Netty: Start-Line Injection in DefaultHttpRequest.setUri() Allows HTTP Request Smuggling and RTSP Request Injection
- io.netty:netty-codec-http 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-xxqh-mfjm-7mv9 (CVE-2026-42581) · 5.8 · Netty HTTP/1.0 TE+CL Coexistence Bypasses Smuggling Sanitization
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-563q-j3cm-6jxm (CVE-2026-50560) · 6.9 · Netty susceptible to HTTP/2 Reset Attack with different on-the-wire signature
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-5x3r-wrvg-rp6q (CVE-2026-47244) · 5.3 · Netty HTTP/2: Advertised MAX_CONCURRENT_STREAMS are not enforced
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-93wv-jw9v-4972 (CVE-2026-56819) · 7.5 · Netty: HTTP/2 decompression leaks ByteBuf reference count when the decompressor channel is already closed (Direct memory leak / OOM DoS)
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-c2gf-v879-257j (CVE-2026-48043) · 5.3 · netty-codec-http2: ByteBuf Reference-Count Leak in DelegatingDecompressorFrameListener Leads to Memory Exhaustion
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.136.Final, 4.2.16.Final · GHSA-c69g-56f8-xwqj (CVE-2026-59900) · 6.9 · Netty: [codec-http2] Lack of Host Header Deduplication in HTTP/2→HTTP/1.x Translation Leads to Request Routing Bypass
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-f6hv-jmp6-3vwv (CVE-2026-42587) · 7.5 · Netty: HttpContentDecompressor maxAllocation bypass when Content-Encoding set to br/zstd/snappy leads to decompression bomb DoS
- io.netty:netty-codec-http2 4.2.7.Final → 수정 4.1.132.Final, 4.2.11.Final · GHSA-w9fj-cfpg-grvv (CVE-2026-33871) · 8.7 · Netty HTTP/2 CONTINUATION Frame Flood DoS via Zero-Byte Frame Bypass
- io.netty:netty-codec-http3 4.2.7.Final → 수정 4.2.13.Final · GHSA-2c5c-chwr-9hqw (CVE-2026-42582) · 7.5 · Netty HTTP/3 QPACK literal unbounded allocation
- io.netty:netty-codec-http3 4.2.7.Final → 수정 4.2.15.Final · GHSA-4grm-h2qv-h6w6 (CVE-2026-48748) · 7.5 · Netty HTTP/3 QPACK Blocked Streams Memory Exhaustion
- io.netty:netty-codec-http3 4.2.7.Final → 수정 4.2.15.Final · GHSA-c2rx-5r8w-8xr2 (CVE-2026-44892) · 7.5 · Netty has a Vulnerable Default Configuration Which Leads to Denial of Service via Unbounded HTTP/3 Header Size
- io.netty:netty-codec-http3 4.2.7.Final → 수정 4.2.16.Final · GHSA-hpcc-26xq-25fv (CVE-2026-56816) · 7.5 · Netty: Memory Exhaustion via HTTP/3 Reserved Frame Types
- io.netty:netty-handler 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-3qp7-7mw8-wx86 (CVE-2026-44249) · 8.1 · Netty has an IPv6 Subnet Filter Bypass via Incorrect Comparator Masking
- io.netty:netty-handler 4.2.7.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-c4c3-7fpv-j4q5 (CVE-2026-75595) · 9.1 · Netty: SNI Routing Bypass via Fragmented TLS ClientHello Causing Fallback to Default SslContext
- io.netty:netty-handler 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-c653-97m9-rcg9 (CVE-2026-50010) · 7.5 · Netty: Wrapping plain trust manager silently disables hostname verification
- io.netty:netty-handler 4.2.7.Final → 수정 4.1.137.Final, 4.2.17.Final · GHSA-fccg-mwvh-qqg4 (CVE-2026-75596) · 6.9 · Netty: Fragmented ClientHello records trigger quadratic pre-handshake reassembly in default SNI parsing
- io.netty:netty-handler 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-x4gw-5cx5-pgmh (CVE-2026-45416) · 7.5 · Netty: SNI handler pre-allocates up to 16 MiB from nine attacker bytes
- io.netty:netty-handler-proxy 4.2.7.Final → 수정 4.1.133.Final, 4.2.13.Final · GHSA-45q3-82m4-75jr (CVE-2026-42578) · 2.9 · Netty has HTTP Header Injection via HttpProxyHandler Disabled Validation (Incomplete Fix CVE-2025-67735)
- io.netty:netty-resolver-dns 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-5pvg-856g-cp85 (CVE-2026-47691) · 8.7 · Netty has Insufficient Bailiwick Validation for NS Records
- io.netty:netty-resolver-dns 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-676x-f7gg-47vc (CVE-2026-45674) · 8.7 · Netty Vulnerable to DNS Cache Poisoning via Missing Bailiwick Checks in CNAME Records
- io.netty:netty-resolver-dns 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-xmv7-r254-6q78 (CVE-2026-45673) · 6.8 · Netty: DNS Cache Poisoning due to Predictable PRNG and Default Static Source Port
- io.netty:netty-transport-classes-epoll 4.2.7.Final → 수정 4.2.13.Final · GHSA-rwm7-x88c-3g2p (CVE-2026-42577) · 7.5 · Netty epoll transport denial of service via RST on half-closed TCP connection
- io.netty:netty-transport-native-epoll 4.2.7.Final → 수정 4.1.135.Final, 4.2.15.Final · GHSA-w573-9ffj-6ff9 (CVE-2026-45536) · 4.0 · Netty: Unix-socket fd receive leaks descriptors when peer sends two at once
- org.apache.logging.log4j:log4j-api 2.25.2 → 수정 2.25.5, 2.26.1 · GHSA-qv9r-c865-cp47 (CVE-2026-49844) · 6.3 · Apache Log4j API: Improper encoding of non-finite floating-point values during MapMessage JSON serialization
- org.assertj:assertj-core 3.27.6 → 수정 3.27.7 · GHSA-rqfh-9r24-8c9r (CVE-2026-24400) · 8.2 · AssertJ has XML External Entity (XXE) vulnerability when parsing untrusted XML via isXmlEqualTo assertion
- org.bouncycastle:bcprov-jdk18on 1.80 → 수정 1.80.2, 1.81.1, 1.84 · GHSA-574f-3g2m-x479 (CVE-2025-14813) · 9.3 · Bouncy Castle for Java GOST 28147 CTR mode reuses keystream after 255 blocks
- org.bouncycastle:bcprov-jdk18on 1.80 → 수정 1.85 · GHSA-9pwp-9qqc-pr26 (CVE-2026-8763) · 9.3 · Bouncy Castle: Name Constraints bypass via trailing dot in rfc822Name and URI
- org.bouncycastle:bcprov-jdk18on 1.80 → 수정 1.80.2, 1.81.1, 1.84 · GHSA-c3fc-8qff-9hwx (CVE-2026-0636) · 6.5 · Bouncy Castle has an LDAP injection
- org.bouncycastle:bcprov-jdk18on 1.80 → 수정 1.80.2, 1.84 · GHSA-p93r-85wp-75v3 (CVE-2026-5598) · 8.9 · Bouncy Castle Has Covert Timing Channel Vulnerability
- org.bouncycastle:bcprov-jdk18on 1.80 → 수정 1.85 · GHSA-qp49-qgx5-5m26 (CVE-2026-13506) · 8.7 · Bouncy Castle: Lazy ASN.1 sequence forcing resets nesting-depth guard
- org.postgresql:postgresql 42.7.8 → 수정 42.7.11 · GHSA-98qh-xjc8-98pq (CVE-2026-42198) · 7.5 · pgjdbc: Unbounded PBKDF2 iterations in SCRAM authentication allows CPU exhaustion DoS
- org.postgresql:postgresql 42.7.8 → 수정 42.7.12 · GHSA-j92g-9f8w-j867 (CVE-2026-54291) · 8.2 · PostgreSQL JDBC Driver: Silent channel-binding authentication downgrade via unsupported certificate algorithms
- org.springframework.boot:spring-boot 4.0.0 → 수정 4.0.6 · GHSA-8v8j-3hxp-93wr (CVE-2026-40976) · 9.1 · Spring Boot's default security filter chain has no authorization rule with Actuator but without Health
- org.springframework.boot:spring-boot 4.0.0 → 수정 3.5.14, 4.0.6 · GHSA-wwpq-f5c3-7hvx (CVE-2026-40973) · 7.0 · Spring Boot accepts predictable temp directory without ownership verification
- org.springframework.boot:spring-boot-autoconfigure 4.0.0 → 수정 3.5.15, 4.0.7 · GHSA-ggg2-9786-hwc8 (CVE-2026-41001) · 5.3 · Spring Boot: Predictable Temp Directory in Artemis Auto-configuration
- org.springframework.data:spring-data-commons 4.0.0 → 수정 3.5.12, 4.0.6 · GHSA-5m4m-73w9-8433 (CVE-2026-41721) · 5.9 · Spring Data Commons: Denial of Service via excessive memory allocation in projection binding
- org.springframework.data:spring-data-commons 4.0.0 → 수정 3.5.12, 4.0.6 · GHSA-5vpf-xvv7-c8vh (CVE-2026-41711) · 5.9 · Spring Data Commons: StackOverflowException when parsing Sort parameters (DoS)
- org.springframework.data:spring-data-commons 4.0.0 → 수정 3.5.12, 4.0.6 · GHSA-88fw-v6x4-3f58 (CVE-2026-41695) · 7.5 · Spring Data: Unbounded property-path cache keyed by externally-supplied path string
- org.springframework.data:spring-data-commons 4.0.0 → 수정 3.5.12, 4.0.6 · GHSA-9fw2-h3hf-293r (CVE-2026-41716) · 7.5 · Spring Data Commons: Heap exhaustion from unbounded property-lookup cache retaining crafted string keys
- org.springframework.graphql:spring-graphql 2.0.0 → 수정 1.4.6, 2.0.4 · GHSA-m39w-hqxx-3r48 (CVE-2026-41700) · 8.1 · Spring for GraphQL: Cross-Site WebSocket Hijacking
- org.springframework.graphql:spring-graphql 2.0.0 → 수정 1.4.6, 2.0.4 · GHSA-phxq-526m-79px (CVE-2026-41856) · 7.5 · Spring for GraphQL: Annotation Detection Vulnerability
- org.springframework.graphql:spring-graphql 2.0.0 → 수정 1.4.6, 2.0.4 · GHSA-px92-q6rc-6mwv (CVE-2026-41699) · 8.1 · Spring for GraphQL: Unsafe Deserialization
- org.springframework.retry:spring-retry 2.0.12 → 수정 2.0.13 · GHSA-2827-2mxx-j8pv (CVE-2026-41710) · 5.9 · Spring Retry has Cache Exhaustion in Stateful Retries that leads to Denial of Service
- org.springframework:spring-core 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-659m-px2c-25wj (CVE-2026-41848) · 3.7 · Spring Framework Denial of Service via AntPathMatcher
- org.springframework:spring-expression 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-9f52-rjqv-25qv (CVE-2026-41852) · 3.7 · Spring Framework Arbitrary Method Invocation in SpEL Expressions
- org.springframework:spring-expression 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-r5w3-xv2f-j59q (CVE-2026-41850) · 7.5 · Spring Framework Algorithmic Denial of Service via SpEL Expressions
- org.springframework:spring-expression 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-wxpp-56q6-5pcg (CVE-2026-41851) · 5.3 · Spring Framework Denial of Service via Unbounded Cache in SpEL
- org.springframework:spring-web 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-7m2p-62gw-p8qq (CVE-2026-41854) · 4.2 · Spring Framework Server-Side Request Forgery via UriComponentsBuilder
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.17, 7.0.6 · GHSA-4773-3jfm-qmx3 (CVE-2026-22737) · 5.9 · Spring Framework Improper Path Limitation with Script View Templates
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-4hfh-6x8g-gwpp (CVE-2026-41839) · 4.2 · Spring Framework Escalation via Session Fixation in WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.18, 7.0.7 · GHSA-5843-p793-ghmm (CVE-2026-22740) · 6.5 · Spring Framework DoS with Multipart Temp Files in WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.17, 7.0.6 · GHSA-6hcq-hmm3-jj3c (CVE-2026-22735) · 2.6 · Spring MVC and WebFlux has Server Sent Event stream corruption
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.18, 7.0.7 · GHSA-6p4f-wcwh-5vvm (CVE-2026-22745) · 5.3 · Spring MVC and WebFlux applications are vulnerable to Denial of Service attacks when resolving static resources
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-72pg-x5f8-j25j (CVE-2026-41843) · 5.9 · Spring Framework Path Traversal via Versioned Static Resources in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-83f7-v6px-pp3h (CVE-2026-41840) · 5.9 · Spring Framework Denial of Service via Multipart Requests in WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 7.0.9 · GHSA-9qf2-26p9-2q2q (CVE-2026-47892) · 9.8 · Spring Framework Header Predicate Bypass in WebFlux Functional Endpoints
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-cjpg-rgq5-fr37 (CVE-2026-41853) · 5.3 · Spring Framework Multipart Request Smuggling in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-h3qp-gqrc-q736 (CVE-2026-41844) · 4.2 · Spring Framework Open Redirect in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 7.0.9 · GHSA-j9f9-w8pj-32f8 (CVE-2026-47890) · 9.8 · Spring Framework Server Sent Event stream corruption while rendering fragments
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-mq64-j8f9-9gcj (CVE-2026-41841) · 5.9 · Spring Framework Information Disclosure via Static Resource Cache in Spring MVC and WebFlux
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.18, 7.0.7 · GHSA-wg35-8jpf-2xv3 (CVE-2026-22741) · 3.1 · Spring MVC and WebFlux applications are vulnerable to cache poisoning when resolving static resources.
- org.springframework:spring-webflux 7.0.1 → 수정 6.2.19, 7.0.8 · GHSA-x23c-287f-qqv5 (CVE-2026-41842) · 7.5 · Spring Framework Denial of Service via Versioned Resources in Spring MVC and WebFlux
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.1 · GHSA-2m67-wjpj-xhg9 (-) · 7.5 · Jackson Core: Document length constraint bypass in blocking, async, and DataInput parsers
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.0 · GHSA-6v53-7c9g-w56r (CVE-2026-29062) · 8.7 · jackson-core has Nesting Depth Constraint Bypass in `UTF8DataInputJsonParser` potentially allowing Resource Exhaustion
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.0 · GHSA-72hv-8253-57qq (CVE-2026-18401) · 6.9 · jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS Condition
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.7, 3.2.3 · GHSA-7hhh-6rmp-j9qf (CVE-2026-89425) · 7.5 · jackson-core: UTF8DataInputJsonParser._reportInvalidToken() missing maxErrorTokenLength limit -> unbounded StringBuilder growth (DoS)
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.7, 3.2.2 · GHSA-p6pp-m3f8-5c89 (CVE-2026-89407) · 7.5 ·  jackson-core: ReDoS: quadratic backtracking in NumberInput.PATTERN_FLOAT via looksLikeValidNumber()
- tools.jackson.core:jackson-core 3.0.2 → 수정 3.1.4 · GHSA-r7wm-3cxj-wff9 (CVE-2026-68494) · 8.7 · jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-3pjw-73gf-8qr5 (CVE-2026-59888) · 6.5 · jackson-databind: @JsonIgnore on a Record property is bypassed with a PropertyNamingStrategy
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.5, 3.2.1 · GHSA-5gvw-p9qm-jgwh (CVE-2026-59889) · 6.5 · jackson-databind: @JsonView bypassed for @JsonUnwrapped container properties on deserialization
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-5hh8-q8hv-fr38 (CVE-2026-54517) · 5.3 · jackson-databind has @JsonView bypass for setterless creator properties
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-9fxm-vc8v-hj55 (CVE-2026-54516) · 5.3 · jackson-databind's renamed @JsonIgnore'd setters can deserialize via private fields
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.7, 3.2.3 · GHSA-cxp5-3px4-pw24 (CVE-2026-91777) · 7.5 · jackson-databind quadratic forward-reference completion 
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.6, 3.2.2 · GHSA-gx83-3vf8-gh7j (CVE-2026-83557) · 5.6 · jackson-databind: Comparable missing from DefaultBaseTypeLimitingValidator's unsafe base types (incomplete PolymorphicTypeValidator denylist)
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-hgj6-7826-r7m5 (CVE-2026-54514) · 5.3 · jackson-databind: InetSocketAddress deserialization triggers eager DNS resolution (SSRF)
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-j3rv-43j4-c7qm (CVE-2026-54512) · 8.1 · jackson-databind has a PolymorphicTypeValidator bypass via generic type parameters that allows arbitrary class instantiation
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.6, 3.2.2 · GHSA-q4xh-88c3-wmh7 (CVE-2026-68497) · 7.5 · jackson-databind: Duration XMLGregorianCalendar Unbounded Number Parse DoS
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-rcqc-6cw3-h962 (CVE-2026-54518) · 6.5 · jackson-databind has a @JsonView bypass for unwrapped creator parameters
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.4 · GHSA-rmj7-2vxq-3g9f (CVE-2026-54513) · 8.1 · jackson-databind has an array subtype allowlist bypass in BasicPolymorphicTypeValidator (allowIfSubTypeIsArray)
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.5, 3.2.1 · GHSA-vvgp-rfg2-7rr6 (CVE-2026-77310) · 5.3 · jackson-databind: Incomplete fix for CVE-2026-54514: eager DNS resolution (SSRF) still present in InetAddress deserialization
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.6, 3.2.2 · GHSA-wjgm-6hv5-3cvf (CVE-2026-19032) · 5.3 · jackson-databind: Path Deserialization Missing Scheme Allowlist for FileSystemProvider Resolution
- tools.jackson.core:jackson-databind 3.0.2 → 수정 3.1.7, 3.2.3 · GHSA-wv8q-qhhj-9h54 (CVE-2026-91776) · 7.5 · jackson-databind retains every unknown raw type ID 
- fastapi 0.108.0 → 수정 0.109.1, 9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc · PYSEC-2024-38 (CVE-2024-24762) · 7.5 · 
- protobuf 4.25.8 → 수정 5.29.6, 6.33.5 · PYSEC-2026-1805 (CVE-2026-0994) · 8.2 · protobuf affected by a JSON recursion depth bypass
- protobuf 4.25.8 → 수정 5.29.6, 6.33.5 · GHSA-7gcm-g887-7qv7 (CVE-2026-0994) · 8.2 · protobuf affected by a JSON recursion depth bypass
- anyio 4.9.0 → 수정 4.14.2 · PYSEC-2026-4024 (CVE-2026-64847) · 6.8 · AnyIO process-pool workers can block indefinitely on undrained stderr
- anyio 4.9.0 → 수정 4.14.2 · PYSEC-2026-4025 (CVE-2026-63374) · 9.3 · AnyIO: TLSStream IDNA 2003 host name encoding enables potential TLS certificate spoofing
- anyio 4.9.0 → 수정 4.14.2 · GHSA-5p39-cfhj-2xmp (CVE-2026-64847) · 6.8 · AnyIO process-pool workers can block indefinitely on undrained stderr
- anyio 4.9.0 → 수정 4.14.2 · GHSA-82r6-8w77-94w6 (CVE-2026-63374) · 9.3 · AnyIO: TLSStream IDNA 2003 host name encoding enables potential TLS certificate spoofing
- h11 0.9.0 → 수정 0.16.0 · PYSEC-2026-348 (CVE-2025-43859) · 9.1 · h11 accepts some malformed Chunked-Encoding bodies
- h11 0.9.0 → 수정 0.16.0 · GHSA-vqfr-h8mv-ghfj (CVE-2025-43859) · 9.1 · h11 accepts some malformed Chunked-Encoding bodies
- idna 3.9.0 → 수정 3.15 · PYSEC-2026-215 (CVE-2026-45409) · 6.9 · 
- idna 3.9.0 → 수정 3.15 · GHSA-65pc-fj4g-8rjx (CVE-2026-45409) · 6.9 · Internationalized Domain Names in Applications (IDNA): Specially crafted inputs to idna.encode() can bypass CVE-2024-3651 fix
- setuptools 9.1.0 → 수정 43a9c9bfa6aa626ec2a22540bea28d2ca77964be, 65.5.1 · PYSEC-2022-43012 (CVE-2022-40897) · 8.7 · 
- setuptools 9.1.0 → 수정 250a6d17978f9f6ac3ac887091f2d32886fbbb0b, 78.1.1 · PYSEC-2025-49 (CVE-2025-47273) · 8.8 · 
- setuptools 9.1.0 → 수정 70.0.0 · PYSEC-2026-1918 (CVE-2024-6345) · 8.8 · setuptools vulnerable to Command Injection via package URL
- setuptools 9.1.0 → 수정 83.0.0 · PYSEC-2026-3447 (CVE-2026-59890) · 6.1 · 
- setuptools 9.1.0 → 수정 78.1.1 · GHSA-5rjg-fvgr-3xxf (CVE-2025-47273) · 8.8 · setuptools has a path traversal vulnerability in PackageIndex.download that leads to Arbitrary File Write
- setuptools 9.1.0 → 수정 70.0.0 · GHSA-cx63-2mw6-8hw5 (CVE-2024-6345) · 8.8 · setuptools vulnerable to Command Injection via package URL
- setuptools 9.1.0 → 수정 83.0.0 · GHSA-h35f-9h28-mq5c (CVE-2026-59890) · 6.1 · setuptools: MANIFEST.in exclusion bypass in sdist via Unicode normalization collision (NFC/NFD) on macOS APFS/HFS+
- setuptools 9.1.0 → 수정 65.5.1 · GHSA-r9hx-vwmv-q579 (CVE-2022-40897) · 8.7 · pypa/setuptools vulnerable to Regular Expression Denial of Service (ReDoS)
- starlette 0.32.0.post1 → 수정 1.0.1 · PYSEC-2026-161 (CVE-2026-48710) · 6.5 · BadHost: Missing Host header validation poisons request.url.path, bypassing path-based security checks
- starlette 0.32.0.post1 → 수정 0.47.2 · PYSEC-2026-1941 (CVE-2025-54121) · 5.3 · Starlette has possible denial-of-service vector when parsing large files in multipart forms
- starlette 0.32.0.post1 → 수정 0.40.0 · PYSEC-2026-1943 (CVE-2024-47874) · 8.7 · Starlette Denial of service (DoS) via multipart/form-data
- starlette 0.32.0.post1 → 수정 1.1.0 · PYSEC-2026-2280 (CVE-2026-48817) · 5.3 · 
- starlette 0.32.0.post1 → 수정 1.1.0 · PYSEC-2026-2281 (CVE-2026-48818) · 7.5 · 
- starlette 0.32.0.post1 → 수정 1.3.0 · PYSEC-2026-248 (CVE-2026-54282) · 5.3 · 
- starlette 0.32.0.post1 → 수정 1.3.1 · PYSEC-2026-249 (CVE-2026-54283) · 7.5 · 
- starlette 0.32.0.post1 → 수정 0.47.2 · GHSA-2c2j-9gv5-cj73 (CVE-2025-54121) · 5.3 · Starlette has possible denial-of-service vector when parsing large files in multipart forms
- starlette 0.32.0.post1 → 수정 1.3.1 · GHSA-82w8-qh3p-5jfq (CVE-2026-54283) · 7.5 · Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS
- starlette 0.32.0.post1 → 수정 1.0.1 · GHSA-86qp-5c8j-p5mr (CVE-2026-48710) · 6.5 · Starlette has missing Host header validation that poisons request.url.path, bypassing path-based security checks
- starlette 0.32.0.post1 → 수정 0.40.0 · GHSA-f96h-pmfr-66vw (CVE-2024-47874) · 8.7 · Starlette Denial of service (DoS) via multipart/form-data
- starlette 0.32.0.post1 → 수정 1.3.0 · GHSA-jp82-jpqv-5vv3 (CVE-2026-54282) · 5.3 · Starlette: Unvalidated request path concatenated into authority poisons request.url.hostname
- starlette 0.32.0.post1 → 수정 1.1.0 · GHSA-wqp7-x3pw-xc5r (CVE-2026-48818) · 7.5 · Starlette: SSRF and NTLM credential theft via UNC paths in StaticFiles on Windows
- starlette 0.32.0.post1 → 수정 1.1.0 · GHSA-x746-7m8f-x49c (CVE-2026-48817) · 5.3 · Starlette: Arbitrary HTTP method dispatched to `HTTPEndpoint` attributes via `getattr`
- @humanfs/node 0.16.7 → 수정 0.16.8 · GHSA-p498-v437-472g (-) · 5.7 · humanfs: Recursive copy follows symlinked files and copies data from outside the source tree
- ajv 6.12.6 → 수정 6.14.0, 8.18.0 · GHSA-2g4f-4pwh-qvx6 (CVE-2025-69873) · 5.5 · ajv has ReDoS when using `$data` option
- brace-expansion 1.1.12 → 수정 1.1.16, 2.1.2, 5.0.7 · GHSA-3jxr-9vmj-r5cp (CVE-2026-13149) · 7.7 · brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups
- brace-expansion 1.1.12 → 수정 1.1.19, 2.1.5, 3.0.7, 5.0.10 · GHSA-6j4f-fj2g-mc7p (CVE-2026-102276) · 7.5 · brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion
- brace-expansion 1.1.12 → 수정 1.1.13, 2.0.3, 3.0.2, 5.0.5 · GHSA-f886-m6hf-6m8v (CVE-2026-33750) · 6.5 · brace-expansion: Zero-step sequence causes process hang and memory exhaustion
- brace-expansion 1.1.12 → 수정 1.1.17, 2.1.3, 3.0.3, 5.0.8 · GHSA-mh99-v99m-4gvg (CVE-2026-14257) · 7.5 · brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash
- brace-expansion 1.1.12 → 수정 1.1.21, 2.1.7, 3.0.9, 5.0.12 · GHSA-q2hr-2g5m-vwhr (CVE-2026-102277) · 5.3 · brace-expansion: Quadratic-time expansion of the `{a},b}` rewrite causes CPU denial of service
- brace-expansion 1.1.12 → 수정 1.1.20, 2.1.6, 3.0.8, 5.0.11 · GHSA-qhr7-859c-m2p7 (CVE-2026-102278) · 7.5 · brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhaustion
- brace-expansion 1.1.12 → 수정 1.1.18, 2.1.4, 3.0.6, 5.0.9 · GHSA-rgw5-rvv9-x895 (CVE-2026-69152) · 7.5 · brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation
- browserslist 4.28.1 → 수정 4.28.7 · GHSA-73wf-gq98-2v4g (CVE-2026-73088) · 7.5 · Browserslist: Uncaught crash / prototype write via untrusted browserslist-stats.json custom stats (normalizeStats)
- browserslist 4.28.1 → 수정 4.28.7 · GHSA-c83g-rgw3-j3cx (CVE-2026-73089) · 7.5 · Browserslist: Unbounded memory growth (no cache eviction) via distinct query results, leading to eventual OOM
- flatted 3.3.3 → 수정 3.4.0 · GHSA-25h7-pfq9-p65f (CVE-2026-32141) · 7.5 · flatted vulnerable to unbounded recursion DoS in parse() revive phase
- flatted 3.3.3 → 수정 3.4.2 · GHSA-rf6f-7fwh-wjgh (CVE-2026-33228) · 8.9 · Prototype Pollution via parse() in NodeJS flatted
- js-yaml 4.1.1 → 수정 3.15.2, 4.3.2 · GHSA-2883-xcg3-v3hh (CVE-2026-84375) · 7.5 · js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources
- js-yaml 4.1.1 → 수정 3.15.0, 4.3.0 · GHSA-52cp-r559-cp3m (CVE-2026-59869) · 7.5 · js-yaml: YAML merge-key chains can force quadratic CPU consumption
- js-yaml 4.1.1 → 수정 3.15.1, 4.3.1 · GHSA-5p4m-2wfm-xmqj (-) · 7.5 · JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported
- js-yaml 4.1.1 → 수정 3.15.0, 4.2.0 · GHSA-h67p-54hq-rp68 (CVE-2026-53550) · 5.3 · JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases
- minimatch 3.1.2 → 수정 10.2.3, 3.1.4, 4.2.5, 5.1.8, 6.2.2, 7.4.8, 8.0.6, 9.0.7 · GHSA-23c5-xmqv-rm74 (CVE-2026-27904) · 7.5 · minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions
- minimatch 3.1.2 → 수정 10.2.1, 3.1.3, 4.2.4, 5.1.7, 6.2.1, 7.4.7, 8.0.5, 9.0.6 · GHSA-3ppc-4f35-3m26 (CVE-2026-26996) · 8.7 · minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern
- minimatch 3.1.2 → 수정 10.2.3, 3.1.3, 4.2.5, 5.1.8, 6.2.2, 7.4.8, 8.0.6, 9.0.7 · GHSA-7r86-cg39-jmmj (CVE-2026-27903) · 7.5 · minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments
- picomatch 2.3.1 → 수정 2.3.2, 3.0.2, 4.0.4 · GHSA-3v7f-55p6-f55p (CVE-2026-33672) · 5.3 · Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching
- picomatch 2.3.1 → 수정 2.3.2, 3.0.2, 4.0.4 · GHSA-c2c7-rcm5-vvqj (CVE-2026-33671) · 7.5 · Picomatch has a ReDoS vulnerability via extglob quantifiers
- picomatch 4.0.3 → 수정 2.3.2, 3.0.2, 4.0.4 · GHSA-3v7f-55p6-f55p (CVE-2026-33672) · 5.3 · Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching
- picomatch 4.0.3 → 수정 2.3.2, 3.0.2, 4.0.4 · GHSA-c2c7-rcm5-vvqj (CVE-2026-33671) · 7.5 · Picomatch has a ReDoS vulnerability via extglob quantifiers
- postcss-selector-parser 6.1.2 → 수정 6.1.5, 7.1.6 · GHSA-rj75-hqrm-r3gf (CVE-2026-104844) · 5.9 · PostCSS: Quadratic complexity in flat selector parsing allows CPU exhaustion
- postcss-selector-parser 6.1.2 → 수정 6.1.3, 7.1.3 · GHSA-w9m9-85wc-3x92 (CVE-2026-9358) · 4.3 · postcss-selector-parser allows denial of service through uncontrolled AST recursion
- source-map-js 1.2.1 → 수정 1.2.2 · GHSA-68fv-2mgg-jv7q (CVE-2026-93749) · 8.7 · source-map-js allows event-loop denial of service through indexed source-map section offsets

