# onetap-shield-probe · 무료 URL 실측 프록시 (Cloudflare Workers)

31호기 **원탭 웹앱 실드**의 `배포 URL` 탭이 쓰는 실측 서버입니다.
브라우저는 다른 오리진의 응답 헤더를 CORS 때문에 읽지 못하므로, 이 Worker가 대신 요청해서
**요약 JSON**만 돌려줍니다.

| 항목 | 값 |
|---|---|
| 주소 | **https://onetap-shield-probe.onetap-ai.workers.dev** (`/health`, `/probe?url=…`) |
| 계정 | Goodday810202@gmail.com's Account (`ba2295ece35e0615879cf696340b96fa`) · Workers Free |
| 허용 출처 | `https://marcj81.github.io`, `http://localhost:*`, `http://127.0.0.1:*` (그 외 403) |
| 소스 | `worker.js` · `wrangler.toml` (이 폴더) |

## 하는 일

```
GET /probe?url=https://hearple.com/
  → 실제 응답 상태 코드
  → 보안 헤더 6종 값 (CSP · HSTS · X-Content-Type-Options · X-Frame-Options · Referrer-Policy · Permissions-Policy)
  → 노출 파일 실측: /.env · /.git/HEAD · /package.json  (200 + 내용 확인일 때만 exposed)
  → 같은 도메인 <script src> 최대 4개 + HTML 본문에서 공개 시크릿 패턴 스캔 (값은 가려서 반환)
  → 걸린 시간(ms)
```

## 안전장치

- **열린 프록시가 아님**: 허용 출처만 받고, 원문 본문은 돌려주지 않으며(요약 JSON만),
  시크릿은 `AIza…9f2c`처럼 가려서 보냅니다.
- **SSRF 차단**: `localhost` · `127.x` · `10.x` · `172.16–31.x` · `192.168.x` · `169.254.x`(메타데이터) ·
  `[::1]` · `.internal` · `.local` · 단일 라벨 호스트 · 자격증명 포함 URL · 위험 포트를 거부합니다.
  리다이렉트도 매 홉 다시 검증합니다(최대 3회).
- GET·텍스트 응답만, HTML 300KB·스크립트 160KB까지만 읽고, 9초 타임아웃.

## 403 / 400 응답

| 코드 | error | 뜻 |
|---|---|---|
| 403 | `origin_not_allowed` | 허용 출처가 아님(배포 도메인·로컬만) |
| 400 | `loopback_ip`·`private_ip`·`metadata_ip`·`invalid_host` … | 사설·메타데이터 주소라 거부 |
| 200 | `ok:false` + `upstream_unreachable` | 대상 서버가 응답하지 않음 |

## 재배포

```bash
cd infra/probe-worker
npx wrangler deploy            # Workers Scripts:Edit 권한의 API 토큰 또는 wrangler login 필요
```

> 이 환경(Node 없음)에서는 Cloudflare REST API로 업로드했습니다:
> `PUT /accounts/{account_id}/workers/scripts/onetap-shield-probe` (multipart: metadata + worker.js)
> 업로드 뒤 `POST …/subdomain {"enabled":true}` 로 workers.dev 라우트를 켜야 주소가 열립니다.
