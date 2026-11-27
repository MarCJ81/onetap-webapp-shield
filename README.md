# 원탭 웹앱 실드 · OneTap WebApp Shield

> AI로 만든 웹앱의 구멍을 **배포 3분 전에** 찾고, **설정으로 막는** 도구.

**라이브**: https://marcj81.github.io/onetap-webapp-shield/

시크릿 유출 · Supabase RLS 누락 · XSS · CORS 전체 허용 · eval · Firestore 공개 규칙을
**86개 규칙**으로 검사하고, 호스팅별 보안 헤더 · CSP · CI · AI 코딩 규칙을 원클릭으로 생성합니다.
의존성 취약점(CVE)은 **OSV.dev 공식 API**로 실제 조회합니다.

빌드 없는 정적 HTML/CSS/JS. 서버 · 계정 · DB 없음. 프레임워크 없음.

---

## 왜 만들었나

Lovable · Bolt · v0 · Cursor · Replit으로 앱을 만드는 사람들이 가장 자주 넘어지는 지점은
"기능은 되는데 남의 데이터가 다 보이는" 상태입니다.

- `.env`와 서비스 키가 그대로 커밋되어 **과금 폭탄**과 **DB 전체 공개**
- Supabase 마이그레이션에 `enable row level security`가 빠져 **anon 키만으로 전 테이블 조회**
- `innerHTML` · `dangerouslySetInnerHTML` · `eval`로 **XSS/RCE**
- `cors()` 기본값 + `Access-Control-Allow-Origin: *`로 **아무 사이트나 API 호출**
- Stripe 웹훅 서명 미검증으로 **무료 결제 완료 위조**
- Firestore `allow read, write: if true;`

이 도구는 그 지점을 **찾는 데서 끝내지 않고**, 바로 붙일 수 있는 **방어 설정 파일**과
AI 코딩 도구에 붙일 **수정 프롬프트**를 같이 만듭니다.

---

## 기능

### 1. 스캔 (브라우저 안에서)
| 입력 | 설명 |
| --- | --- |
| 코드 붙여넣기 | 입력 즉시 220ms 디바운스로 재검사 |
| 파일 · 폴더 업로드 | 최대 40개, 텍스트만, 브라우저 안에서 읽음 |
| GitHub 공개 저장소 | API로 트리 조회 + raw로 주요 파일 45개(`.env` · SQL · 설정 · API 우선) |
| 배포 URL | 무료 실측 서버(Cloudflare Worker)로 **실제 응답 헤더 6종** · 노출 파일(`.env`, `.git/HEAD`, `package.json`) · 같은 도메인 스크립트의 키 노출까지 확인 |

- **시크릿 38종**: OpenAI · Anthropic · Gemini · AWS · GitHub · Stripe · Supabase(`service_role` JWT 포함) ·
  Slack · Discord · PEM · DB 연결 문자열 · SendGrid · Resend · Twilio · Telegram · npm · Notion ·
  Hugging Face · Replicate · Groq · OpenRouter · Perplexity · Shopify · DigitalOcean · 카카오 · 네이버 ·
  포트원 · 토스페이먼츠 · Cloudflare · Vercel · Mux · Bearer · 일반 비밀값
- **Shannon 엔트로피** 검사 + 자리표시자 필터(`YOUR_API_KEY`, `example`, `xxxx`, `${process.env…}`)
- **SAST 37종**: XSS(DOM · React) · eval/Function · postMessage · SQL 결합 · CORS · 쿠키 · JWT ·
  TLS 검증 해제 · 명령/경로/SSRF · 공개 환경변수 접두사(`NEXT_PUBLIC_` 등) · 약한 해시 · 소스맵 ·
  rate limit 누락
- **파일 문맥 11종**: Supabase RLS/`using (true)`/View definer, Firestore 규칙, Stripe 웹훅 서명,
  보안 헤더, `.gitignore`, `.env` 커밋, CORS 설정, Basic 인증, 보안 TODO
- 점수: 100점 만점, 심각도 가중(치명 30 · 높음 13 · 보통 5 · 낮음 2, 상한 적용), 등급 A+~F
- **정직한 판정**: 실측하지 못한 헤더는 "미확인"으로 남기고 초록 체크로 표시하지 않음

### 1-2. 바이브코더용 V2
- **전문 용어 옆에 쉬운 한 줄**: CSP·HSTS·X-Frame-Options·Referrer-Policy·Permissions-Policy·엔트로피·RLS·XSS·CORS마다 초보자용 설명을 함께 표시
- **🤖 AI에게 고쳐달라고 할 프롬프트 통째로 복사**: 발견 항목을 우선순위대로 모아 Cursor·Claude·ChatGPT에 그대로 붙이면 고쳐지는 완성형 프롬프트(1클릭)
- **3단계 흐름**: 1) 링크·코드 넣기 → 2) 위험 확인(신호등) → 3) AI 프롬프트 복사해서 고치기

### 2. 방어팩
- 호스팅별 보안 헤더 파일 즉시 생성: **Cloudflare Pages / Netlify(`_headers`)**, **Vercel(`vercel.json`)**,
  **Next.js(`next.config.mjs`)**, **Nginx**, **Express**
- **CSP 빌더**: Google Fonts · GA4 · Meta Pixel · OpenAI · Anthropic · Gemini · Workers · Supabase ·
  Firebase · Google 로그인 · Stripe · 토스페이먼츠 · 포트원 · Sentry · Vercel Analytics · YouTube ·
  Google/Kakao/Naver 지도 · Cloudinary · Tawk 등 22개 서비스 체크 → 필요한 출처만 조립
- **가드레일 키트 7파일**(ZIP): `.gitignore` · `.gitleaks.toml` · `.githooks/pre-commit` ·
  `.github/workflows/security-shield.yml`(Gitleaks + OSV-Scanner + Semgrep + 배포 헤더 확인) ·
  `SECURITY_RULES.md`(AI 에이전트 규칙) · `AGENTS.md`

### 3. 의존성 CVE (실조회)
- `package.json`의 `dependencies`/`devDependencies`를 **OSV.dev 공식 무료 API**에 그대로 질의
- `querybatch` → 취약점 상세(`/v1/vulns/{id}`)로 GHSA/CVE · 심각도 · 수정 버전 · 링크 표시
- 네트워크 실패 시 내장 참고 DB로 폴백하되 "실시간 아님"을 배너로 명시

### 4. AI 리뷰
- **무료 AI 맛보기**(하루 5회)로 발견 항목 우선순위·수정 방향
- **BYOK**: Gemini / OpenAI / Claude 키를 브라우저에만 저장해 사용
- 코드 전송은 **동의 체크** 후에만. 프롬프트는 2,000자 한도에 맞춰 요약
- **전송 전 시크릿 마스킹**: 코드 안의 키·토큰·JWT·개인키 블록을 `[REDACTED]`로 치환한 뒤 전송

### 5. 리포트
- 100점 점수 · 등급 · 심각도 요약 · 항목별 근거 · 수정법을 **Markdown / JSON**으로
- **배지 SVG** 생성(README용), 인쇄용 레이아웃
- 리포트에 "정적 분석, 침투 테스트 아님"과 미확인 항목을 항상 포함

---

## 파일 구조

```
index.html            화면 (스캔 · 방어팩 · CVE · AI · 리포트)
styles.css            다크 우선 디자인 시스템
rules.js              시크릿 · SAST · 파일 규칙 정의 (86개)
core.js               스캔 엔진 · 점수 · 프롬프트 · 리포트 · 배지
defense.js            헤더 / CSP / 가드레일 / ZIP 생성기
osv.js                OSV.dev 조회 + 내장 폴백
remote.js             배포 URL 실측(무료 Worker 프록시) + GitHub 저장소 스캔
infra/probe-worker/   onetap-shield-probe · Cloudflare Worker 실측 프록시(worker.js · wrangler.toml)
data.js               데모 프리셋 3종 (가짜 키는 실행 시 생성)
app.js                UI 상태 · 렌더 · 이벤트
engines/free-ai-client.js   무료 AI 클라이언트 (UMD)
privacy.html          개인정보 처리
manifest.json · robots.txt · sitemap.xml · favicon.svg · .nojekyll
assets/fonts/         IBM Plex Sans KR (OFL)
```

---

## 점수 계산

| 심각도 | 1건당 감점 | 총 감점 상한 |
| --- | --- | --- |
| 치명적 | 30 | 100 |
| 높음 | 13 | 46 |
| 보통 | 5 | 26 |
| 낮음 | 2 | 10 |
| 참고 | 0 | 0 |

`점수 = max(0, 100 − 감점)` · A+ ≥99, A ≥95, A- ≥90, B+ ≥85, B ≥78, B- ≥70, C+ ≥60, C ≥50, D ≥35, F <35

> 점수보다 **치명적 건수**를 먼저 보세요. 키 하나가 새면 점수와 무관하게 이미 위험합니다.

---

## 정직성 원칙

1. **읽지 못한 것은 "미확인"**. 배포 URL은 무료 실측 서버(`onetap-shield-probe`)가 실제 헤더를 읽고,
   실측 서버를 쓰지 못한 경우(로컬·사설 주소·네트워크)에만 브라우저 CORS 한계로 "미확인"이 됩니다.
   그때도 녹색 체크를 띄우지 않고 `curl` 한 줄 명령을 줍니다.
2. **가짜 초록 금지**. 노출 파일 프로브도 `exposed / blocked / unknown`을 구분합니다.
3. **오프라인은 오프라인이라고**. CVE 폴백은 "내장 참고 DB"로 표시합니다.
4. **시크릿은 마스킹**. 결과 · 리포트 · 수정 프롬프트 · AI 전송문 어디에도 원문 키를 넣지 않습니다.
5. **정적 분석의 한계 명시**. 로직 · 권한 설계 취약점은 잡지 못합니다.

---

## 알려진 한계

- 정적 패턴 기반이라 **비즈니스 로직 취약점**(예: 남의 주문 id로 조회)은 잡지 못합니다.
- GitHub 스캔은 저장소당 주요 파일 45개까지만 읽습니다(전체 파일 아님).
- 배포 URL 실측은 GET·텍스트 응답만 봅니다. 스크립트는 같은 도메인 4개, 노출 파일 3종까지이며,
  POST·로그인 뒤 화면·WebSocket은 확인하지 않습니다.
- 실측 서버는 **열린 프록시가 아닙니다**: 허용 출처(`https://marcj81.github.io`·로컬)만 받고,
  사설·메타데이터 주소(SSRF)를 거부하며, 원문 본문 대신 요약 JSON만 돌려줍니다.
- OSV 조회는 `package.json` 선언 버전 기준입니다. 실제 설치본(`lock`)과 다를 수 있습니다.
- 무료 AI는 하루 5회 · 700토큰이라 긴 코드 전체 리뷰에는 부족합니다(BYOK 권장).
- 규칙은 계속 늘릴 수 있게 `rules.js` 한 곳에 모아 두었습니다.

---

## 데이터 · 개인정보

- 스캔한 코드와 파일은 **브라우저 밖으로 나가지 않습니다**. 서버 · DB · 계정이 없습니다.
- 외부 요청은 사용자가 직접 실행한 경우에만: OSV.dev(패키지 이름·버전), GitHub 공개 API(저장소 파일),
  사용자가 동의한 AI 리뷰(마스킹된 요약). 자세한 내용은 [privacy.html](privacy.html).
- 광고 · 분석 · 추적 스크립트 없음.

---

## 참고한 공개 자료

- [Gitleaks](https://github.com/gitleaks/gitleaks) — 시크릿 패턴 체계와 pre-commit 사용법
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — 고엔트로피 탐지 아이디어
- [OSV.dev](https://osv.dev) — 의존성 취약점 API
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — XSS · CORS · CSRF · Secrets
- [Supabase RLS 문서](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [MDN CSP](https://developer.mozilla.org/ko/docs/Web/HTTP/CSP)

자세한 라이선스 표기는 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

MIT License · OneTap Labs
