# THIRD-PARTY NOTICES

원탭 웹앱 실드(v1.0.0)는 아래 공개 자료의 **아이디어·규칙 체계·표준**을 참고했습니다.
소스 코드를 그대로 복사한 부분은 없으며, 규칙 정규식과 문서는 이 프로젝트에 맞게 작성했습니다.

## 폰트
- **IBM Plex Sans KR** — © IBM, SIL Open Font License 1.1.
  `assets/fonts/plexkr-*.woff2` (OFL은 폰트 파일 자체의 재배포·번들링을 허용)

## 참고한 오픈소스 / 표준
| 자료 | 라이선스 | 이 프로젝트에서의 사용 |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | 시크릿 패턴 분류 체계, `.gitleaks.toml` 설정 형식, pre-commit 사용법 참고. 코드 미포함 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | "고엔트로피 문자열 탐지" 개념만 참고. 코드 미포함·미링크 |
| [OSV.dev](https://osv.dev) / [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | 취약점 조회 API 사용, CI 워크플로에서 공식 액션 참조 |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | CC BY-SA 4.0 | XSS·CORS·CSRF·Secrets Management·SQL Injection 권고를 규칙 문구로 요약 |
| [Supabase Docs — Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) | 문서 인용(공정 사용) | RLS·`security_invoker`·service_role 규칙 근거 |
| [MDN — Content-Security-Policy](https://developer.mozilla.org/ko/docs/Web/HTTP/CSP) | CC BY-SA 2.5 | CSP 지시어 설명·헤더 예시 참고 |
| [Stripe Docs — Webhook signatures](https://docs.stripe.com/webhooks) | 문서 인용 | `constructEvent` 검증 규칙 근거 |
| [Semgrep](https://semgrep.dev) | LGPL-2.1 | CI 예시에서 `p/owasp-top-ten`, `p/javascript` 규칙팩 참조 |

## 사용 API
- `https://api.osv.dev` — Google OSV. 무료·키 불필요.
- `https://api.github.com`, `https://raw.githubusercontent.com` — GitHub 공개 저장소 읽기.
- `https://free-ai-taste.onetap-ai.workers.dev` — 같은 제품군의 무료 AI 체험 워커(Cloudflare Workers).
- Google Gemini / OpenAI / Anthropic API — 사용자가 직접 키를 연결한 경우에만.

## 디자인
- IBM Plex Sans KR + 자체 다크 콘솔 디자인 시스템. 아이콘은 직접 그린 인라인 SVG.
