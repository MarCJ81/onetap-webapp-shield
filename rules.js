/* ============================================================================
   rules.js · 원탭 웹앱 실드 규칙 라이브러리
   ----------------------------------------------------------------------------
   바이브 코딩( Lovable · Bolt · Cursor · v0 · Replit )으로 만든 웹앱에서
   실제로 새는 것들을 기준으로 정리한 정적 분석 규칙.

   - SECRET_RULES : Gitleaks / TruffleHog 계열 고신뢰 시크릿 패턴 + 엔트로피
   - CODE_RULES   : 줄 단위 SAST (XSS · 인증 · RLS · CORS · 쿠키 · 암호화 …)
   - FILE_RULES   : 파일 전체 문맥이 필요한 검사 (Supabase SQL, firestore.rules,
                    보안 헤더, .gitignore, 웹훅 서명 검증 …)

   의존성 없음. 브라우저와 Node에서 같은 객체를 쓴다.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.SHIELD_RULES = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '1.0.0';

  var CATEGORIES = {
    secret: '시크릿·키 노출',
    xss: 'XSS·DOM 주입',
    auth: '인증·권한',
    db: 'DB·RLS',
    api: 'API·서버',
    crypto: '암호화',
    config: '설정·헤더',
    git: 'Git·빌드 위생',
    deps: '의존성'
  };

  var SEVERITY = {
    critical: { label: '치명적', weight: 30, order: 0 },
    high: { label: '높음', weight: 13, order: 1 },
    medium: { label: '보통', weight: 5, order: 2 },
    low: { label: '낮음', weight: 2, order: 3 },
    info: { label: '참고', weight: 0, order: 4 }
  };

  var REFS = {
    owaspXss: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    owaspRls: 'https://supabase.com/docs/guides/database/postgres/row-level-security',
    owaspCors: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html',
    owaspCsrf: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
    owaspSecrets: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    gitleaks: 'https://github.com/gitleaks/gitleaks',
    trufflehog: 'https://github.com/trufflesecurity/trufflehog',
    osv: 'https://osv.dev',
    mdnCsp: 'https://developer.mozilla.org/ko/docs/Web/HTTP/CSP',
    stripeWebhook: 'https://docs.stripe.com/webhooks#verify-manually',
    nextHeaders: 'https://nextjs.org/docs/app/api-reference/config/next-config-js/headers',
    supabaseKeys: 'https://supabase.com/docs/guides/api/api-keys'
  };

  // PEM 헤더는 규칙 파일 자체가 시크릿 스캐너에 걸리지 않도록 조각으로 만든다.
  var PEM_BEGIN = '-----BEGIN ';
  var PEM_END = 'PRIVATE KEY-----';
  function escRe(t) { return String(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  var PEM_RE = new RegExp('(' + escRe(PEM_BEGIN) + '(?:RSA |EC |DSA |OPENSSH |PGP )?' + escRe(PEM_END) + ')', 'g');
  var FIREBASE_PEM_RE = new RegExp('("private_key"\\s*:\\s*"' + escRe(PEM_BEGIN) + escRe(PEM_END) + ')', 'g');

  /* ── 1. 시크릿 패턴 ─────────────────────────────────────────────────────
     re  : 전체 일치. g 필수.
     g   : 시크릿 값이 들어 있는 캡처 그룹 번호 (없으면 0 = 전체)
     minEntropy : 값의 Shannon 엔트로피 하한 (오탐 억제)
     context : 파일 안에서 이 정규식이 같이 있어야 인정 (문맥 의존 키)
     ──────────────────────────────────────────────────────────────────── */
  var SECRET_RULES = [
    {
      id: 'openai-key', name: 'OpenAI API 키', sev: 'critical', g: 1, minEntropy: 3.0,
      re: /\b(sk-proj-[A-Za-z0-9_-]{24,}|sk-svcacct-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})\b/g,
      why: '이 키 하나로 GPT 호출과 과금이 가능합니다. 공개 저장소·클라이언트 번들에 들어가면 수 분 안에 수집되어 요금이 터집니다.',
      fix: '키를 즉시 폐기하고 서버 환경변수로만 보관하세요. 브라우저 코드에서는 자체 프록시 API를 거쳐 호출하세요.'
    },
    {
      id: 'anthropic-key', name: 'Anthropic(Claude) API 키', sev: 'critical', g: 1, minEntropy: 3.0,
      re: /\b(sk-ant-(?:api\d+-)?[A-Za-z0-9_-]{20,})\b/g,
      why: 'Claude API 키가 노출되면 타인이 사용자 크레딧으로 호출할 수 있습니다.',
      fix: '키를 폐기하고 서버 측 환경변수로 이동하세요. 클라이언트에는 절대 두지 마세요.'
    },
    {
      id: 'google-api-key', name: 'Google API 키', sev: 'high', g: 1,
      re: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
      why: 'Gemini·Maps·Firebase 등 Google API 키가 노출되면 쿼터 도용과 과금이 발생할 수 있습니다.',
      fix: 'Google Cloud 콘솔에서 키를 제한(HTTP 리퍼러·IP·API별)하고, 서버용 키는 환경변수로 옮기세요.'
    },
    {
      id: 'aws-access-key', name: 'AWS 액세스 키 ID', sev: 'critical', g: 1,
      re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
      why: 'AWS 키 ID가 노출되면 짝이 되는 시크릿 키와 함께 계정 리소스 탈취로 이어질 수 있습니다.',
      fix: 'IAM에서 해당 키를 즉시 비활성화하고, GitHub Actions OIDC 같은 무키 인증으로 바꾸세요.'
    },
    {
      id: 'aws-secret-key', name: 'AWS 시크릿 액세스 키', sev: 'critical', g: 1, minEntropy: 3.7,
      re: /aws_?secret_?access_?key[^A-Za-z0-9]{0,20}([A-Za-z0-9/+]{40})/gi,
      why: 'AWS 시크릿 키는 액세스 키 ID와 결합해 계정 전체 권한을 넘깁니다.',
      fix: '키를 폐기(Rotate)하고 Secrets Manager·환경변수로만 주입하세요.'
    },
    {
      id: 'github-token', name: 'GitHub 토큰', sev: 'critical', g: 1,
      re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g,
      why: 'GitHub 토큰으로 저장소 읽기·쓰기, 워크플로 실행까지 가능합니다.',
      fix: 'GitHub Settings → Developer settings에서 즉시 revoke하고, fine-grained 토큰으로 최소 권한만 발급하세요.'
    },
    {
      id: 'stripe-live-key', name: 'Stripe 라이브 시크릿 키', sev: 'critical', g: 1,
      re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g,
      why: 'Stripe 라이브 키로 결제 생성·환불·고객 정보 조회가 가능합니다.',
      fix: 'Stripe 대시보드에서 키를 롤링하고 서버 환경변수로만 쓰세요. 테스트 키(sk_test_)로 개발하세요.'
    },
    {
      id: 'stripe-webhook-secret', name: 'Stripe 웹훅 시크릿', sev: 'high', g: 1, minEntropy: 3.0,
      re: /\b(whsec_[A-Za-z0-9]{20,})\b/g,
      why: '웹훅 시크릿이 노출되면 공격자가 가짜 결제 완료 이벤트를 서명해 보낼 수 있습니다.',
      fix: '웹훅 시크릿을 롤링하고 서버 환경변수로 보관하세요. constructEvent로 서명을 검증하세요.'
    },
    {
      id: 'supabase-secret', name: 'Supabase 시크릿 키', sev: 'critical', g: 1,
      re: /\b(sb_secret_[A-Za-z0-9_-]{16,})\b/g,
      why: 'Supabase 신형 시크릿 키는 RLS를 우회하는 관리자 권한입니다. 클라이언트에 있으면 DB 전체가 열립니다.',
      fix: '키를 폐기하고 서버(Route Handler·Edge Function)에서만 사용하세요. 공개용은 anon(publishable) 키입니다.'
    },
    {
      id: 'slack-token', name: 'Slack 토큰', sev: 'critical', g: 1,
      re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/g,
      why: 'Slack 토큰으로 워크스페이스 메시지 열람·전송이 가능합니다.',
      fix: 'Slack API에서 토큰을 폐기하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'slack-webhook', name: 'Slack 웹훅 URL', sev: 'high', g: 1,
      re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/g,
      why: '웹훅 URL을 아는 사람은 누구나 채널에 메시지를 보낼 수 있습니다(스팸·피싱).',
      fix: 'Slack에서 웹훅을 재발급하고 서버에서만 호출하세요.'
    },
    {
      id: 'discord-webhook', name: 'Discord 웹훅 URL', sev: 'high', g: 1,
      re: /(https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{25,})/g,
      why: '웹훅 URL 노출 시 서버 채널에 임의 메시지를 보낼 수 있습니다.',
      fix: '채널 설정에서 웹훅을 삭제·재생성하고 서버 측에서만 보관하세요.'
    },
    {
      id: 'private-key', name: 'PEM 개인키', sev: 'critical', g: 1,
      re: PEM_RE,
      why: '개인키가 저장소에 들어가면 TLS·SSH·서명 위조가 가능합니다.',
      fix: '키를 폐기·재발급하고 저장소 기록에서 제거하세요(git filter-repo). 이후 .gitignore에 *.pem, *.key를 추가하세요.'
    },
    {
      id: 'firebase-private-key', name: 'Firebase 서비스 계정 개인키', sev: 'critical', g: 1,
      re: FIREBASE_PEM_RE,
      why: 'Firebase 서비스 계정 키는 Firestore·Storage·Auth 관리자 권한입니다.',
      fix: '서비스 계정 키를 삭제하고 서버에서만 사용하세요. 클라이언트에는 firebaseConfig(공개 값)만 둡니다.'
    },
    {
      id: 'db-connection-string', name: '비밀번호가 포함된 DB 연결 문자열', sev: 'critical', g: 1,
      re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s:@\/"'<>]+:[^\s:@\/"'<>]{3,}@[^\s"'<>]+)/gi,
      why: '연결 문자열에 DB 비밀번호가 들어 있어 그대로 DB 접속이 가능합니다.',
      fix: '비밀번호를 변경하고 연결 문자열은 서버 환경변수로만 보관하세요. 클라이언트 번들에 넣지 마세요.'
    },
    {
      id: 'basic-auth-url', name: 'URL에 포함된 Basic 인증 정보', sev: 'high', g: 1,
      re: /\b(https?:\/\/[^\s:@\/"'<>]+:[^\s:@\/"'<>]{4,}@[^\s"'<>]+)/g,
      why: 'URL에 아이디·비밀번호가 평문으로 남아 로그·리퍼러로 유출됩니다.',
      fix: 'URL에서 자격 증명을 제거하고 Authorization 헤더 또는 환경변수로 옮기세요.'
    },
    {
      id: 'sendgrid-key', name: 'SendGrid API 키', sev: 'critical', g: 1,
      re: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,})\b/g,
      why: 'SendGrid 키로 사용자 도메인에서 메일을 대량 발송할 수 있습니다.',
      fix: '키를 폐기하고 서버에서만 사용하세요. 발신 도메인 인증과 권한 제한을 설정하세요.'
    },
    {
      id: 'resend-key', name: 'Resend API 키', sev: 'critical', g: 1,
      re: /\b(re_[A-Za-z0-9]{16,}_[A-Za-z0-9]{8,})\b/g,
      why: 'Resend 키로 등록 도메인에서 메일을 발송할 수 있습니다.',
      fix: '키를 폐기하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'twilio-key', name: 'Twilio 자격 증명', sev: 'critical', g: 1,
      re: /\b(SK[0-9a-f]{32})\b/g, context: /twilio/i,
      why: 'Twilio 키로 문자·전화 발송 과금이 발생합니다.',
      fix: 'Twilio 콘솔에서 키를 폐기하고 서버에서만 사용하세요.'
    },
    {
      id: 'telegram-bot', name: 'Telegram 봇 토큰', sev: 'high', g: 1,
      re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{30,})\b/g,
      why: '봇 토큰으로 메시지 발송·수신이 가능합니다.',
      fix: 'BotFather에서 /revoke로 토큰을 재발급하고 서버에만 보관하세요.'
    },
    {
      id: 'npm-token', name: 'npm 액세스 토큰', sev: 'critical', g: 1,
      re: /\b(npm_[A-Za-z0-9]{36})\b/g,
      why: 'npm 토큰으로 패키지 배포(공급망 공격)가 가능합니다.',
      fix: 'npm에서 토큰을 revoke하고 2FA·granular 토큰을 사용하세요.'
    },
    {
      id: 'notion-token', name: 'Notion 통합 토큰', sev: 'high', g: 1,
      re: /\b(secret_[A-Za-z0-9]{43})\b/g,
      why: 'Notion 토큰으로 연결된 워크스페이스 문서를 읽고 쓸 수 있습니다.',
      fix: 'Notion integrations에서 토큰을 재발급하고 서버에만 보관하세요.'
    },
    {
      id: 'huggingface-token', name: 'Hugging Face 토큰', sev: 'high', g: 1,
      re: /\b(hf_[A-Za-z0-9]{30,})\b/g,
      why: 'HF 토큰으로 모델·데이터셋 접근과 크레딧 사용이 가능합니다.',
      fix: '토큰을 폐기하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'replicate-token', name: 'Replicate 토큰', sev: 'high', g: 1,
      re: /\b(r8_[A-Za-z0-9]{30,})\b/g,
      why: 'Replicate 토큰으로 GPU 과금이 발생할 수 있습니다.',
      fix: '토큰을 폐기하고 서버에서만 호출하세요.'
    },
    {
      id: 'groq-key', name: 'Groq API 키', sev: 'high', g: 1,
      re: /\b(gsk_[A-Za-z0-9]{40,})\b/g,
      why: 'Groq 키로 LLM 호출 과금이 발생합니다.',
      fix: '키를 폐기하고 서버 프록시를 통해 호출하세요.'
    },
    {
      id: 'openrouter-key', name: 'OpenRouter API 키', sev: 'high', g: 1,
      re: /\b(sk-or-v1-[A-Za-z0-9]{32,})\b/g,
      why: 'OpenRouter 키로 연결된 모든 모델을 사용자 크레딧으로 호출할 수 있습니다.',
      fix: '키를 폐기하고 서버에서만 사용하세요.'
    },
    {
      id: 'perplexity-key', name: 'Perplexity API 키', sev: 'high', g: 1,
      re: /\b(pplx-[A-Za-z0-9]{40,})\b/g,
      why: 'Perplexity 키로 검색·생성 호출 과금이 발생합니다.',
      fix: '키를 폐기하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'shopify-token', name: 'Shopify 액세스 토큰', sev: 'critical', g: 1,
      re: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g,
      why: 'Shopify 토큰으로 상품·주문·고객 정보에 접근할 수 있습니다.',
      fix: '앱에서 토큰을 재발급하고 서버에만 보관하세요.'
    },
    {
      id: 'digitalocean-token', name: 'DigitalOcean 토큰', sev: 'critical', g: 1,
      re: /\b(dop_v1_[a-f0-9]{64})\b/g,
      why: 'DigitalOcean 토큰으로 서버 생성·삭제가 가능합니다.',
      fix: '토큰을 revoke하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'kakao-key', name: '카카오 REST API 키', sev: 'high', g: 1,
      re: /\b(KakaoAK\s+[0-9a-f]{32})\b/g,
      why: '카카오 REST 키로 로그인·메시지·지도 API 쿼터를 도용할 수 있습니다.',
      fix: '카카오 디벨로퍼스에서 키를 재발급하고 허용 도메인·IP를 제한하세요.'
    },
    {
      id: 'naver-client-secret', name: '네이버 클라이언트 시크릿', sev: 'high', g: 1,
      re: /naver[^\n]{0,80}?client[_-]?secret\s*[:=]\s*['"]([A-Za-z0-9]{8,})['"]/gi,
      why: '네이버 클라이언트 시크릿으로 검색·로그인 API를 대신 호출할 수 있습니다.',
      fix: '네이버 개발자센터에서 재발급하고 서버 환경변수로 옮기세요.'
    },
    {
      id: 'portone-secret', name: '포트원(아임포트) API 시크릿', sev: 'critical', g: 1,
      re: /(?:imp[_-]?secret|portone[_-]?(?:api[_-]?)?secret)\s*[:=]\s*['"]([A-Za-z0-9-]{12,})['"]/gi,
      why: '포트원 시크릿으로 결제 조회·취소·가상계좌 조작이 가능합니다.',
      fix: '포트원 콘솔에서 시크릿을 재발급하고 서버에서만 사용하세요.'
    },
    {
      id: 'tosspayments-secret', name: '토스페이먼츠 시크릿 키', sev: 'critical', g: 1,
      re: /\b((?:test|live)_sk_[A-Za-z0-9]{20,})\b/g,
      why: '토스페이먼츠 시크릿 키로 결제 승인·취소가 가능합니다.',
      fix: '토스페이먼츠 콘솔에서 키를 재발급하고 서버에서만 사용하세요.'
    },
    {
      id: 'cloudflare-token', name: 'Cloudflare API 토큰', sev: 'critical', g: 1,
      re: /\b([A-Za-z0-9_-]{40})\b/g, context: /cloudflare/i, minEntropy: 4.0,
      why: 'Cloudflare 토큰으로 DNS·Workers·캐시 설정을 바꿀 수 있습니다.',
      fix: 'Cloudflare 대시보드에서 토큰을 롤링하고 서버에만 보관하세요.'
    },
    {
      id: 'vercel-token', name: 'Vercel 토큰', sev: 'high', g: 1,
      re: /\b([A-Za-z0-9]{24})\b/g, context: /vercel/i, minEntropy: 4.2,
      why: 'Vercel 토큰으로 프로젝트 배포·환경변수 조회가 가능합니다.',
      fix: 'Vercel 계정 설정에서 토큰을 삭제하고 CI 환경변수로만 쓰세요.'
    },
    {
      id: 'mux-token', name: 'Mux 토큰', sev: 'high', g: 1,
      re: /\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b/g, context: /mux/i,
      why: 'Mux 토큰으로 영상 업로드·재생 정책을 바꿀 수 있습니다.',
      fix: 'Mux 대시보드에서 토큰을 재발급하고 서버에만 보관하세요.'
    },
    {
      id: 'bearer-token', name: '하드코딩된 Bearer 토큰', sev: 'high', g: 1, minEntropy: 3.4,
      re: /authorization['"]?\s*[:=]\s*['"]bearer\s+([A-Za-z0-9\-._~+\/]{20,})['"]/gi,
      why: 'Authorization 헤더에 토큰이 코드로 박혀 있으면 배포본에서 그대로 추출됩니다.',
      fix: '토큰을 환경변수/세션에서 읽도록 바꾸고, 발급된 토큰은 폐기하세요.'
    },
    {
      id: 'generic-secret', name: '코드에 하드코딩된 비밀값', sev: 'high', g: 1, minEntropy: 3.5,
      re: /(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key|encryption[_-]?key|signing[_-]?secret|jwt[_-]?secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-\.\/+=$!@#%^&*]{12,})['"`]/gi,
      why: '이름은 비밀값인데 코드에 그대로 적혀 있습니다. 저장소를 본 사람은 그대로 사용할 수 있습니다.',
      fix: '값을 환경변수(.env, 호스팅 시크릿)로 옮기고 process.env / import.meta.env로 읽으세요. 노출된 값은 교체하세요.'
    }
  ];

  /* ── 2. 줄 단위 코드 규칙 ────────────────────────────────────────────────
     files   : 적용 확장자
     notFiles: 제외 (문서·테스트 등)
     re      : 그 줄에서 찾을 패턴
     unless  : 같이 있으면 안전한 경우(예: escaping, sanitize)
     escalate: 같은 줄에 이 패턴이 있으면 심각도 상향
     ──────────────────────────────────────────────────────────────────── */
  var JS = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|php|py|rb|go|java|kt)$/i;
  var WEB = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|html?|php)$/i;
  var DOCS = /(^|\/)(node_modules|vendor|dist|build|\.next|coverage|docs?|examples?|tests?|__tests__|__mocks__)\//i;

  var CODE_RULES = [
    {
      id: 'xss-innerhtml', name: 'innerHTML에 값 대입', cat: 'xss', sev: 'medium', files: WEB,
      re: /\.innerHTML\s*=\s*[^=]/,
      escalate: { re: /(\$\{|\+\s*[A-Za-z_$]|req\.|params\.|searchParams|location\.|\.value|data\.|\.(?:body|content|text|html|message|comment|input)\b)/, sev: 'high' },
      why: 'innerHTML은 문자열을 HTML로 해석합니다. 사용자 입력이 섞이면 <img onerror> 같은 스크립트가 그대로 실행됩니다.',
      fix: 'textContent를 쓰거나, HTML이 필요하면 DOMPurify.sanitize()를 거치세요.',
      cwe: 'CWE-79', refs: [REFS.owaspXss]
    },
    {
      id: 'xss-outerhtml', name: 'outerHTML에 값 대입', cat: 'xss', sev: 'medium', files: WEB,
      re: /\.outerHTML\s*=/,
      why: 'outerHTML도 HTML로 해석되어 주입 지점이 됩니다.',
      fix: 'textContent 또는 안전한 DOM API(createElement)를 사용하세요.', cwe: 'CWE-79', refs: [REFS.owaspXss]
    },
    {
      id: 'xss-document-write', name: 'document.write() 사용', cat: 'xss', sev: 'medium', files: WEB,
      re: /document\.write(?:ln)?\s*\(/,
      why: 'document.write는 외부 값이 섞이면 그대로 HTML로 실행되고, CSP·렌더링도 깨뜨립니다.',
      fix: 'DOM API로 요소를 만들어 붙이세요.', cwe: 'CWE-79', refs: [REFS.owaspXss]
    },
    {
      id: 'xss-insert-adjacent', name: 'insertAdjacentHTML 사용', cat: 'xss', sev: 'medium', files: WEB,
      re: /\.insertAdjacentHTML\s*\(/,
      why: 'insertAdjacentHTML은 innerHTML과 같습니다. 입력이 섞이면 XSS가 됩니다.',
      fix: 'insertAdjacentElement + textContent로 바꾸세요.', cwe: 'CWE-79'
    },
    {
      id: 'xss-dangerously', name: 'React dangerouslySetInnerHTML', cat: 'xss', sev: 'high', files: WEB,
      re: /dangerouslySetInnerHTML/,
      why: 'React가 의도적으로 막아 둔 HTML 주입을 여는 구멍입니다. AI가 만든 마크다운 렌더러에서 자주 터집니다.',
      fix: 'DOMPurify.sanitize(html)를 거친 값만 넣고, 가능하면 react-markdown으로 대체하세요.', cwe: 'CWE-79', refs: [REFS.owaspXss]
    },
    {
      id: 'code-eval', name: 'eval() 실행', cat: 'xss', sev: 'critical', files: WEB,
      re: /(^|[^.\w'"`])eval\s*\(/,
      why: 'eval은 문자열을 코드로 실행합니다. 조금이라도 외부 값이 닿으면 원격 코드 실행(RCE)입니다.',
      fix: 'eval을 제거하고 JSON.parse·명시적 분기로 바꾸세요. CSP로도 막으세요.', cwe: 'CWE-95'
    },
    {
      id: 'code-new-function', name: 'new Function() 동적 코드', cat: 'xss', sev: 'high', files: JS,
      re: /new\s+Function\s*\(/,
      why: 'new Function도 문자열을 코드로 만듭니다. eval과 같은 위험이 있습니다.',
      fix: '동적 실행이 필요하면 허용된 연산만 구현한 인터프리터/맵을 쓰세요.', cwe: 'CWE-95'
    },
    {
      id: 'code-timer-string', name: 'setTimeout/setInterval 문자열 실행', cat: 'xss', sev: 'medium', files: WEB,
      re: /(?:setTimeout|setInterval)\s*\(\s*['"`][^'"`]*['"`]/,
      why: '문자열을 넘기면 내부적으로 eval처럼 실행됩니다.',
      fix: '함수 참조를 넘기세요: setTimeout(() => fn(), 100).', cwe: 'CWE-95'
    },
    {
      id: 'xss-javascript-uri', name: "javascript: URL", cat: 'xss', sev: 'high', files: WEB,
      re: /(?:href|src|action)\s*=\s*\{?\s*['"`]javascript:/i,
      why: 'javascript: 링크는 클릭 시 스크립트를 실행합니다.',
      fix: 'http(s) URL만 허용하는 검증을 넣고 javascript:·data: 스킴을 차단하세요.', cwe: 'CWE-79'
    },
    {
      id: 'postmessage-wildcard', name: "postMessage 대상이 '*'", cat: 'xss', sev: 'high', files: WEB,
      re: /postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/,
      why: "origin을 '*'로 보내면 그 페이지를 iframe에 넣은 아무 사이트나 메시지를 받아갑니다.",
      fix: "수신측 도메인을 정확히 지정하세요: postMessage(data, 'https://app.example.com').", cwe: 'CWE-346'
    },
    {
      id: 'message-no-origin', name: 'message 이벤트 origin 미검사', cat: 'xss', sev: 'medium', files: WEB,
      re: /addEventListener\s*\(\s*['"]message['"]/, unless: /(event|e|evt|msg)\.origin\s*===|checkOrigin|allowedOrigin/i,
      why: 'message 이벤트는 모든 origin에서 옵니다. origin 검사가 없으면 다른 사이트가 앱을 조종할 수 있습니다.',
      fix: "핸들러 첫 줄에서 if (event.origin !== 'https://내도메인') return;", cwe: 'CWE-346'
    },
    {
      id: 'target-blank', name: 'rel="noopener" 없는 새 창', cat: 'xss', sev: 'low', files: WEB,
      re: /target\s*=\s*['"]_blank['"]/, unless: /noopener|noreferrer/,
      why: '외부 링크가 window.opener로 원래 탭을 조작할 수 있습니다(리버스 탭내빙).',
      fix: 'rel="noopener noreferrer"를 추가하세요.', cwe: 'CWE-1022'
    },
    {
      id: 'sql-template', name: 'SQL 문자열 결합(템플릿 리터럴)', cat: 'api', sev: 'critical', files: /\.(js|ts|jsx|tsx|mjs|py|php|rb|go)$/i,
      re: /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;'"`]{0,120}\$\{/i,
      why: 'SQL에 값을 문자열로 붙이면 SQL 인젝션입니다. 로그인 우회·DB 덤프로 이어집니다.',
      fix: '파라미터 바인딩으로 바꾸세요: pool.query("SELECT * FROM t WHERE id=$1", [id]).', cwe: 'CWE-89'
    },
    {
      id: 'sql-concat', name: 'SQL 문자열 + 결합', cat: 'api', sev: 'high', files: /\.(js|ts|jsx|tsx|mjs|py|php|rb|go)$/i,
      re: /(?:query|execute|raw)\s*\(\s*['"`][^'"`]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"`]*['"`]\s*\+/i,
      why: '쿼리 문자열에 변수를 더하면 인젝션 지점이 됩니다.',
      fix: '플레이스홀더($1, ?)와 파라미터 배열을 사용하세요.', cwe: 'CWE-89'
    },
    {
      id: 'cors-wildcard-credentials', name: 'CORS * + credentials 조합', cat: 'api', sev: 'critical', files: /\.(js|ts|mjs|cjs|py|php|json|conf|toml)$/i,
      re: /Access-Control-Allow-Origin['"]?\s*(?::|=|,)\s*['"]\*['"]/i,
      escalate: { re: /credentials\s*[:=]\s*true|Access-Control-Allow-Credentials/i, sev: 'critical' },
      why: '자격 증명을 허용하면서 origin을 *로 열면, 어떤 사이트든 로그인된 사용자의 데이터를 읽을 수 있습니다.',
      fix: "허용 origin 목록을 두고 정확히 일치할 때만 그 origin을 반환하세요. '*'와 credentials는 함께 쓸 수 없습니다.",
      cwe: 'CWE-942', refs: [REFS.owaspCors]
    },
    {
      id: 'cors-default', name: 'cors() 기본 설정(모든 origin 허용)', cat: 'api', sev: 'medium', files: /\.(js|ts|mjs|cjs)$/i,
      re: /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,
      why: 'cors()를 인자 없이 쓰면 모든 사이트가 API를 호출할 수 있습니다.',
      fix: "cors({ origin: ['https://내앱.com'] })처럼 allowlist를 지정하세요.", cwe: 'CWE-942', refs: [REFS.owaspCors]
    },
    {
      id: 'tls-verify-off', name: 'TLS 인증서 검증 해제', cat: 'api', sev: 'high', files: /\.(js|ts|mjs|cjs|py|go|rb)$/i,
      re: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/,
      why: 'TLS 검증을 끄면 중간자(MITM)가 트래픽을 가로채도 알 수 없습니다.',
      fix: '검증을 켜고, 사내 CA라면 NODE_EXTRA_CA_CERTS로 인증서를 신뢰시키세요.', cwe: 'CWE-295'
    },
    {
      id: 'hardcoded-jwt-secret', name: 'JWT/세션 시크릿 하드코딩', cat: 'crypto', sev: 'critical', files: JS,
      re: /(?:jwt[_-]?secret|session[_-]?secret|signing[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
      why: '시크릿을 알면 누구나 유효한 토큰을 위조해 관리자로 로그인할 수 있습니다.',
      fix: '32바이트 이상 무작위 값을 환경변수로 주입하고, 기존 토큰은 만료시키세요.', cwe: 'CWE-798'
    },
    {
      id: 'debug-true', name: '프로덕션 debug: true', cat: 'config', sev: 'medium', files: /\.(js|ts|mjs|cjs|json|py|php)$/i,
      re: /\bdebug\s*[:=]\s*true\b/i,
      why: '디버그 모드는 스택 트레이스·내부 경로·쿼리를 사용자에게 노출합니다.',
      fix: 'debug: process.env.NODE_ENV !== "production" 처럼 환경별로 켜세요.', cwe: 'CWE-489'
    },
    {
      id: 'cookie-no-httponly', name: '쿠키 HttpOnly 미설정', cat: 'auth', sev: 'medium', files: /\.(js|ts|jsx|tsx|mjs|cjs|py|php)$/i,
      re: /(?:res\.cookie|cookies?\.set|setCookie)\s*\(/,
      unless: /httpOnly\s*:\s*true|httponly|HttpOnly/i,
      why: 'HttpOnly가 없으면 XSS 한 번으로 세션 쿠키를 훔쳐 갈 수 있습니다.',
      fix: 'httpOnly: true, secure: true, sameSite: "lax"(또는 strict)를 넣으세요.', cwe: 'CWE-1004'
    },
    {
      id: 'cookie-samesite-none', name: 'SameSite=None 쿠키', cat: 'auth', sev: 'high', files: /\.(js|ts|jsx|tsx|mjs|cjs|py|php)$/i,
      re: /sameSite\s*[:=]\s*['"]?none['"]?/i, unless: /secure\s*:\s*true/i,
      why: 'SameSite=None + Secure 없음은 CSRF 방어가 사라진 상태입니다.',
      fix: 'SameSite=Lax를 기본으로 쓰고, 꼭 필요하면 Secure를 함께 지정하세요.', cwe: 'CWE-1275'
    },
    {
      id: 'localstorage-token', name: '토큰을 localStorage에 저장', cat: 'auth', sev: 'medium', files: WEB,
      re: /localStorage\.setItem\s*\(\s*['"`][^'"`]*(?:token|jwt|session|password|secret)/i,
      why: 'localStorage는 JS로 읽힙니다. XSS가 하나라도 있으면 세션이 그대로 탈취됩니다.',
      fix: '세션은 HttpOnly 쿠키로 두고, localStorage에는 서명된 짧은 참조만 두세요.', cwe: 'CWE-922'
    },
    {
      id: 'math-random-token', name: 'Math.random()으로 토큰 생성', cat: 'crypto', sev: 'medium', files: JS,
      re: /(?:token|otp|code|nonce|salt|reset)[^\n]{0,40}Math\.random\(\)/i,
      why: 'Math.random은 암호학적으로 안전하지 않아 예측 가능합니다.',
      fix: 'crypto.randomUUID() 또는 crypto.getRandomValues(new Uint8Array(32))를 쓰세요.', cwe: 'CWE-338'
    },
    {
      id: 'weak-hash-password', name: 'MD5/SHA1로 비밀번호 해시', cat: 'crypto', sev: 'high', files: /\.(js|ts|jsx|tsx|mjs|cjs|py|php|rb|go|java)$/i,
      re: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(|md5\s*\()/i,
      why: 'MD5/SHA1은 초당 수십억 번 대입이 가능해 비밀번호 저장에 부적합합니다.',
      fix: 'bcrypt(cost 12+) · scrypt · argon2id를 사용하세요.', cwe: 'CWE-327'
    },
    {
      id: 'hardcoded-password-check', name: '코드에 박힌 비밀번호 비교', cat: 'auth', sev: 'high', files: JS,
      re: /(?:password|passwd|admin[_-]?pw)\s*===?\s*['"][^'"]{3,}['"]/i,
      why: '비밀번호가 코드에 있어 배포본에서 추출되면 그대로 로그인됩니다.',
      fix: '해시 비교로 바꾸고 비밀번호는 DB/시크릿에 두세요.', cwe: 'CWE-798'
    },
    {
      id: 'exec-user-input', name: '명령 실행에 사용자 입력', cat: 'api', sev: 'critical', files: /\.(js|ts|mjs|cjs|py|php|rb|go)$/i,
      re: /(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/,
      why: '명령 문자열에 사용자 입력이 닿으면 서버 장악(RCE)으로 이어집니다.',
      fix: 'execFile에 인자 배열로 넘기고, 허용 목록으로 값을 검증하세요.', cwe: 'CWE-78'
    },
    {
      id: 'path-traversal', name: '파일 경로에 사용자 입력', cat: 'api', sev: 'high', files: /\.(js|ts|mjs|cjs|py|php|rb|go)$/i,
      re: /(?:readFile|readFileSync|writeFile|createReadStream|sendFile)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/,
      why: '\'../../etc/passwd\' 같은 경로로 서버 파일을 읽을 수 있습니다.',
      fix: 'path.basename()으로 파일명만 받고, 기준 디렉터리 안인지 path.resolve 후 확인하세요.', cwe: 'CWE-22'
    },
    {
      id: 'open-redirect', name: '입력값으로 리다이렉트', cat: 'auth', sev: 'medium', files: /\.(js|ts|mjs|cjs|py|php)$/i,
      re: /(?:res\.redirect|redirect|location\.href\s*=)\s*\(?\s*(?:req\.|request\.|params\.|query\.)/,
      why: '외부 URL로 튕길 수 있어 피싱·토큰 탈취에 쓰입니다.',
      fix: '허용 경로 목록과 대조하고, 없다면 "/"로 보내세요.', cwe: 'CWE-601'
    },
    {
      id: 'ssrf-fetch', name: '사용자 입력 URL을 서버에서 fetch', cat: 'api', sev: 'high', files: /\.(js|ts|mjs|cjs|py|php)$/i,
      re: /(?:fetch|axios\.get|axios\.post|requests\.get|http\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/,
      why: '내부 메타데이터(169.254.169.254)·관리 포트로 요청을 보내게 만들 수 있습니다(SSRF).',
      fix: '허용 도메인 allowlist + 사설 IP 차단을 적용하세요.', cwe: 'CWE-918'
    },
    {
      id: 'env-fallback-secret', name: '환경변수 기본값으로 들어간 시크릿', cat: 'config', sev: 'high', files: JS,
      re: /process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|SALT|CREDENTIAL)[A-Z0-9_]*\s*\|\|\s*['"](?!https?:\/\/)[^'"]{10,}['"]/i,
      why: '환경변수가 비어 있으면 하드코딩된 값이 실제로 쓰입니다. 결국 시크릿이 저장소에 있는 것과 같습니다.',
      fix: '기본값을 없애고 누락 시 부팅 실패하게 만드세요(필수 환경변수 검증).', cwe: 'CWE-798'
    },
    {
      id: 'public-env-secret', name: 'NEXT_PUBLIC/VITE 환경변수에 시크릿', cat: 'config', sev: 'critical', files: /\.(js|ts|jsx|tsx|mjs|cjs|env|env\.\w+|md)$/i,
      re: /(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|ADMIN|TOKEN|API_KEY)[A-Z0-9_]*/,
      why: '이 접두사가 붙은 값은 빌드되어 브라우저 번들에 그대로 들어갑니다. "환경변수"라고 안전한 게 아닙니다.',
      fix: '시크릿은 접두사 없는 서버 전용 변수로 옮기고, 클라이언트에는 공개 가능한 값만 두세요.', cwe: 'CWE-200'
    },
    {
      id: 'service-role-client', name: '클라이언트 코드에 service_role 키', cat: 'auth', sev: 'critical', files: /\.(js|ts|jsx|tsx|mjs|cjs|vue|svelte)$/i,
      re: /service[_-]?role|SUPABASE_SERVICE|sb_secret_/i,
      notFiles: /(^|\/)(api|server|serverless|functions|workers?|routes?|app\/api)\//i,
      why: 'service_role 키는 RLS를 무시합니다. 브라우저 번들에 들어가면 누구나 DB 전체를 읽고 쓸 수 있습니다.',
      fix: 'service_role은 서버(Route Handler·Edge Function)에서만 쓰고, 클라이언트는 anon 키 + RLS로 보호하세요.',
      cwe: 'CWE-269', refs: [REFS.supabaseKeys]
    },
    {
      id: 'jwt-decode-client', name: 'JWT를 검증 없이 디코드', cat: 'auth', sev: 'medium', files: JS,
      re: /(?:jwt[_-]?decode|decodeJwt|atob\s*\(\s*[^)]*\.split\(['"]\.['"]\))/i,
      why: '서명 검증 없이 payload를 믿으면 토큰을 위조한 사용자가 관리자로 통과합니다.',
      fix: '서버에서 jwtVerify(토큰, 시크릿)로 검증한 뒤 클레임을 읽으세요.', cwe: 'CWE-347'
    },
    {
      id: 'sourcemap-exposed', name: '프로덕션 소스맵 참조', cat: 'git', sev: 'low', files: /\.(js|css|html)$/i, allowComment: true,
      re: /\/\/[#@]\s*sourceMappingURL=/,
      why: '소스맵이 함께 배포되면 원본 소스·주석·내부 구조가 그대로 공개됩니다.',
      fix: '프로덕션 빌드에서 sourcemap: false 또는 hidden-source-map을 쓰고, .map 접근을 막으세요.', cwe: 'CWE-540'
    },
    {
      id: 'http-api-client', name: '클라이언트에서 http:// API 호출', cat: 'config', sev: 'low', files: WEB,
      re: /['"`]http:\/\/(?!localhost|127\.0\.0\.1)[a-z0-9.-]+/i,
      why: 'HTTPS 페이지에서 http:// 호출은 차단되거나(혼합 콘텐츠) 평문으로 노출됩니다.',
      fix: 'https://로 바꾸고 HSTS를 켜세요.', cwe: 'CWE-319'
    },
    {
      id: 'console-secret-log', name: '민감값 콘솔 로그', cat: 'git', sev: 'low', files: JS,
      re: /console\.(?:log|info|debug)\s*\([^)]*(?:token|password|secret|apiKey|authorization)/i,
      why: '브라우저 콘솔·로그 수집기(Sentry 등)에 토큰이 남습니다.',
      fix: '로그에서 민감값을 빼고, 디버그 로그는 빌드에서 제거하세요.', cwe: 'CWE-532'
    },
    {
      id: 'rate-limit-missing', name: 'AI/결제 엔드포인트 rate limit 없음', cat: 'api', sev: 'low',
      files: /(^|\/)(api|server|functions|workers?)\/.*\.(js|ts|mjs)$/i,
      fileScan: function (file) {
        var c = file.content;
        if (!/(openai|anthropic|gemini|claude|gpt|stripe|portone|tosspayments|결제|chat)/i.test(c)) return [];
        if (/(rateLimit|rate-limit|ratelimit|upstash\/ratelimit|limiter|throttle|@vercel\/kv)/i.test(c)) return [];
        return [{ line: 1, note: 'LLM·결제 호출이 있는 핸들러에 요청 한도 장치가 보이지 않습니다.' }];
      },
      why: '공개된 AI·결제 엔드포인트는 그대로 과금 폭탄과 남용 통로가 됩니다.',
      fix: 'IP·사용자별 분당 한도(예: 10회/분)와 일일 상한을 두고, 실패도 카운트하세요.', cwe: 'CWE-770'
    }
  ];

  /* ── 3. 파일 전체 문맥 규칙 ─────────────────────────────────────────────
     scan(file) → [{ line, note? }]
     ──────────────────────────────────────────────────────────────────── */
  var FILE_RULES = [
    {
      id: 'supabase-rls-missing', name: 'Supabase 테이블에 RLS 없음', cat: 'auth', sev: 'critical',
      files: /\.sql$/i, notFiles: /(^|\/)(node_modules|migrations\/archive)\//i,
      scan: function (file) {
        var out = [];
        var re = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:["']?public["']?\.)?["']?([a-z0-9_]+)["']?/gi;
        var m;
        while ((m = re.exec(file.content))) {
          var table = m[1];
          var line = file.lineAt(m.index);
          var after = file.content.slice(m.index);
          var rls = new RegExp('alter\\s+table\\s+(?:["\\\']?public["\\\']?\\.)?["\\\']?' + table + '["\\\']?[\\s\\S]{0,120}?enable\\s+row\\s+level\\s+security', 'i');
          if (!rls.test(after)) out.push({ line: line, note: table + ' 테이블에 ENABLE ROW LEVEL SECURITY가 없습니다.' });
        }
        return out;
      },
      why: 'RLS가 꺼진 Supabase 테이블은 anon 키만으로 전 행을 읽고 쓸 수 있습니다. 바이브 코딩 앱 유출 사고의 1번 원인입니다.',
      fix: 'alter table public.<table> enable row level security; 를 추가하고, select/insert/update/delete 정책을 각각 만드세요.',
      cwe: 'CWE-284', refs: [REFS.owaspRls]
    },
    {
      id: 'supabase-rls-true', name: 'RLS 정책이 true(전체 허용)', cat: 'auth', sev: 'high',
      files: /\.sql$/i,
      scan: function (file) {
        var out = [], re = /(using|with\s+check)\s*\(\s*true\s*\)/gi, m;
        while ((m = re.exec(file.content))) out.push({ line: file.lineAt(m.index), note: m[1].toUpperCase() + ' (true) 정책' });
        return out;
      },
      why: 'RLS를 켰어도 USING (true)면 정책이 모든 행을 허용합니다. 켠 것처럼 보이지만 아무것도 막지 않습니다.',
      fix: 'auth.uid() = user_id 같은 실제 소유자 조건으로 바꾸세요.',
      cwe: 'CWE-284', refs: [REFS.owaspRls]
    },
    {
      id: 'supabase-view-definer', name: 'security_invoker 없는 View', cat: 'db', sev: 'medium',
      files: /\.sql$/i,
      scan: function (file) {
        var out = [], re = /create\s+(?:or\s+replace\s+)?view\s+[\s\S]{0,400}?;/gi, m;
        while ((m = re.exec(file.content))) {
          if (!/security_invoker\s*=\s*(?:true|on)/i.test(m[0])) out.push({ line: file.lineAt(m.index), note: '뷰가 소유자 권한으로 실행됩니다(definer).' });
        }
        return out;
      },
      why: '기본 View는 만든 사람(소유자) 권한으로 돌아 RLS를 우회해 데이터가 새어 나갈 수 있습니다.',
      fix: 'create view ... with (security_invoker = true); 로 만드세요.',
      cwe: 'CWE-284', refs: [REFS.owaspRls]
    },
    {
      id: 'firestore-open-rules', name: 'Firestore 규칙 전체 공개', cat: 'auth', sev: 'critical',
      files: /firestore\.rules$/i,
      scan: function (file) {
        var out = [], re = /allow\s+(read\s*,\s*write|write\s*,\s*read|read|write)\s*:\s*if\s+(true|request\.auth\s*==\s*null)\s*;/g, m;
        while ((m = re.exec(file.content))) out.push({ line: file.lineAt(m.index), note: 'allow ' + m[1] + ': if ' + m[2] });
        return out;
      },
      why: '규칙이 true면 누구나(비로그인 포함) 전체 컬렉션을 읽고 쓸 수 있습니다.',
      fix: 'request.auth != null && request.auth.uid == resource.data.ownerId 같은 소유자 조건으로 바꾸세요.',
      cwe: 'CWE-284'
    },
    {
      id: 'stripe-webhook-unverified', name: 'Stripe 웹훅 서명 미검증', cat: 'api', sev: 'high',
      files: /\.(js|ts|mjs|py|php)$/i,
      fileScan: function (file) {
        if (!/stripe/i.test(file.content)) return [];
        var hasWebhook = /webhook/i.test(file.content) || /checkout\.session\.completed|payment_intent\.succeeded/.test(file.content);
        if (!hasWebhook) return [];
        if (/constructEvent|construct_event|Webhook\.constructEvent|stripe\.webhooks/.test(file.content)) return [];
        return [{ line: file.lineOf(/webhook/i) || 1, note: '웹훅 처리 코드에 constructEvent 서명 검증이 없습니다.' }];
      },
      why: '서명 검증이 없으면 누구나 "결제 완료" 이벤트를 POST해 무료로 유료 기능을 열 수 있습니다.',
      fix: 'const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET); 로 검증하고, 실패 시 400을 반환하세요.',
      cwe: 'CWE-347', refs: [REFS.stripeWebhook]
    },
    {
      id: 'security-headers-missing', name: '보안 헤더 설정 누락', cat: 'config', sev: 'medium',
      files: /(^|\/)(_headers|vercel\.json|next\.config\.(?:js|mjs|ts)|netlify\.toml|nginx\.conf|server\.(?:js|ts)|app\.(?:js|ts)|index\.(?:js|ts))$/i,
      fileScan: function (file) {
        var c = file.content;
        var isConfigPath = /(^|\/)(_headers|vercel\.json|next\.config\.(?:js|mjs|ts)|netlify\.toml|nginx\.conf)$/i.test(file.path);
        if (!isConfigPath && !/(res\.setHeader\s*\(\s*['"]Content-Security-Policy|add_header\s+Content-Security-Policy)/i.test(c)) return [];
        var missing = [];
        if (!/content-security-policy/i.test(c)) missing.push('CSP');
        if (!/strict-transport-security/i.test(c)) missing.push('HSTS');
        if (!/x-content-type-options/i.test(c)) missing.push('X-Content-Type-Options');
        if (!/referrer-policy/i.test(c)) missing.push('Referrer-Policy');
        if (!missing.length) return [];
        return [{ line: 1, note: '누락: ' + missing.join(', ') }];
      },
      why: '헤더가 없으면 XSS가 그대로 실행되고, 클릭재킹·MIME 스니핑·리퍼러 유출에 노출됩니다.',
      fix: '방어팩 탭에서 호스팅에 맞는 헤더 파일을 생성해 붙여넣으세요. 최소 CSP·HSTS·nosniff·Referrer-Policy를 넣습니다.',
      cwe: 'CWE-693', refs: [REFS.mdnCsp]
    },
    {
      id: 'gitignore-missing-entries', name: '권장: .gitignore에 .env 무시', cat: 'git', sev: 'low',
      files: /(^|\/)\.gitignore$/i,
      fileScan: function (file) {
        var need = ['.env', '*.pem', '*.key'], missing = [];
        need.forEach(function (n) {
          var re = new RegExp('(^|\\n)\\s*' + n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*($|\\n)', 'i');
          if (!re.test(file.content)) missing.push(n);
        });
        if (!missing.length) return [];
        return [{ line: 1, note: '누락: ' + missing.join(', ') }];
      },
      why: 'process.env를 쓰는 코드가 있습니다. .env 파일을 만든다면 커밋되지 않도록 무시 규칙을 두는 편이 안전합니다.',
      fix: '방어팩의 .gitignore를 참고하세요. 이미 커밋했다면 기록에서 제거하고 키를 교체해야 합니다.',
      cwe: 'CWE-538'
    },
    {
      id: 'env-file-committed', name: '환경변수 파일이 스캔 대상에 포함', cat: 'git', sev: 'critical',
      files: /(^|\/)\.env(\.local|\.production|\.development|\.preview)?$/i,
      fileScan: function (file) {
        if (!/^[A-Z0-9_]+\s*=\s*\S+/m.test(file.content)) return [];
        return [{ line: 1, note: '값이 채워진 .env 파일입니다.' }];
      },
      why: '.env에 실제 키가 들어 있는 채로 저장소·배포본에 포함되면 그대로 유출됩니다.',
      fix: '.env를 .gitignore에 넣고, 호스팅의 환경변수(Secrets)로 옮기세요. 이미 올렸다면 모든 값을 교체하세요.',
      cwe: 'CWE-538'
    },
    {
      id: 'cors-config-wildcard', name: '설정 파일의 CORS 전체 허용', cat: 'api', sev: 'high',
      files: /(_headers|vercel\.json|netlify\.toml|nginx\.conf|\.toml)$/i,
      fileScan: function (file) {
        var out = [], re = /access-control-allow-origin\s*[:=]?\s*["']?\*/gi, m;
        while ((m = re.exec(file.content))) out.push({ line: file.lineAt(m.index), note: 'Access-Control-Allow-Origin: *' });
        return out;
      },
      why: '모든 사이트가 API 응답을 읽을 수 있게 됩니다. 인증 쿠키와 함께면 더 위험합니다.',
      fix: '허용할 프런트 도메인만 나열하세요.',
      cwe: 'CWE-942', refs: [REFS.owaspCors]
    },
    {
      id: 'hardcoded-basic-auth', name: '하드코딩된 Basic 인증 헤더', cat: 'api', sev: 'high',
      files: /\.(js|ts|mjs|py|php|json)$/i,
      re: /basic\s+[A-Za-z0-9+/=]{16,}/i,
      why: 'Basic 인증 값은 디코드하면 아이디:비밀번호가 그대로 나옵니다.',
      fix: '자격 증명을 환경변수로 옮기고, 토큰 방식(OAuth)으로 바꾸세요.',
      cwe: 'CWE-798'
    },
    {
      id: 'todo-security', name: '보안 TODO 방치', cat: 'config', sev: 'low', allowComment: true,
      files: /\.(js|ts|jsx|tsx|mjs|py|php|rb|go|sql)$/i,
      re: /(?:TODO|FIXME|HACK)[^\n]{0,60}(?:auth|security|csrf|sanitiz|xss|permission|권한|인증|보안)/i,
      why: '나중에 처리하려던 보안 항목이 그대로 배포되는 경우가 많습니다.',
      fix: '배포 전에 처리하거나 이슈로 옮기고 코드에서는 제거하세요.', cwe: 'CWE-1059'
    }
  ];

  /* 파일 규칙 중 code 항목처럼 re/fileScan을 가진 것은 core에서 공통 처리한다. */
  return {
    VERSION: VERSION,
    CATEGORIES: CATEGORIES,
    SEVERITY: SEVERITY,
    REFS: REFS,
    SECRET_RULES: SECRET_RULES,
    CODE_RULES: CODE_RULES,
    FILE_RULES: FILE_RULES,
    DOCS: DOCS
  };
});
