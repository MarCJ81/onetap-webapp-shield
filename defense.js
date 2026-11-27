/* ============================================================================
   defense.js · 자동 방어 장치 (방어팩 생성기)
   ----------------------------------------------------------------------------
   - 호스팅별 보안 헤더 파일 (Cloudflare/Netlify _headers, vercel.json,
     next.config.mjs, nginx.conf, Express/Node 미들웨어)
   - 비주얼 CSP 빌더 (쓰는 서비스만 체크 → 정확한 출처 목록 조립)
   - 개발자 가드레일 키트: .gitignore, .gitleaks.toml, pre-commit 훅,
     GitHub Actions 보안 CI, AI 코딩 에이전트용 SECURITY_RULES.md
   - 전체를 .zip으로 묶는 무의존 ZIP 작성기(store, CRC32)

   브라우저 · node 공용. 의존성 0.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DEFENSE = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '1.1.0';
  var TOOL_URL = 'https://marcj81.github.io/onetap-webapp-shield/';

  /* ── CSP 서비스 카탈로그 ─────────────────────────────────────────────── */

  var SERVICES = [
    { id: 'google-fonts', label: 'Google Fonts', note: '웹폰트', csp: { style: ['https://fonts.googleapis.com'], font: ['https://fonts.gstatic.com'] } },
    { id: 'pretendard', label: 'Pretendard CDN', note: 'jsDelivr 폰트', csp: { style: ['https://cdn.jsdelivr.net'], font: ['https://cdn.jsdelivr.net'] } },
    { id: 'ga4', label: 'GA4 · Google Tag', note: '분석', csp: { script: ['https://www.googletagmanager.com'], img: ['https://*.google-analytics.com', 'https://www.googletagmanager.com'], connect: ['https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://www.googletagmanager.com'] } },
    { id: 'meta-pixel', label: 'Meta Pixel', note: '광고 추적', csp: { script: ['https://connect.facebook.net'], img: ['https://www.facebook.com'], connect: ['https://www.facebook.com', 'https://connect.facebook.net'] } },
    { id: 'openai', label: 'OpenAI API', note: 'LLM', csp: { connect: ['https://api.openai.com'] } },
    { id: 'anthropic', label: 'Anthropic API', note: 'LLM', csp: { connect: ['https://api.anthropic.com'] } },
    { id: 'gemini', label: 'Google Gemini API', note: 'LLM', csp: { connect: ['https://generativelanguage.googleapis.com'] } },
    { id: 'workers-ai', label: 'Cloudflare Workers', note: 'AI 프록시', csp: { connect: ['https://*.workers.dev'] } },
    { id: 'supabase', label: 'Supabase', note: 'DB·Auth·Storage', csp: { connect: ['https://*.supabase.co', 'wss://*.supabase.co'], img: ['https://*.supabase.co'] } },
    { id: 'firebase', label: 'Firebase', note: 'Auth·Firestore', csp: { script: ['https://apis.google.com'], connect: ['https://*.googleapis.com', 'https://*.firebaseio.com', 'wss://*.firebaseio.com', 'https://*.cloudfunctions.net'], frame: ['https://*.firebaseapp.com', 'https://accounts.google.com'], img: ['https://*.googleusercontent.com'] } },
    { id: 'google-oauth', label: 'Google 로그인', note: 'OAuth', csp: { script: ['https://accounts.google.com'], frame: ['https://accounts.google.com'], connect: ['https://accounts.google.com'] } },
    { id: 'stripe', label: 'Stripe', note: '결제', csp: { script: ['https://js.stripe.com'], frame: ['https://js.stripe.com', 'https://hooks.stripe.com'], connect: ['https://api.stripe.com'] } },
    { id: 'tosspayments', label: '토스페이먼츠', note: '결제', csp: { script: ['https://js.tosspayments.com'], frame: ['https://*.tosspayments.com'], connect: ['https://api.tosspayments.com'] } },
    { id: 'portone', label: '포트원(아임포트)', note: '결제', csp: { script: ['https://cdn.iamport.kr'], frame: ['https://*.iamport.kr', 'https://*.portone.io'], connect: ['https://api.iamport.kr', 'https://api.portone.io'] } },
    { id: 'sentry', label: 'Sentry', note: '에러 수집', csp: { connect: ['https://*.ingest.sentry.io', 'https://*.sentry.io'], script: ['https://js.sentry-cdn.com'] } },
    { id: 'vercel-analytics', label: 'Vercel Analytics', note: '분석', csp: { script: ['https://va.vercel-scripts.com'], connect: ['https://vitals.vercel-insights.com'] } },
    { id: 'youtube', label: 'YouTube 임베드', note: '영상', csp: { frame: ['https://www.youtube.com', 'https://www.youtube-nocookie.com'], img: ['https://i.ytimg.com'] } },
    { id: 'google-maps', label: 'Google Maps', note: '지도', csp: { script: ['https://maps.googleapis.com'], img: ['https://maps.gstatic.com', 'https://*.googleapis.com', 'https://*.ggpht.com'], connect: ['https://maps.googleapis.com'] } },
    { id: 'kakao-map', label: '카카오맵', note: '지도', csp: { script: ['https://dapi.kakao.com'], connect: ['https://dapi.kakao.com'], img: ['https://*.daumcdn.net', 'https://*.kakaocdn.net'] } },
    { id: 'naver-map', label: '네이버 지도', note: '지도', csp: { script: ['https://oapi.map.naver.com', 'https://openapi.map.naver.com'], img: ['https://*.pstatic.net', 'https://*.naver.com'], connect: ['https://oapi.map.naver.com'] } },
    { id: 'cloudinary', label: 'Cloudinary', note: '이미지', csp: { img: ['https://res.cloudinary.com'], connect: ['https://api.cloudinary.com'] } },
    { id: 'tawk', label: 'Tawk.to 상담', note: '채팅', csp: { script: ['https://embed.tawk.to'], frame: ['https://embed.tawk.to'], connect: ['https://*.tawk.to', 'wss://*.tawk.to'] } }
  ];

  var DIRECTIVES = ['script', 'style', 'img', 'font', 'connect', 'frame', 'media'];

  function uniq(list) {
    var seen = Object.create(null), out = [];
    list.forEach(function (v) { if (v && !seen[v]) { seen[v] = 1; out.push(v); } });
    return out;
  }

  /**
   * csp({ services:['supabase','ga4'], inlineStyle:true, frameAncestors:"'none'" })
   * → "default-src 'self'; script-src ..."
   */
  function csp(opts) {
    opts = opts || {};
    var picked = (opts.services || []).map(function (id) {
      return SERVICES.filter(function (s) { return s.id === id; })[0];
    }).filter(Boolean);

    var acc = { script: [], style: [], img: [], font: [], connect: [], frame: [], media: [] };
    picked.forEach(function (s) {
      Object.keys(s.csp).forEach(function (k) { if (acc[k]) acc[k] = acc[k].concat(s.csp[k]); });
    });

    var parts = [];
    parts.push("default-src 'self'");
    parts.push("script-src 'self'" + (acc.script.length ? ' ' + uniq(acc.script).join(' ') : ''));
    parts.push("style-src 'self'" + (opts.inlineStyle === false ? '' : " 'unsafe-inline'") + (acc.style.length ? ' ' + uniq(acc.style).join(' ') : ''));
    parts.push("img-src 'self' data: blob:" + (acc.img.length ? ' ' + uniq(acc.img).join(' ') : ''));
    parts.push("font-src 'self' data:" + (acc.font.length ? ' ' + uniq(acc.font).join(' ') : ''));
    parts.push("connect-src 'self'" + (acc.connect.length ? ' ' + uniq(acc.connect).join(' ') : ''));
    parts.push(acc.frame.length ? 'frame-src ' + uniq(acc.frame).join(' ') : "frame-src 'none'");
    if (acc.media.length) parts.push('media-src ' + uniq(acc.media).join(' '));
    parts.push("frame-ancestors " + (opts.frameAncestors || "'none'"));
    parts.push("base-uri 'self'");
    parts.push("form-action 'self'");
    parts.push("object-src 'none'");
    if (opts.upgrade !== false) parts.push('upgrade-insecure-requests');
    return parts.join('; ');
  }

  /* ── 헤더 한 벌 ─────────────────────────────────────────────────────── */

  function headerPairs(opts) {
    opts = opts || {};
    var pairs = [
      ['Content-Security-Policy', opts.csp || csp(opts)],
      ['Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload'],
      ['X-Content-Type-Options', 'nosniff'],
      ['X-Frame-Options', 'DENY'],
      ['Referrer-Policy', 'strict-origin-when-cross-origin'],
      ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
      ['Cross-Origin-Opener-Policy', 'same-origin'],
      ['Cross-Origin-Resource-Policy', 'same-origin'],
      ['X-XSS-Protection', '0']
    ];
    if (opts.permissions) pairs[5][1] = opts.permissions;
    return pairs;
  }

  var HOSTINGS = [
    { id: 'cloudflare', label: 'Cloudflare Pages', path: 'public/_headers', lang: 'text', note: '정적 배포에 가장 간단. public 폴더에 넣으면 빌드 후 루트로 복사됩니다.' },
    { id: 'netlify', label: 'Netlify', path: '_headers', lang: 'text', note: '저장소 루트(또는 publish 폴더)에 _headers 파일을 둡니다.' },
    { id: 'vercel', label: 'Vercel', path: 'vercel.json', lang: 'json', note: '기존 vercel.json이 있으면 headers 배열만 병합하세요.' },
    { id: 'next', label: 'Next.js', path: 'next.config.mjs', lang: 'js', note: '기존 next.config 파일의 headers()에 배열을 합치세요.' },
    { id: 'nginx', label: 'Nginx · 직접 서버', path: 'nginx.conf', lang: 'nginx', note: 'server 블록 안에 넣습니다. 항상 적용하려면 always를 유지하세요.' },
    { id: 'express', label: 'Express · Node', path: 'server-headers.js', lang: 'js', note: 'app.use(securityHeaders)를 라우트보다 먼저 등록하세요.' }
  ];

  function headersFile(hostingId, opts) {
    opts = opts || {};
    var h = HOSTINGS.filter(function (x) { return x.id === hostingId; })[0] || HOSTINGS[0];
    var pairs = headerPairs(opts);
    var cspValue = pairs[0][1];

    if (h.id === 'cloudflare' || h.id === 'netlify') {
      var out = [
        '# ' + h.label + ' Security headers — generated by OneTap WebApp Shield',
        '# If CSP blocks something, add the service in the CSP builder of the defence pack and regenerate.',
        '/*',
        '  ! Cache-Control'
      ];
      pairs.forEach(function (p) { out.push('  ' + p[0] + ': ' + p[1]); });
      out.push('');
      out.push('# Long cache for hashed static assets');
      out.push('/assets/*');
      out.push('  Cache-Control: public, max-age=31536000, immutable');
      return out.join('\n');
    }

    if (h.id === 'vercel') {
      var headers = pairs.map(function (p) { return { key: p[0], value: p[1] }; });
      return JSON.stringify({
        $schema: 'https://openapi.vercel.sh/vercel.json',
        headers: [{ source: '/(.*)', headers: headers }]
      }, null, 2) + '\n';
    }

    if (h.id === 'next') {
      return [
        '// next.config.mjs — OneTap WebApp Shield',
        '/** @type {import("next").NextConfig} */',
        'const securityHeaders = [',
        pairs.map(function (p) { return '  { key: ' + JSON.stringify(p[0]) + ', value: ' + JSON.stringify(p[1]) + ' }'; }).join(',\n'),
        '];',
        '',
        'const nextConfig = {',
        '  async headers() {',
        "    return [{ source: '/(.*)', headers: securityHeaders }];",
        '  },',
        '  poweredByHeader: false,',
        '};',
        '',
        'export default nextConfig;',
        ''
      ].join('\n');
    }

    if (h.id === 'nginx') {
      return [
        '# nginx.conf — put this inside the server { } block (OneTap WebApp Shield)',
        'server {',
        '  listen 443 ssl http2;',
        '  server_name example.com;',
        '',
        '  # TLS (Let’s Encrypt)',
        '  ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;',
        '  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;',
        '  ssl_protocols TLSv1.2 TLSv1.3;',
        '',
        pairs.map(function (p) { return '  add_header ' + p[0] + ' "' + p[1].replace(/"/g, '\\"') + '" always;'; }).join('\n'),
        '',
        '  # block .env, .git and source maps',
        '  location ~ /\\.(?!well-known) { deny all; }',
        '  location ~* \\.(map|pem|key|sqlite|bak)$ { deny all; }',
        '',
        '  root /var/www/app;',
        '  try_files $uri /index.html;',
        '}',
        ''
      ].join('\n');
    }

    // express
    return [
      '// server-headers.js — OneTap WebApp Shield',
      '// app.use(securityHeaders) 를 모든 라우트보다 먼저 등록하세요.',
      'const CSP = ' + JSON.stringify(cspValue) + ';',
      '',
      'export function securityHeaders(req, res, next) {',
      pairs.filter(function (p) { return p[0] !== 'Content-Security-Policy'; }).map(function (p) {
        return '  res.setHeader(' + JSON.stringify(p[0]) + ', ' + JSON.stringify(p[1]) + ');';
      }).join('\n'),
      "  res.setHeader('Content-Security-Policy', CSP);",
      '  next();',
      '}',
      ''
    ].join('\n');
  }

  function headersFiles(opts) {
    return HOSTINGS.map(function (h) {
      return { id: h.id, path: h.path, label: h.label, lang: h.lang, note: h.note, content: headersFile(h.id, opts) };
    });
  }

  /* ── 가드레일 키트 ──────────────────────────────────────────────────── */

  function gitignore() {
    return [
      '# ── 시크릿 · 키 ─────────────────────────────',
      '.env',
      '.env.*',
      '!.env.example',
      '*.pem',
      '*.key',
      '*.p12',
      '*.pfx',
      '*.keystore',
      'secrets.json',
      'service-account*.json',
      '',
      '# ── DB · 백업 ───────────────────────────────',
      '*.sqlite',
      '*.sqlite3',
      '*.db',
      '*.dump',
      '*.bak',
      '',
      '# ── 빌드 · 캐시 ─────────────────────────────',
      'node_modules/',
      '.next/',
      '.nuxt/',
      'dist/',
      'build/',
      'out/',
      '.vercel/',
      '.netlify/',
      '.wrangler/',
      'coverage/',
      '*.tsbuildinfo',
      '',
      '# ── 로그 · 로컬 ─────────────────────────────',
      '*.log',
      'npm-debug.log*',
      '.DS_Store',
      'Thumbs.db',
      '.idea/',
      '.vscode/*',
      '!.vscode/extensions.json',
      '',
      '# ── 소스맵(프로덕션 노출 방지) ──────────────',
      '*.map',
      ''
    ].join('\n');
  }

  function gitleaksToml() {
    return [
      '# .gitleaks.toml — OneTap WebApp Shield',
      '# 설치: https://github.com/gitleaks/gitleaks',
      '# 실행: gitleaks detect --source . --redact',
      '',
      '[extend]',
      'useDefault = true   # Gitleaks 기본 규칙(180+ 제공자 패턴)을 그대로 사용',
      '',
      '[[rules]]',
      'id = "generic-api-key"',
      'description = "하드코딩된 API 키/시크릿"',
      'regex = \'\'\'(?i)(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\\s*[:=]\\s*["\\\']([A-Za-z0-9_\\-./+=]{16,})["\\\']\'\'\'',
      'entropy = 3.5',
      'secretGroup = 2',
      'keywords = ["api", "key", "secret", "token", "password"]',
      '',
      '# 예제·문서·테스트 픽스처는 오탐이 많아 제외합니다.',
      '[allowlist]',
      'description = "문서와 테스트의 더미 값"',
      'paths = [',
      '  \'\'\'(^|/)node_modules/\'\'\',',
      '  \'\'\'(^|/)dist/\'\'\',',
      '  \'\'\'(^|/)(docs?|examples?|fixtures?|__tests__)/\'\'\',',
      '  \'\'\'\\.example$\'\'\',',
      ']',
      'regexes = [',
      '  \'\'\'YOUR_[A-Z_]+\'\'\',',
      '  \'\'\'<[^>]+>\'\'\',',
      '  \'\'\'\\$\\{[^}]+\\}\'\'\',',
      ']',
      ''
    ].join('\n');
  }

  function preCommitHook() {
    return [
      '#!/bin/sh',
      '# .githooks/pre-commit — OneTap WebApp Shield',
      '# 설치: git config core.hooksPath .githooks && chmod +x .githooks/pre-commit',
      '',
      'echo "[shield] 스테이징된 변경에서 시크릿 검사..."',
      '',
      'if command -v gitleaks >/dev/null 2>&1; then',
      '  gitleaks protect --staged --redact --verbose',
      '  if [ $? -ne 0 ]; then',
      '    echo "[shield] 시크릿이 감지되어 커밋을 막았습니다."',
      '    echo "        가짜 값이면 .gitleaks.toml allowlist에 경로를 추가하세요."',
      '    exit 1',
      '  fi',
      'else',
      '  echo "[shield] gitleaks가 없어 검사를 건너뜁니다."',
      '  echo "        설치: brew install gitleaks / https://github.com/gitleaks/gitleaks/releases"',
      'fi',
      '',
      '# .env 파일 자체가 스테이징되면 무조건 차단',
      'if git diff --cached --name-only | grep -E \'(^|/)\\.env($|\\.)\' | grep -v \'\\.env\\.example\'; then',
      '  echo "[shield] .env 파일이 스테이징되었습니다. 커밋을 막습니다."',
      '  exit 1',
      'fi',
      '',
      'exit 0',
      ''
    ].join('\n');
  }

  function actionsWorkflow() {
    return [
      'name: Security Shield',
      '',
      'on:',
      '  push:',
      '    branches: [main, master]',
      '  pull_request:',
      '  workflow_dispatch:',
      '',
      'permissions:',
      '  contents: read',
      '',
      'jobs:',
      '  secrets:',
      '    name: 시크릿 유출 검사',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          fetch-depth: 0',
      '      - name: Gitleaks',
      '        uses: gitleaks/gitleaks-action@v2',
      '        env:',
      '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
      '          # 조직 저장소라면 아래 라이선스가 필요합니다(개인 저장소는 불필요).',
      '          # GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}',
      '',
      '  dependencies:',
      '    name: 의존성 CVE 검사',
      '    runs-on: ubuntu-latest',
      '    permissions:',
      '      contents: read',
      '      security-events: write',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - name: OSV-Scanner',
      '        uses: google/osv-scanner-action/osv-scanner-action@v1',
      '        with:',
      '          scan-args: |-',
      '            --recursive',
      '            ./',
      '        continue-on-error: true',
      '',
      '  sast:',
      '    name: 코드 취약점 검사',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - uses: actions/setup-python@v5',
      '        with:',
      '          python-version: "3.12"',
      '      - run: pip install semgrep',
      '      - name: Semgrep (OWASP Top 10 + JS/TS 보안)',
      '        run: semgrep --config p/owasp-top-ten --config p/javascript --error --severity ERROR',
      '',
      '  headers:',
      '    name: 배포 보안 헤더 확인',
      '    runs-on: ubuntu-latest',
      '    if: github.ref == \'refs/heads/main\'',
      '    steps:',
      '      - name: 헤더 점검 (배포 URL을 넣으세요)',
      '        run: |',
      '          URL="https://example.com"',
      '          for h in content-security-policy strict-transport-security x-content-type-options referrer-policy; do',
      '            if curl -sI "$URL" | grep -qi "^$h:"; then echo "OK   $h"; else echo "MISS $h"; exit 1; fi',
      '          done',
      ''
    ].join('\n');
  }

  function securityRulesMd(opts) {
    opts = opts || {};
    return [
      '# SECURITY_RULES.md — AI 코딩 에이전트 보안 규칙',
      '',
      '> 이 파일을 `AGENTS.md`(Codex·Cursor·Claude Code) 또는 `.cursorrules`에 붙이면,',
      '> AI가 코드를 만들 때부터 아래 규칙을 지킵니다. OneTap WebApp Shield 생성.',
      '',
      '## 절대 하지 말 것',
      '1. API 키·비밀번호·토큰을 코드에 쓰지 말 것. 항상 `process.env.X` / `import.meta.env.X`.',
      '2. `NEXT_PUBLIC_` `VITE_` `REACT_APP_` 접두사에 시크릿을 넣지 말 것 — 브라우저 번들에 그대로 들어간다.',
      '3. `eval()`, `new Function()`, `document.write()`, `dangerouslySetInnerHTML`(살균 없이) 금지.',
      '4. 사용자 입력을 SQL 문자열에 붙이지 말 것. 항상 파라미터 바인딩.',
      '5. `service_role` / `sb_secret_` 키를 클라이언트 코드에 두지 말 것.',
      '6. CORS를 `*` + credentials로 열지 말 것. 허용 도메인 배열을 쓸 것.',
      '7. `rejectUnauthorized: false`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0` 금지.',
      '8. 쿠키는 `httpOnly: true, secure: true, sameSite: "lax"` 기본.',
      '9. Stripe 웹훅은 반드시 `constructEvent`로 서명 검증.',
      '10. 비밀번호는 bcrypt(12+)·argon2id. MD5/SHA1 금지.',
      '',
      '## Supabase를 쓴다면',
      '- 테이블을 만들면 **같은 마이그레이션 파일에서** `enable row level security`를 켠다.',
      '- 정책은 `using (auth.uid() = user_id)`처럼 소유자 조건. `using (true)` 금지.',
      '- View는 `with (security_invoker = true)`.',
      '- 클라이언트에는 anon(publishable) 키만. service_role은 서버 전용.',
      '',
      '## Firebase를 쓴다면',
      '- `firestore.rules`에 `allow read, write: if true;` 금지.',
      '- `request.auth != null && request.auth.uid == resource.data.ownerId` 형태로.',
      '- 서비스 계정 JSON은 서버에만.',
      '',
      '## 새 API 라우트를 만들면',
      '- 입력 길이·형식을 먼저 검증한다(스키마 검증).',
      '- 인증 확인을 핸들러 첫 줄에 둔다(권한은 역할별로 다시 확인).',
      '- 응답에 내부 에러 메시지·스택을 넣지 않는다.',
      '- AI·결제 엔드포인트에는 사용자별 rate limit을 둔다.',
      '- 남의 리소스 id로 조회할 때 소유자 조건을 WHERE에 포함한다.',
      '',
      '## 배포 전 체크',
      '- [ ] `.env`가 `.gitignore`에 있다',
      '- [ ] CSP·HSTS·nosniff·Referrer-Policy 헤더가 배포된다',
      '- [ ] `.map` 소스맵이 공개되지 않는다',
      '- [ ] `npm audit` / OSV 스캔에 critical 0건',
      '- [ ] 에러 페이지에 스택 트레이스가 없다',
      '',
      '## AI가 자주 만드는 실수 (이 저장소에서 금지)',
      '1. `supabase.from("orders").select("*")` 를 RLS 없이 만들고 "일단 동작"으로 끝내기.',
      '2. 로그인 후 사용자 id를 `localStorage`에 저장하고 그 값으로 권한 판단하기(위조 가능).',
      '3. API 라우트에서 `req.body.userId`를 그대로 믿고 남의 데이터 수정하기.',
      '4. 에러를 `res.json({ error: e.message, stack: e.stack })`로 그대로 반환하기.',
      '5. `catch {}` 로 실패를 삼켜 권한 검사를 건너뛰기.',
      '6. 업로드 파일 이름을 그대로 저장 경로로 사용하기.',
      '7. `Access-Control-Allow-Origin: *` 를 "일단 CORS 해결"로 붙이기.',
      '8. Stripe/포트원 웹훅에서 서명 검증 없이 `req.body`를 믿기.',
      '',
      '## 응답 형식',
      '코드를 고칠 때는 (1) 바뀐 파일 전체 (2) 왜 안전해졌는지 3줄 (3) 추가로 필요한 환경변수 이름을 함께 출력한다.',
      '',
      '---',
      '출처: OneTap WebApp Shield · ' + TOOL_URL,
      ''
    ].join('\n');
  }

  function agentsMd() {
    return [
      '# AGENTS.md',
      '',
      '이 저장소에서 코드를 생성·수정하는 AI 에이전트는 `SECURITY_RULES.md`를 반드시 따른다.',
      '',
      '- 시크릿 하드코딩 금지 (환경변수만)',
      '- Supabase 테이블 생성 시 RLS를 같은 마이그레이션에서 켠다',
      '- 사용자 입력은 SQL/HTML/명령/경로에 직접 넣지 않는다',
      '- 배포 전 `SECURITY_RULES.md`의 체크리스트를 확인한다',
      '',
      '전체 규칙: ./SECURITY_RULES.md',
      ''
    ].join('\n');
  }

  function kit(opts) {
    opts = opts || {};
    var hosting = opts.hosting || 'cloudflare';
    var out = [
      { id: 'gitignore', path: '.gitignore', lang: 'text', label: '.gitignore', note: '시크릿·키·DB·소스맵 차단', content: gitignore() },
      { id: 'gitleaks', path: '.gitleaks.toml', lang: 'toml', label: '.gitleaks.toml', note: 'Gitleaks 기본 규칙 + 오탐 allowlist', content: gitleaksToml() },
      { id: 'precommit', path: '.githooks/pre-commit', lang: 'sh', label: 'pre-commit 훅', note: '커밋 전 시크릿 차단', content: preCommitHook() },
      { id: 'actions', path: '.github/workflows/security-shield.yml', lang: 'yaml', label: 'GitHub Actions CI', note: 'Gitleaks · OSV · Semgrep 자동 실행', content: actionsWorkflow() },
      { id: 'rules', path: 'SECURITY_RULES.md', lang: 'md', label: 'SECURITY_RULES.md', note: 'AI 코딩 에이전트용 규칙', content: securityRulesMd(opts) },
      { id: 'agents', path: 'AGENTS.md', lang: 'md', label: 'AGENTS.md', note: '규칙 파일 연결', content: agentsMd() }
    ];
    var hf = headersFile(hosting, opts);
    var h = HOSTINGS.filter(function (x) { return x.id === hosting; })[0] || HOSTINGS[0];
    out.unshift({ id: 'headers', path: h.path, lang: h.lang, label: h.label, note: h.note, content: hf });
    return out;
  }

  function terminalCommands(url) {
    var u = url || 'https://example.com';
    return [
      '# 1) all four response headers at once',
      'curl -sI ' + u + ' | grep -iE "content-security-policy|strict-transport-security|x-content-type-options|referrer-policy"',
      '',
      '# 2) score them (OK when present, MISS when not)',
      'for h in content-security-policy strict-transport-security x-content-type-options referrer-policy permissions-policy; do printf "%-32s" "$h"; curl -sI ' + u + ' | grep -qi "^$h:" && echo OK || echo MISS; done',
      '',
      '# 3) check for accidentally public files (404/403 is correct)',
      'for p in .env .git/HEAD package.json .DS_Store backup.zip; do printf "%-14s" "$p"; curl -s -o /dev/null -w "%{http_code}\\n" ' + u + '/' + '$p; done',
      '',
      '# 4) check for exposed source maps',
      'curl -s ' + u + ' | grep -o "sourceMappingURL=[^ ]*" | head',
      ''
    ].join('\n');
  }

  /* ── ZIP (store) ─────────────────────────────────────────────────────── */

  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(bytes) {
    var c = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xC0 | (c >> 6), 0x80 | (c & 63));
      else out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }

  function dosTime(d) {
    return {
      time: ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xFFFF,
      date: (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xFFFF
    };
  }

  /** files [{path, content}] → Uint8Array (ZIP, 무압축 store) */
  function zip(files, now) {
    var d = now || new Date();
    var t = dosTime(d);
    var locals = [], centrals = [], offset = 0;
    var encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;

    (files || []).forEach(function (f) {
      var nameBytes = encoder ? encoder.encode(f.path) : utf8(f.path);
      var data = encoder ? encoder.encode(String(f.content)) : utf8(String(f.content));
      var crc = crc32(data);

      var lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true);
      lh.setUint16(4, 20, true);
      lh.setUint16(6, 0x0800, true);       // UTF-8 이름
      lh.setUint16(8, 0, true);            // store
      lh.setUint16(10, t.time, true);
      lh.setUint16(12, t.date, true);
      lh.setUint32(14, crc, true);
      lh.setUint32(18, data.length, true);
      lh.setUint32(22, data.length, true);
      lh.setUint16(26, nameBytes.length, true);
      lh.setUint16(28, 0, true);

      var local = concat([new Uint8Array(lh.buffer), nameBytes, data]);
      locals.push(local);

      var ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true);
      ch.setUint16(4, 20, true);
      ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true);
      ch.setUint16(10, 0, true);
      ch.setUint16(12, t.time, true);
      ch.setUint16(14, t.date, true);
      ch.setUint32(16, crc, true);
      ch.setUint32(20, data.length, true);
      ch.setUint32(24, data.length, true);
      ch.setUint16(28, nameBytes.length, true);
      ch.setUint16(30, 0, true);
      ch.setUint16(32, 0, true);
      ch.setUint16(34, 0, true);
      ch.setUint16(36, 0, true);
      ch.setUint32(38, 0, true);
      ch.setUint32(42, offset, true);
      centrals.push(concat([new Uint8Array(ch.buffer), nameBytes]));

      offset += local.length;
    });

    var centralSize = centrals.reduce(function (a, b) { return a + b.length; }, 0);
    var eocd = new DataView(new ArrayBuffer(22));
    eocd.setUint32(0, 0x06054b50, true);
    eocd.setUint16(4, 0, true);
    eocd.setUint16(6, 0, true);
    eocd.setUint16(8, files.length, true);
    eocd.setUint16(10, files.length, true);
    eocd.setUint32(12, centralSize, true);
    eocd.setUint32(16, offset, true);
    eocd.setUint16(20, 0, true);

    return concat(locals.concat(centrals, [new Uint8Array(eocd.buffer)]));
  }

  function concat(parts) {
    var len = parts.reduce(function (a, p) { return a + p.length; }, 0);
    var out = new Uint8Array(len), at = 0;
    parts.forEach(function (p) { out.set(p, at); at += p.length; });
    return out;
  }

  return {
    VERSION: VERSION,
    SERVICES: SERVICES,
    HOSTINGS: HOSTINGS,
    csp: csp,
    headerPairs: headerPairs,
    headersFile: headersFile,
    headersFiles: headersFiles,
    gitignore: gitignore,
    gitleaksToml: gitleaksToml,
    preCommitHook: preCommitHook,
    actionsWorkflow: actionsWorkflow,
    securityRulesMd: securityRulesMd,
    agentsMd: agentsMd,
    kit: kit,
    terminalCommands: terminalCommands,
    zip: zip,
    crc32: crc32
  };
});
