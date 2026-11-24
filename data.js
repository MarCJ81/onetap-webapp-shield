/* ============================================================================
   data.js · 데모 프리셋
   ----------------------------------------------------------------------------
   시크릿은 저장소에 리터럴로 두지 않는다. 화면을 열 때 즉석에서 만든
   "가짜 키"를 조립해 넣는다(공개 저장소에 진짜처럼 보이는 키가 커밋되는 것을
   피하고, GitHub push protection·시크릿 스캐너의 오탐도 막는다).
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.SAMPLES = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  function token(prefix, len, seed) {
    var s = (seed >>> 0) || 1, out = '';
    for (var i = 0; i < len; i++) {
      s = (s * 1664525 + 1013904223) >>> 0;
      out += ALNUM[s % ALNUM.length];
    }
    return prefix + out;
  }

  function b64u(str) {
    if (typeof btoa === 'function') {
      return btoa(unescape(encodeURIComponent(str))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(str, 'utf8').toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
    return '';
  }

  function fakeJwt(role, seed) {
    var header = b64u('{"alg":"HS256","typ":"JWT"}');
    var payload = b64u(JSON.stringify({
      iss: 'supabase', ref: 'demoproject', role: role, iat: 1730000000, exp: 2000000000
    }) + ' ');
    return header + '.' + payload + '.' + token('', 43, seed);
  }

  /* ── ① API 키가 박힌 채 배포된 Supabase 앱 ─────────────────────────── */

  function presetKeys() {
    var openai = token('sk-proj-', 48, 20261124);
    var stripe = token('sk_live_', 26, 771234);
    var supa = token('sb_secret_', 32, 445566);
    var serviceJwt = fakeJwt('service_role', 99001);

    return [
      {
        path: '.env',
        content: [
          '# (데모) 값은 화면에서 즉석 생성한 가짜 키입니다. 실제 키가 아닙니다.',
          'VITE_SUPABASE_URL=https://demoproject.supabase.co',
          'VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.anon',
          'SUPABASE_SERVICE_ROLE_KEY=' + supa,
          'OPENAI_API_KEY=' + openai,
          'STRIPE_SECRET_KEY=' + stripe,
          'VITE_STRIPE_SECRET_KEY=' + stripe
        ].join('\n')
      },
      {
        path: 'src/lib/supabase-admin.ts',
        content: [
          "import { createClient } from '@supabase/supabase-js'",
          '',
          '// 데모용 가짜 service_role JWT (실제 키 아님)',
          "const SERVICE_KEY = '" + serviceJwt + "'",
          '',
          'export const admin = createClient(',
          "  'https://demoproject.supabase.co',",
          '  SERVICE_KEY',
          ')',
          '',
          'export async function listAllOrders() {',
          "  const { data } = await admin.from('orders').select('*')",
          '  return data',
          '}'
        ].join('\n')
      },
      {
        path: 'supabase/migrations/001_orders.sql',
        content: [
          '-- 주문 테이블 (RLS를 켜지 않은 상태로 배포됨)',
          'create table public.orders (',
          '  id uuid primary key default gen_random_uuid(),',
          '  user_id uuid references auth.users(id),',
          '  email text,',
          '  total integer,',
          '  created_at timestamptz default now()',
          ');',
          '',
          'create policy "orders_all" on public.orders',
          '  for all using (true) with check (true);',
          '',
          'create view public.order_summary as',
          '  select user_id, sum(total) as lifetime from public.orders group by user_id;'
        ].join('\n')
      },
      {
        path: 'src/pages/Checkout.tsx',
        content: [
          '// 데모 컴포넌트',
          'export default function Checkout() {',
          "  const key = import.meta.env.VITE_STRIPE_SECRET_KEY",
          '  return <div>checkout ready</div>',
          '}'
        ].join('\n')
      }
    ];
  }

  /* ── ② XSS + CORS + eval 백엔드 (AI가 자주 만드는 형태) ────────────── */

  function presetXss() {
    var demoJwtSecret = token('demo-', 24, 7788);
    return [
      {
        path: 'src/components/ReviewList.jsx',
        content: [
          'export default function ReviewList({ reviews }) {',
          '  return (',
          '    <ul>',
          '      {reviews.map((r) => (',
          '        <li key={r.id}>',
          '          <div dangerouslySetInnerHTML={{ __html: r.body }} />',
          '        </li>',
          '      ))}',
          '    </ul>',
          '  )',
          '}',
          '',
          'export function renderPreview(el, review) {',
          '  el.innerHTML = review.body',
          '}'
        ].join('\n')
      },
      {
        path: 'api/review.js',
        content: [
          "import express from 'express'",
          "import cors from 'cors'",
          "import mysql from 'mysql2'",
          "import { exec } from 'child_process'",
          '',
          'const app = express()',
          'app.use(cors())',
          'app.use(express.json())',
          '',
          "const JWT_SECRET = '" + demoJwtSecret + "'",
          '',
          'app.get("/api/review", async (req, res) => {',
          '  const id = req.query.id',
          '  const rows = await mysql.query(`SELECT * FROM reviews WHERE id = ${id}`)',
          '  res.cookie("session", req.query.session)',
          '  res.redirect(req.query.next)',
          '  res.json(rows)',
          '})',
          '',
          'app.post("/api/run", (req, res) => {',
          '  const result = eval(req.body.code)',
          '  res.json({ result })',
          '})',
          '',
          'app.get("/api/preview", async (req, res) => {',
          '  const html = await fetch(req.query.url).then((r) => r.text())',
          '  res.send(html)',
          '})',
          '',
          'const agent = new https.Agent({ rejectUnauthorized: false })',
          '',
          'app.listen(3000)'
        ].join('\n')
      },
      {
        path: 'firestore.rules',
        content: [
          'rules_version = "2";',
          'service cloud.firestore {',
          '  match /databases/{database}/documents {',
          '    match /{document=**} {',
          '      allow read, write: if true;',
          '    }',
          '  }',
          '}'
        ].join('\n')
      },
      {
        path: 'public/index.html',
        content: [
          '<!DOCTYPE html>',
          '<html><head><title>Demo</title>',
          '<script src="//cdn.example.com/lib.js"></script>',
          '</head><body>',
          '<a href="http://api.demosite.com/data" target="_blank">API</a>',
          '<script>',
          "document.getElementById('out').innerHTML = location.hash.slice(1)",
          '</script>',
          '<script>//# sourceMappingURL=app.js.map</script>',
          '</body></html>'
        ].join('\n')
      }
    ];
  }

  /* ── ③ 안전한 대조군 ────────────────────────────────────────────────── */

  function presetSafe() {
    return [
      {
        path: 'src/lib/supabase.ts',
        content: [
          "import { createClient } from '@supabase/supabase-js'",
          '',
          '// 공개 전제인 anon 키만 클라이언트에 둔다. 실제 값은 호스팅 환경변수.',
          'export const supabase = createClient(',
          '  import.meta.env.VITE_SUPABASE_URL,',
          '  import.meta.env.VITE_SUPABASE_ANON_KEY',
          ')',
          '',
          'export async function myOrders() {',
          "  const { data, error } = await supabase.from('orders').select('*')",
          '  if (error) throw error',
          '  return data',
          '}'
        ].join('\n')
      },
      {
        path: 'supabase/migrations/002_secure.sql',
        content: [
          'create table public.orders (',
          '  id uuid primary key default gen_random_uuid(),',
          '  user_id uuid not null references auth.users(id),',
          '  total integer not null check (total >= 0),',
          '  created_at timestamptz default now()',
          ');',
          '',
          'alter table public.orders enable row level security;',
          '',
          'create policy "orders_select_own" on public.orders',
          '  for select using (auth.uid() = user_id);',
          '',
          'create policy "orders_insert_own" on public.orders',
          '  for insert with check (auth.uid() = user_id);',
          '',
          'create view public.order_summary',
          '  with (security_invoker = true) as',
          '  select user_id, sum(total) as lifetime from public.orders group by user_id;'
        ].join('\n')
      },
      {
        path: 'api/review.ts',
        content: [
          "import { Pool } from 'pg'",
          "import { z } from 'zod'",
          '',
          'const pool = new Pool({ connectionString: process.env.DATABASE_URL })',
          'const ALLOWED = [process.env.APP_ORIGIN || "https://app.example.com"]',
          '',
          'const ReviewInput = z.object({ id: z.string().uuid(), body: z.string().max(2000) })',
          '',
          'export default async function handler(req, res) {',
          '  const origin = req.headers.origin',
          '  if (ALLOWED.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin)',
          '  res.setHeader("Vary", "Origin")',
          '',
          '  const parsed = ReviewInput.safeParse(req.body)',
          '  if (!parsed.success) return res.status(400).json({ error: "invalid input" })',
          '',
          '  const rows = await pool.query("SELECT id, body FROM reviews WHERE id = $1", [parsed.data.id])',
          "  res.setHeader('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Lax; Path=/')",
          '  return res.status(200).json(rows.rows)',
          '}'
        ].join('\n')
      },
      {
        path: 'public/_headers',
        content: [
          '/*',
          "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
          '  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
          '  X-Content-Type-Options: nosniff',
          '  X-Frame-Options: DENY',
          '  Referrer-Policy: strict-origin-when-cross-origin',
          '  Permissions-Policy: camera=(), microphone=(), geolocation=()',
          '  Cross-Origin-Opener-Policy: same-origin'
        ].join('\n')
      },
      {
        path: '.gitignore',
        content: ['.env', '.env.*', '!.env.example', '*.pem', '*.key', 'node_modules/', 'dist/', '*.map', '*.log'].join('\n')
      }
    ];
  }

  var PACKAGE_JSON = [
    '{',
    '  "name": "my-vibe-app",',
    '  "private": true,',
    '  "dependencies": {',
    '    "next": "14.1.0",',
    '    "react": "18.3.1",',
    '    "lodash": "4.17.20",',
    '    "axios": "1.5.0",',
    '    "jsonwebtoken": "8.5.1",',
    '    "express": "4.18.2",',
    '    "@supabase/supabase-js": "^2.45.0",',
    '    "stripe": "^16.2.0"',
    '  },',
    '  "devDependencies": {',
    '    "vite": "5.4.0",',
    '    "typescript": "^5.4.0"',
    '  }',
    '}'
  ].join('\n');

  function getPresets() {
    return [
      {
        id: 'keys-supabase',
        label: 'API 키 + Supabase RLS 누락',
        short: '키 노출 · RLS',
        desc: '서비스 키가 .env와 코드에 박힌 채, RLS를 켜지 않은 테이블을 배포한 전형적인 바이브 코딩 앱.',
        tone: 'critical',
        files: presetKeys()
      },
      {
        id: 'xss-cors-eval',
        label: 'XSS + CORS + eval 백엔드',
        short: 'XSS · CORS',
        desc: 'innerHTML·dangerouslySetInnerHTML, 모든 origin 허용, eval API, 열린 Firestore 규칙이 한 번에.',
        tone: 'critical',
        files: presetXss()
      },
      {
        id: 'safe-baseline',
        label: '안전한 대조군',
        short: '안전 예시',
        desc: 'RLS·파라미터 바인딩·HttpOnly 쿠키·허용 origin·보안 헤더·.gitignore까지 갖춘 기준선.',
        tone: 'ok',
        files: presetSafe()
      }
    ];
  }

  return {
    getPresets: getPresets,
    PACKAGE_JSON: PACKAGE_JSON,
    token: token,
    fakeJwt: fakeJwt
  };
});
