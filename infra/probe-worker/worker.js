/* ============================================================================
   onetap-shield-probe · 배포 URL 실측 프록시 (Cloudflare Worker, Workers Free)
   ----------------------------------------------------------------------------
   목적
     31호기 '원탭 웹앱 실드'(https://marcj81.github.io/onetap-webapp-shield/)의
     '배포 URL' 탭에서, 브라우저 CORS 때문에 읽지 못하던 실제 서버 응답 헤더와
     노출 파일을 대신 확인해 JSON 으로 돌려준다.

   한 줄 원칙
     - 열린 프록시가 아니다. 허용한 출처(아래 ALLOWED_ORIGINS·로컬)만 받고,
       돌려주는 것은 '요약 JSON'뿐이다. 원문 본문은 절대 그대로 돌려주지 않는다.
     - 사설·메타데이터 주소(SSRF)로는 절대 요청하지 않는다.
     - 확인하지 못한 것은 확인했다고 하지 않는다(unknown / unconfirmed).

   인터페이스
     OPTIONS *            → 204 + CORS 프리플라이트
     GET  / · /health     → 상태 JSON
     GET  /probe?url=...  → 대상 1개 실측 결과 JSON
   ========================================================================== */

const SERVICE = 'onetap-shield-probe';
const VERSION = '1.0.0';

const DEFAULT_ORIGINS = ['https://marcj81.github.io'];
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

const UA = 'Mozilla/5.0 (compatible; OneTapShieldProbe/1.0; +https://marcj81.github.io/onetap-webapp-shield/)';
const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy'
];
const PROBE_PATHS = ['/.env', '.git/HEAD', 'package.json'];
const EXTRA_HEADERS = ['content-type', 'server', 'x-powered-by', 'content-encoding'];

const MAX_HTML_BYTES = 300 * 1024;
const MAX_SCRIPT_BYTES = 160 * 1024;
const MAX_SCRIPTS = 4;
const MAX_REDIRECTS = 3;
const UPSTREAM_TIMEOUT_MS = 9000;
const TOTAL_BUDGET_MS = 22000;
const MAX_SECRETS = 12;

const SECRET_PATTERNS = [
  { id: 'google-api-key', label: 'Google API 키', sev: 'critical', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'openai-key', label: 'OpenAI API 키', sev: 'critical', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b/g },
  { id: 'stripe-key', label: 'Stripe 키', sev: 'critical', re: /\b(?:sk|rk|pk)_live_[0-9A-Za-z]{16,}\b/g },
  { id: 'github-token', label: 'GitHub 토큰', sev: 'critical', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g },
  { id: 'aws-access-key', label: 'AWS 액세스 키', sev: 'critical', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'slack-token', label: 'Slack 토큰', sev: 'critical', re: /\bxox[abprs]-[A-Za-z0-9-]{12,}\b/g },
  { id: 'supabase-secret', label: 'Supabase service_role 키', sev: 'critical', re: /\bsb_secret_[A-Za-z0-9_-]{10,}\b/g },
  { id: 'pem-private-key', label: '개인키(PEM)', sev: 'critical', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+\/= \n]{20,}/g },
  { id: 'anthropic-key', label: 'Anthropic API 키', sev: 'critical', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'jwt-token', label: 'JWT 토큰', sev: 'low', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g }
];

/* ── CORS ──────────────────────────────────────────────────────────────── */

function allowedOrigins(env) {
  const raw = (env && env.ALLOWED_ORIGINS) || '';
  const list = raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  return list.length ? list : DEFAULT_ORIGINS;
}

function originAllowed(origin, env) {
  if (!origin) return false;
  if (LOCAL_ORIGIN.test(origin)) return true;
  return allowedOrigins(env).indexOf(origin) >= 0;
}

function corsHeaders(origin) {
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
    'vary': 'Origin'
  };
}

function json(body, status, origin, extra) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  };
  if (origin) Object.assign(headers, corsHeaders(origin));
  if (extra) Object.assign(headers, extra);
  return new Response(JSON.stringify(body), { status: status || 200, headers: headers });
}

/* ── SSRF 방어 ─────────────────────────────────────────────────────────── */

function hostProblem(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return 'empty_host';
  if (h === 'localhost' || /\.localhost$/.test(h)) return 'loopback_host';
  if (h === 'local' || /\.local$/.test(h) || /\.internal$/.test(h) || /\.home\.arpa$/.test(h)) return 'private_host';
  if (/^(metadata|instance-data)$/.test(h) || /\.metadata\./.test(h)) return 'metadata_host';

  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]), b = Number(v4[2]);
    if (a === 0) return 'reserved_ip';
    if (a === 10) return 'private_ip';
    if (a === 127) return 'loopback_ip';
    if (a === 169 && b === 254) return 'metadata_ip';
    if (a === 172 && b >= 16 && b <= 31) return 'private_ip';
    if (a === 192 && b === 168) return 'private_ip';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat_ip';
    if (a >= 224) return 'reserved_ip';
  }

  if (h.charAt(0) === '[') {
    const v6 = h.slice(1, -1);
    if (v6 === '::' || v6 === '::1' || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || /^::ffff:/.test(v6)) return 'private_ip';
  }
  if (/^\d+$/.test(h)) return 'numeric_host';
  if (/^0x[0-9a-f]+$/i.test(h)) return 'numeric_host';
  if (h.indexOf('.') < 0) return 'single_label_host';
  return '';
}

function blockedPort(port) {
  const p = Number(port);
  if (!p) return false;
  if (p === 80 || p === 443) return false;
  return p < 1024 || p === 3306 || p === 5432 || p === 6379 || p === 9200 || p === 11211 || p === 27017;
}

/** 대상 URL 검증. 문제가 있으면 문자열(이유)을, 통과하면 빈 문자열을 돌려준다. */
function targetProblem(raw) {
  let u;
  try { u = new URL(raw); } catch (e) { return 'bad_url'; }
  if (!/^https?:$/.test(u.protocol)) return 'bad_scheme';
  if (u.username || u.password) return 'credentials_in_url';
  const hp = hostProblem(u.hostname);
  if (hp) return hp;
  if (blockedPort(u.port)) return 'blocked_port';
  return '';
}

/* ── HTTP ──────────────────────────────────────────────────────────────── */

function hostOf(u) {
  try { return new URL(u).host; } catch (e) { return u; }
}

async function fetchLimited(url, opts) {
  opts = opts || {};
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, opts.timeout || UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: ctrl.signal,
      headers: {
        'user-agent': UA,
        'accept': opts.accept || 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'accept-language': 'ko,en;q=0.8'
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

/** 리다이렉트를 직접 따라가며 매 홉의 목적지를 다시 검증한다. */
async function fetchFollowing(url, budget) {
  let current = url, hops = 0, res = null;
  while (hops <= MAX_REDIRECTS) {
    if (Date.now() > budget.deadline) throw new Error('timeout_budget');
    res = await fetchLimited(current);
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      let next;
      try { next = new URL(loc, current).href; } catch (e) { return { res: res, finalUrl: current, redirectProblem: 'bad_location' }; }
      const p = targetProblem(next);
      if (p) return { res: res, finalUrl: current, redirectProblem: p };
      current = next;
      hops++;
      continue;
    }
    return { res: res, finalUrl: current, redirectProblem: '' };
  }
  return { res: res, finalUrl: current, redirectProblem: 'too_many_redirects' };
}

async function readText(res, maxBytes) {
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (ct && !/(text\/|html|json|javascript|ecmascript|xml|x-www-form-urlencoded)/.test(ct)) {
    return { text: '', skipped: 'binary', contentType: ct };
  }
  const len = Number(res.headers.get('content-length') || 0);
  if (len && len > 4 * 1024 * 1024) return { text: '', skipped: 'too_large', contentType: ct };
  let buf;
  try { buf = await res.arrayBuffer(); } catch (e) { return { text: '', skipped: 'read_failed', contentType: ct }; }
  const bytes = new Uint8Array(buf);
  const slice = bytes.byteLength > maxBytes ? bytes.subarray(0, maxBytes) : bytes;
  let text = '';
  try { text = new TextDecoder('utf-8').decode(slice); } catch (e) { text = ''; }
  return { text: text, skipped: '', contentType: ct, bytes: bytes.byteLength, truncated: bytes.byteLength > maxBytes };
}

/* ── 시크릿 스캔 ───────────────────────────────────────────────────────── */

function mask(v) {
  const s = String(v);
  if (s.length <= 10) return s.slice(0, 2) + '…';
  return s.slice(0, 4) + '…' + s.slice(-4);
}

function scanSecrets(text, where, out) {
  if (!text) return;
  const sample = text.slice(0, 400 * 1024);
  for (let i = 0; i < SECRET_PATTERNS.length; i++) {
    const p = SECRET_PATTERNS[i];
    p.re.lastIndex = 0;
    let m, guard = 0;
    while ((m = p.re.exec(sample)) && guard < 3) {
      guard++;
      const hit = m[0];
      if (/example|placeholder|your[-_]?key|xxxx|dummy|sample|test[_-]?key/i.test(hit)) continue;
      out.push({ id: p.id, label: p.label, sev: p.sev, where: where, masked: mask(hit), length: hit.length });
      if (out.length >= MAX_SECRETS) return;
    }
  }
}

/* ── 노출 파일 판정 ────────────────────────────────────────────────────── */

function confirmExposure(path, body) {
  if (!body) return false;
  const p = path.replace(/^\//, '');
  if (/^\.env/.test(p)) return /^\s*[A-Z0-9_]{2,}\s*=\s*\S+/m.test(body) && !/<html/i.test(body.slice(0, 200));
  if (/^\.git\/HEAD$/.test(p)) return /^ref:\s+refs\//m.test(body) || /^[0-9a-f]{40}\s*$/m.test(body);
  if (/^package\.json$/.test(p)) {
    try { const j = JSON.parse(body); return !!(j && (j.name || j.dependencies || j.devDependencies)); }
    catch (e) { return /"name"\s*:/.test(body) && /"version"\s*:/.test(body); }
  }
  return false;
}

async function probeFile(origin, path, budget) {
  const url = origin + '/' + path.replace(/^\//, '');
  const entry = { path: '/' + path.replace(/^\//, ''), url: url, httpStatus: 0, status: 'unknown', bytes: 0, contentType: '' };
  try {
    const { res } = await fetchFollowing(url, budget);
    entry.httpStatus = res.status;
    entry.contentType = res.headers.get('content-type') || '';
    if (res.status === 401 || res.status === 403 || res.status === 404 || res.status === 410) {
      entry.status = 'blocked';
      return entry;
    }
    if (res.status >= 200 && res.status < 300) {
      const r = await readText(res, 64 * 1024);
      entry.bytes = r.bytes || 0;
      entry.status = confirmExposure(entry.path, r.text) ? 'exposed' : 'unconfirmed';
      return entry;
    }
    entry.status = 'unknown';
  } catch (e) {
    entry.status = 'unknown';
    entry.note = 'request_failed';
  }
  return entry;
}

/* ── 스크립트 수집 ─────────────────────────────────────────────────────── */

function extractScripts(html, baseUrl) {
  const out = [], seen = Object.create(null);
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  const baseHost = (function () { try { return new URL(baseUrl).host; } catch (e) { return ''; } })();
  while ((m = re.exec(html)) && out.length < 40) {
    let abs;
    try { abs = new URL(m[1], baseUrl).href; } catch (e) { continue; }
    if (!/^https?:/.test(abs)) continue;
    if (hostOf(abs) !== baseHost) continue;        // 동일 도메인만
    if (seen[abs]) continue;
    seen[abs] = 1;
    out.push(abs);
  }
  return out;
}

function extractInlineScripts(html) {
  const out = [];
  const re = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m, total = 0;
  while ((m = re.exec(html)) && total < 200 * 1024) {
    out.push(m[1]);
    total += m[1].length;
  }
  return out.join('\n');
}

/* ── 메인 ──────────────────────────────────────────────────────────────── */

async function handleProbe(request, env, url) {
  const raw = url.searchParams.get('url') || '';
  const problem = targetProblem(raw);
  if (problem) {
    return { status: 400, body: { ok: false, error: problem, message: 'http(s) 공인 주소만 확인할 수 있습니다.' } };
  }

  const started = Date.now();
  const budget = { deadline: started + TOTAL_BUDGET_MS };
  const target = new URL(raw);
  target.hash = '';
  const targetHref = target.href;
  const origin = target.origin;

  const out = {
    ok: true, service: SERVICE, version: VERSION,
    target: targetHref, requested: raw,
    httpStatus: 0, finalUrl: targetHref, redirectProblem: '',
    headers: {}, headerCount: 0, headerStatus: 'checked',
    probes: [], scripts: [], secrets: [],
    page: { htmlBytes: 0, inlineBytes: 0, truncated: false, title: '' },
    elapsedMs: 0, note: ''
  };

  let res, finalUrl = targetHref, redirectProblem = '';
  try {
    const r = await fetchFollowing(targetHref, budget);
    res = r.res; finalUrl = r.finalUrl; redirectProblem = r.redirectProblem;
  } catch (e) {
    out.ok = false;
    out.error = 'upstream_unreachable';
    out.message = /abort|timeout/i.test(String(e && e.message)) ? '대상 서버 응답이 너무 느립니다.' : '대상 서버에 연결하지 못했습니다.';
    out.elapsedMs = Date.now() - started;
    return { status: 200, body: out };
  }

  out.httpStatus = res.status;
  out.finalUrl = finalUrl;
  out.redirectProblem = redirectProblem;

  SECURITY_HEADERS.forEach(function (h) {
    const v = res.headers.get(h) || '';
    out.headers[h] = v;
    if (v) out.headerCount += 1;
  });
  EXTRA_HEADERS.forEach(function (h) {
    const v = res.headers.get(h);
    if (v) out.headers[h] = v;
  });

  // 본문·시크릿
  if (res.status >= 200 && res.status < 300) {
    const r = await readText(res, MAX_HTML_BYTES);
    out.page.htmlBytes = r.bytes || 0;
    out.page.truncated = !!r.truncated;
    out.page.contentType = r.contentType || '';
    if (r.text) {
      const tm = r.text.match(/<title[^>]*>([\s\S]{0,120}?)<\/title>/i);
      if (tm) out.page.title = tm[1].replace(/\s+/g, ' ').trim();
      const inline = extractInlineScripts(r.text);
      out.page.inlineBytes = inline.length;
      scanSecrets(r.text, 'html', out.secrets);
      if (/sourceMappingURL=/.test(r.text)) out.page.sourceMap = true;

      const scripts = extractScripts(r.text, finalUrl).slice(0, MAX_SCRIPTS);
      for (let i = 0; i < scripts.length; i++) {
        const src = scripts[i];
        const entry = { url: src, httpStatus: 0, bytes: 0, secrets: 0 };
        try {
          const sr = await fetchFollowing(src, budget);
          entry.httpStatus = sr.res.status;
          if (sr.res.status >= 200 && sr.res.status < 300) {
            const body = await readText(sr.res, MAX_SCRIPT_BYTES);
            entry.bytes = body.bytes || 0;
            const before = out.secrets.length;
            scanSecrets(body.text, 'script:' + src, out.secrets);
            entry.secrets = out.secrets.length - before;
          }
        } catch (e) {
          entry.note = 'request_failed';
        }
        out.scripts.push(entry);
      }
    }
  } else {
    out.note = '대상이 2xx로 응답하지 않아 본문·헤더만 확인했습니다.';
  }

  // 노출 파일
  for (let i = 0; i < PROBE_PATHS.length; i++) {
    out.probes.push(await probeFile(origin, PROBE_PATHS[i], budget));
  }

  out.elapsedMs = Date.now() - started;
  return { status: 200, body: out };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      if (!originAllowed(origin, env)) {
        return new Response(null, { status: 403, headers: { 'content-type': 'text/plain', 'vary': 'Origin' } });
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'GET') {
      return json({ ok: false, error: 'method_not_allowed' }, 405, null);
    }

    if (url.pathname === '/' || url.pathname === '/health') {
      return json({
        ok: true, service: SERVICE, version: VERSION,
        now: new Date().toISOString(),
        allowedOrigins: allowedOrigins(env),
        endpoints: ['/health', '/probe?url=https://example.com/']
      }, 200, null);
    }

    if (url.pathname !== '/probe') {
      return json({ ok: false, error: 'not_found' }, 404, null);
    }

    // 브라우저 호출은 허용 출처만. (출처 없는 서버·스크립트 호출도 막는다)
    if (!originAllowed(origin, env)) {
      return json({ ok: false, error: 'origin_not_allowed', message: '허용되지 않은 출처입니다.' }, 403, null);
    }

    const result = await handleProbe(request, env, url);
    return json(result.body, result.status, origin);
  }
};
