/* ============================================================================
   remote.js · 배포 URL 실측 + GitHub 공개 저장소 원클릭 스캔
   ----------------------------------------------------------------------------
   원칙: 브라우저에서 확인하지 못한 것은 "확인됨"으로 표시하지 않는다.
   - 같은 오리진이면 응답 헤더를 실제로 읽어 점수를 낸다.
   - 다른 오리진이면 CORS가 헤더 노출을 막으므로 '미확인(Inconclusive)'으로
     남기고, 터미널에서 1초에 확인할 명령을 함께 준다.
   - 노출 파일 프로브도 상태를 구분한다: exposed / blocked / unknown.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.REMOTE = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '1.1.0';
  var SECURITY_HEADERS = [
    { key: 'content-security-policy', label: 'CSP', weight: 30, sev: 'high' },
    { key: 'strict-transport-security', label: 'HSTS', weight: 20, sev: 'medium' },
    { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 15, sev: 'low' },
    { key: 'referrer-policy', label: 'Referrer-Policy', weight: 15, sev: 'low' },
    { key: 'x-frame-options', label: 'X-Frame-Options', weight: 10, sev: 'low' },
    { key: 'permissions-policy', label: 'Permissions-Policy', weight: 10, sev: 'info' }
  ];
  var PROBE_PATHS = ['.env', '.git/HEAD', 'package.json', '.DS_Store', 'backup.zip'];

  function normalizeUrl(input) {
    var s = String(input || '').trim();
    if (!s) return null;
    if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
    try {
      var u = new URL(s);
      if (!/^https?:$/.test(u.protocol)) return null;
      u.hash = '';
      return u;
    } catch (e) { return null; }
  }

  function originOf(loc) {
    try { return (loc && loc.origin) ? loc.origin : ''; } catch (e) { return ''; }
  }

  function headerGet(headers, name) {
    try { return headers.get(name) || ''; } catch (e) { return ''; }
  }

  /* ── 배포 URL 점검 ──────────────────────────────────────────────────── */

  async function probeUrl(input, opts) {
    opts = opts || {};
    var u = normalizeUrl(input);
    if (!u) return { ok: false, message: 'http(s) 주소 형식이 아닙니다.' };
    var here = opts.sameOriginBase || originOf(typeof location !== 'undefined' ? location : null);
    var sameOrigin = !!here && u.origin === here;

    var out = {
      ok: true, target: u.href, origin: u.origin, sameOrigin: sameOrigin,
      headerStatus: 'unknown', headers: {}, headerScore: null,
      probes: [], findings: [], note: '', fetchedAt: new Date().toISOString()
    };

    var res = null, err = '';
    try {
      res = await fetch(u.href, { method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'follow' });
    } catch (e) {
      err = 'network';
    }

    if (!res) {
      out.headerStatus = 'unreachable';
      out.note = '페이지에 접속하지 못했습니다(네트워크·CORS·차단). 서버 상태를 확인하세요.';
      out.findings.push(infoUnverified('unreachable'));
      return out;
    }

    out.httpStatus = res.status;
    out.finalUrl = res.url || u.href;

    // 헤더 가독성 판정: 같은 오리진이면 전부 읽을 수 있다.
    // 다른 오리진이면 CORS-safelisted 헤더(content-type 등)만 보인다.
    var contentType = headerGet(res.headers, 'content-type');
    var canReadSecurity = SECURITY_HEADERS.some(function (h) { return !!headerGet(res.headers, h.key); });

    if (sameOrigin || canReadSecurity) {
      out.headerStatus = 'checked';
      var earned = 0;
      SECURITY_HEADERS.forEach(function (h) {
        var val = headerGet(res.headers, h.key);
        out.headers[h.key] = val;
        if (val) earned += h.weight;
      });
      out.headerScore = earned;
      SECURITY_HEADERS.forEach(function (h) {
        if (!out.headers[h.key]) {
          out.findings.push({
            ruleId: 'header-' + h.key, name: '보안 헤더 누락: ' + h.label, sev: h.sev, cat: 'config', kind: 'remote',
            path: u.href, line: 1, snippet: '', note: '응답에 ' + h.label + ' 헤더가 없습니다.',
            why: '헤더가 없으면 브라우저의 기본 방어(스크립트 제한·MIME 검사·클릭재킹 차단·리퍼러 최소화)가 작동하지 않습니다.',
            fix: '방어팩에서 이 호스팅에 맞는 헤더 파일을 생성해 배포하세요.',
            cwe: 'CWE-693', refs: ['https://developer.mozilla.org/ko/docs/Web/HTTP/Headers']
          });
        }
      });
    } else if (contentType) {
      out.headerStatus = 'limited';
      out.note = '응답은 받았지만 다른 오리진이라 보안 헤더가 브라우저에 노출되지 않습니다(CORS). 헤더 상태는 "미확인"입니다.';
      out.findings.push(infoUnverified('cors'));
    } else {
      out.headerStatus = 'cors-blocked';
      out.note = 'CORS 정책으로 응답을 읽지 못했습니다. 헤더 상태는 "미확인"입니다.';
      out.findings.push(infoUnverified('cors'));
    }

    // 본문에서 소스맵 참조 확인 (읽을 수 있을 때만)
    if (res.status >= 200 && res.status < 300) {
      try {
        var text = await res.text();
        out.bytes = text.length;
        if (/sourceMappingURL=/.test(text)) {
          out.findings.push({
            ruleId: 'remote-sourcemap', name: '배포본 HTML/JS에 소스맵 참조', sev: 'low', cat: 'git', kind: 'remote',
            path: u.href, line: 1, snippet: (text.match(/[^\s"'<>]*sourceMappingURL=[^\s"'<>]+/) || [''])[0].slice(0, 120),
            note: '', why: '소스맵이 공개되면 원본 소스와 내부 구조가 그대로 노출됩니다.',
            fix: '프로덕션에서 sourcemap을 끄거나 접근을 차단하세요.', cwe: 'CWE-540', refs: []
          });
        }
        // 배포 HTML에 박힌 공개용이 아닌 키 (NEXT_PUBLIC 등은 스캔 엔진이 잡는다)
        out.htmlSample = text.slice(0, 20000);
      } catch (e) { /* noop */ }
    }

    // 노출 파일 프로브 — 상태를 정직하게 구분
    out.probes = await probeFiles(u, sameOrigin, opts);

    return out;
  }

  function infoUnverified(kind) {
    if (kind === 'unreachable') {
      return {
        ruleId: 'remote-unreachable', name: '배포 URL 응답 없음(미확인)', sev: 'info', cat: 'config', kind: 'remote',
        path: '', line: 1, snippet: '',
        note: '서버 헤더·노출 파일을 확인하지 못했습니다.',
        why: '확인하지 못한 항목은 안전하다고 볼 수 없습니다.',
        fix: '터미널 명령으로 직접 확인하세요.', cwe: '', refs: []
      };
    }
    return {
      ruleId: 'remote-cors-unverified', name: '서버 헤더 미확인 (브라우저 CORS 제한)', sev: 'info', cat: 'config', kind: 'remote',
      path: '', line: 1, snippet: '',
      note: '다른 오리진의 응답 헤더는 브라우저가 읽지 못합니다.',
      why: '이 항목은 "안전"이 아니라 "확인 못 함"입니다. 녹색 체크로 표시하지 않습니다.',
      fix: '복사한 curl 명령을 터미널에서 실행해 헤더를 확인하세요.', cwe: '', refs: []
    };
  }

  async function probeFiles(u, sameOrigin, opts) {
    var out = [];
    var paths = (opts && opts.probePaths) || PROBE_PATHS;
    for (var i = 0; i < paths.length; i++) {
      var p = paths[i];
      var url = u.origin + '/' + p;
      var entry = { path: p, url: url, status: 'unknown', httpStatus: 0, note: '' };
      try {
        var r = await fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store' });
        entry.httpStatus = r.status;
        if (r.status === 404 || r.status === 403 || r.status === 401 || r.status === 410) {
          entry.status = 'blocked';
        } else if (r.status >= 200 && r.status < 300) {
          var body = '';
          try { body = (await r.text()).slice(0, 4000); } catch (e) { body = ''; }
          entry.status = confirmExposure(p, body) ? 'exposed' : 'unconfirmed';
          entry.bytes = body.length;
        } else {
          entry.status = 'unknown';
        }
      } catch (e) {
        entry.status = sameOrigin ? 'unknown' : 'unknown';
        entry.note = sameOrigin ? '요청 실패' : 'CORS/네트워크로 확인 불가';
      }
      out.push(entry);
    }
    return out;
  }

  function confirmExposure(path, body) {
    if (!body) return false;
    if (/\.env$/.test(path)) return /^[A-Z0-9_]+\s*=\s*\S+/m.test(body);
    if (/\.git\/HEAD$/.test(path)) return /^ref:\s+refs\//m.test(body) || /^[0-9a-f]{40}$/m.test(body);
    if (/package\.json$/.test(path)) return /"name"\s*:/.test(body) && /"version"\s*:/.test(body);
    if (/DS_Store/.test(path)) return /Bud1/.test(body);
    return false;
  }

  /* ── 배포 URL 실측: Worker 프록시 ───────────────────────────────────────
     브라우저는 다른 오리진의 응답 헤더를 CORS로 읽지 못한다. 그래서 무료
     Cloudflare Worker(onetap-shield-probe)가 대신 확인해 JSON으로 돌려준다.
     Worker는 허용 출처만 받고, 사설·메타데이터 주소(SSRF)는 거부하며,
     원문 본문은 돌려주지 않고 시크릿은 가려서(masked)만 보낸다. */

  var PROBE_WORKER = 'https://onetap-shield-probe.onetap-ai.workers.dev';

  var HEADER_EASY = {
    'content-security-policy': '브라우저가 실행해도 되는 스크립트를 미리 정해두는 허용 목록이에요. 목록에 없는 스크립트는 실행되지 않습니다.',
    'strict-transport-security': '이 사이트에는 앞으로 항상 암호화된 https로만 접속하라고 브라우저에 기억시키는 장치예요.',
    'x-content-type-options': '파일 종류를 브라우저가 마음대로 추측해서 실행하지 않게 하는 잠금장치예요.',
    'x-frame-options': '다른 사이트가 내 화면을 몰래 액자처럼 끼워 넣는 걸 막는 잠금장치예요.',
    'referrer-policy': '다른 사이트로 넘어갈 때 내 주소·경로를 얼마나 알려줄지 정하는 규칙이에요.',
    'permissions-policy': '카메라·위치·마이크 같은 기능을 이 사이트가 쓸 수 있는지 정하는 스위치예요.'
  };

  /* 로컬·사설 주소인가? 그렇다면 실측 서버(공인 인터넷)로는 확인할 수 없어
     브라우저가 직접 확인한다. 서버에 400을 보내 콘솔을 어지럽히지 않기 위함. */
  function isPrivateTarget(input) {
    var u = normalizeUrl(input);
    if (!u) return true;
    var h = u.hostname.toLowerCase();
    if (h === 'localhost' || /\.localhost$/.test(h)) return true;
    if (/\.local$|\.internal$|\.home\.arpa$/.test(h)) return true;
    var v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      var a = Number(v4[1]), b = Number(v4[2]);
      if (a === 0 || a === 10 || a === 127) return true;
      if (a === 169 && b === 254) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 192 && b === 168) return true;
      if (a === 100 && b >= 64 && b <= 127) return true;
    }
    if (h.charAt(0) === '[') return true;
    if (/^\d+$/.test(h)) return true;
    return false;
  }

  function headerScoreOf(headers) {
    var earned = 0;
    SECURITY_HEADERS.forEach(function (h) { if (headers && headers[h.key]) earned += h.weight; });
    return earned;
  }

  function workerFindings(p) {
    var out = [];
    var target = p.finalUrl || p.target || '';

    SECURITY_HEADERS.forEach(function (h) {
      if (p.headers && p.headers[h.key]) return;
      out.push({
        ruleId: 'header-' + h.key, name: '보안 헤더 누락: ' + h.label, sev: h.sev, cat: 'config', kind: 'remote',
        path: target, line: 1, snippet: '',
        note: '실제 응답에 ' + h.label + ' 헤더가 없습니다(Worker 실측).',
        why: '헤더가 없으면 브라우저의 기본 방어(스크립트 제한·MIME 검사·클릭재킹 차단·리퍼러 최소화)가 작동하지 않습니다.',
        fix: '방어팩에서 이 호스팅에 맞는 헤더 파일을 생성해 배포하세요.',
        easy: HEADER_EASY[h.key] || '', easyKey: h.key,
        cwe: 'CWE-693', refs: ['https://developer.mozilla.org/ko/docs/Web/HTTP/Headers']
      });
    });

    (p.probes || []).forEach(function (pr) {
      if (pr.status !== 'exposed') return;
      var isEnv = /\.env/.test(pr.path);
      var isGit = /\.git\/HEAD/.test(pr.path);
      out.push({
        ruleId: isEnv ? 'remote-env-exposed' : isGit ? 'remote-git-exposed' : 'remote-file-exposed',
        name: isEnv ? '.env 환경변수 파일이 공개 노출' : isGit ? '.git 저장소 정보 노출' : 'package.json 공개',
        sev: isEnv ? 'critical' : isGit ? 'high' : 'low',
        cat: 'config', kind: 'remote',
        path: pr.url || (target + '/' + pr.path), line: 1,
        snippet: pr.contentType ? ('HTTP ' + pr.httpStatus + ' · ' + pr.contentType) : ('HTTP ' + pr.httpStatus),
        note: '주소창에 그대로 입력해도 ' + pr.path + ' 이(가) 내려받아집니다.',
        why: isEnv
          ? '서버 설정과 API 키가 담긴 파일을 누구나 내려받을 수 있습니다. 열쇠를 문 앞에 놓고 나간 셈입니다.'
          : isGit ? '저장소 주소와 커밋 정보가 드러나 소스 복원 시도로 이어질 수 있습니다.'
          : '의존성·스크립트·내부 패키지 이름이 그대로 드러납니다.',
        fix: isEnv
          ? '.env를 웹 루트 밖으로 옮기고 서버에서 404로 막으세요. 이미 노출된 키는 모두 교체(revoke)해야 합니다.'
          : '배포 폴더에서 이 파일을 빼고, 서버 설정으로 404를 반환하게 하세요.',
        cwe: 'CWE-538', refs: []
      });
    });

    var en = !!(typeof window !== 'undefined' && window.ONETAP_I18N && window.ONETAP_I18N.lang && window.ONETAP_I18N.lang() === 'en');
    var SECRET_LABEL_EN = {
      'google-api-key': 'Google API key',
      'openai-key': 'OpenAI API key',
      'stripe-key': 'Stripe key',
      'github-token': 'GitHub token',
      'aws-access-key': 'AWS access key',
      'slack-token': 'Slack token',
      'supabase-secret': 'Supabase service_role key',
      'pem-private-key': 'private key (PEM)',
      'anthropic-key': 'Anthropic API key',
      'jwt-token': 'JWT token'
    };
    (p.secrets || []).forEach(function (s, i) {
      var label = en ? (SECRET_LABEL_EN[s.id] || 'API key') : (s.label || 'API 키');
      out.push({
        ruleId: 'remote-live-secret-' + s.id, name: (en ? 'Key exposed in the deployed page: ' : '배포 화면에 키 노출: ') + label,
        sev: s.sev === 'low' ? 'low' : 'critical', cat: 'secret', kind: 'remote',
        path: s.where === 'html' ? target : (s.where || target), line: 1 + i,
        snippet: s.masked || '',
        note: s.where === 'html' ? '배포된 HTML 안에서 발견했습니다(Worker 실측).' : '같은 도메인의 스크립트에서 발견했습니다.',
        why: '누구나 볼 수 있는 화면에 키가 박혀 있으면, 그 키로 바로 서비스를 호출해 요금을 쓰게 만들 수 있습니다.',
        fix: '해당 키를 즉시 폐기(revoke)하고, 서버나 환경변수에서만 쓰도록 옮기세요. 프론트에 넣어야 하는 공개 키(anon key)라면 RLS로 권한을 막아야 합니다.',
        easy: '비밀 열쇠를 누구나 보는 게시판에 붙여둔 상태예요. 지우는 것만으로는 늦고, 열쇠를 새로 발급해야 합니다.',
        cwe: 'CWE-798', refs: []
      });
    });

    if (p.page && p.page.sourceMap) {
      out.push({
        ruleId: 'remote-sourcemap', name: '배포본 HTML/JS에 소스맵 참조', sev: 'low', cat: 'git', kind: 'remote',
        path: target, line: 1, snippet: 'sourceMappingURL',
        note: '', why: '소스맵이 공개되면 원본 소스와 내부 구조가 그대로 노출됩니다.',
        fix: '프로덕션에서 sourcemap을 끄거나 접근을 차단하세요.', cwe: 'CWE-540', refs: []
      });
    }

    return out;
  }

  function normalizeWorkerProbe(p, u) {
    var headers = {};
    SECURITY_HEADERS.forEach(function (h) { headers[h.key] = (p.headers && p.headers[h.key]) || ''; });
    var out = {
      ok: true, via: 'worker', target: p.target || u.href, origin: u.origin,
      sameOrigin: false, headerStatus: 'checked', headers: headers,
      headerScore: headerScoreOf(headers), headerCount: p.headerCount || 0,
      httpStatus: p.httpStatus, finalUrl: p.finalUrl || u.href,
      probes: (p.probes || []).map(function (pr) {
        return { path: (pr.path || '').replace(/^\//, ''), url: pr.url, status: pr.status, httpStatus: pr.httpStatus, bytes: pr.bytes || 0, contentType: pr.contentType || '' };
      }),
      scripts: p.scripts || [], secrets: p.secrets || [], page: p.page || {},
      redirectProblem: p.redirectProblem || '', elapsedMs: p.elapsedMs || 0,
      note: p.note || '', fetchedAt: new Date().toISOString()
    };
    out.findings = workerFindings(out);
    return out;
  }

  async function probeViaWorker(input, opts) {
    opts = opts || {};
    var u = normalizeUrl(input);
    if (!u) return { ok: false, message: 'http(s) 주소 형식이 아닙니다.' };
    var endpoint = opts.worker || PROBE_WORKER;
    var ctrl = null, timer = null;
    try {
      if (typeof AbortController !== 'undefined') {
        ctrl = new AbortController();
        timer = setTimeout(function () { ctrl.abort(); }, opts.timeout || 30000);
      }
      var res = await fetch(endpoint + '/probe?url=' + encodeURIComponent(u.href), {
        method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store',
        signal: ctrl ? ctrl.signal : undefined
      });
      var data = null;
      try { data = await res.json(); } catch (e) { data = null; }
      if (res.status === 403 && data && data.error === 'origin_not_allowed') {
        return { ok: false, reason: 'origin', message: '실측 서버가 이 페이지의 출처를 허용하지 않습니다(배포 도메인에서만 동작).' };
      }
      if (!data) return { ok: false, reason: 'bad_response', message: '실측 서버 응답을 이해하지 못했습니다(HTTP ' + res.status + ').' };
      if (!res.ok || !data.ok) {
        return {
          ok: false, reason: data.error || ('http_' + res.status),
          message: data.message || ('실측 서버 오류(HTTP ' + res.status + ')'),
          blockedTarget: /^(loopback|private|metadata|cgnat|reserved|numeric|single_label|blocked_port|bad_scheme|credentials)/.test(data.error || '')
        };
      }
      return normalizeWorkerProbe(data, u);
    } catch (e) {
      return { ok: false, reason: 'network', message: '실측 서버에 연결하지 못했습니다(네트워크).' };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /* ── GitHub 저장소 ──────────────────────────────────────────────────── */

  function parseRepo(input) {
    var s = String(input || '').trim()
      .replace(/^https?:\/\/github\.com\//i, '')
      .replace(/^git@github\.com:/i, '')
      .replace(/\.git$/i, '')
      .replace(/\/+$/, '');
    var m = s.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/(?:tree|blob)\/([^\/]+))?/);
    if (!m) return null;
    return { owner: m[1], repo: m[2], ref: m[3] || '' };
  }

  function ghHeaders(token) {
    var h = { accept: 'application/vnd.github+json' };
    if (token) h.authorization = 'Bearer ' + token;
    return h;
  }

  var INTERESTING = [
    /(^|\/)\.env(\.[a-z0-9]+)?$/i,
    /(^|\/)\.gitignore$/i,
    /(^|\/)package\.json$/i,
    /(^|\/)firestore\.rules$/i,
    /\.sql$/i,
    /(^|\/)(next|vite|nuxt|astro|svelte|remix)\.config\.[a-z]+$/i,
    /(^|\/)vercel\.json$/i,
    /(^|\/)_headers$/i,
    /(^|\/)netlify\.toml$/i,
    /(^|\/)nginx\.conf$/i,
    /(^|\/)middleware\.[jt]s$/i,
    /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|html|py|php|rb|go|java|yml|yaml|toml)$/i
  ];

  function isInteresting(path) {
    if (/(^|\/)(node_modules|\.git|dist|build|\.next|\.nuxt|coverage|vendor)\//i.test(path)) return false;
    if (/(\.min\.(js|css)|\.map|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(path)) return false;
    if (/\.(png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|mp4|mov|webm|mp3|wav|zip|pdf|wasm)$/i.test(path)) return false;
    return INTERESTING.some(function (re) { return re.test(path); });
  }

  async function scanRepo(repoInput, opts) {
    opts = opts || {};
    var parsed = parseRepo(repoInput);
    if (!parsed) return { ok: false, message: '저장소 주소 형식이 아닙니다. 예: https://github.com/owner/repo' };
    var token = opts.token || '';
    var api = 'https://api.github.com/repos/' + parsed.owner + '/' + parsed.repo;

    var metaRes;
    try {
      metaRes = await fetch(api, { headers: ghHeaders(token), mode: 'cors', cache: 'no-store' });
    } catch (e) {
      return { ok: false, message: 'GitHub API에 연결하지 못했습니다(네트워크).' };
    }

    if (metaRes.status === 403 || metaRes.status === 429) {
      var resetAt = metaRes.headers.get('x-ratelimit-reset');
      return {
        ok: false, reason: 'rate_limit',
        message: 'GitHub API 호출 한도에 걸렸습니다. 토큰을 넣거나 잠시 뒤 다시 시도하세요.',
        resetAt: resetAt ? new Date(Number(resetAt) * 1000) : null
      };
    }
    if (metaRes.status === 404) return { ok: false, reason: 'not_found', message: '저장소를 찾을 수 없습니다(비공개이거나 이름 오타).' };
    if (!metaRes.ok) {
      if (metaRes.status === 401) return { ok: false, reason: 'bad_token', message: 'GitHub 토큰이 유효하지 않습니다.' };
      return { ok: false, message: 'GitHub API 오류 (' + metaRes.status + ')' };
    }

    var meta = await metaRes.json();
    var branch = parsed.ref || meta.default_branch || 'main';
    var sizeKb = meta.size || 0;

    var treeRes = await fetch(api + '/git/trees/' + encodeURIComponent(branch) + '?recursive=1', {
      headers: ghHeaders(token), mode: 'cors', cache: 'no-store'
    });
    if (!treeRes.ok) {
      return { ok: false, message: '파일 목록을 가져오지 못했습니다 (' + treeRes.status + '). 브랜치 이름을 확인하세요.', branch: branch };
    }
    var tree = await treeRes.json();
    var nodes = (tree.tree || []).filter(function (n) { return n.type === 'blob'; });

    // 저장소에 있으면 안 되는 파일/소스맵/개인키 흔적
    var treeFindings = [];
    nodes.forEach(function (n) {
      if (/(^|\/)\.env(\.[a-z0-9]+)?$/i.test(n.path) && !/\.example$|\.sample$|\.template$/i.test(n.path)) {
        treeFindings.push({
          ruleId: 'repo-env-committed', name: '저장소에 .env 파일 커밋', sev: 'critical', cat: 'git', kind: 'repo',
          path: n.path, line: 1, snippet: '', note: '파일 크기 ' + (n.size || 0) + 'B',
          why: 'GitHub에서 파일이 그대로 보입니다. 시크릿 스캐너는 공개 저장소를 분 단위로 긁습니다.',
          fix: '파일을 삭제하고 키를 모두 교체하세요. 기록까지 지우려면 git filter-repo가 필요합니다.',
          cwe: 'CWE-538', refs: []
        });
      }
      if (/(^|\/)(\.env\.[a-z]+|\.dev\.vars|secrets\.json|service-account[^\/]*\.json)$/i.test(n.path)) {
        treeFindings.push({
          ruleId: 'repo-secret-file', name: '저장소에 시크릿 파일', sev: 'critical', cat: 'git', kind: 'repo',
          path: n.path, line: 1, snippet: '', note: '',
          why: '배포용 시크릿 파일이 공개 저장소에 있습니다.',
          fix: '삭제 후 키를 교체하고 .gitignore에 추가하세요.', cwe: 'CWE-538', refs: []
        });
      }
      if (/\.map$/i.test(n.path) && /(^|\/)(dist|build|public|static|assets)\//i.test(n.path)) {
        treeFindings.push({
          ruleId: 'repo-sourcemap', name: '배포 폴더에 소스맵(.map)', sev: 'low', cat: 'git', kind: 'repo',
          path: n.path, line: 1, snippet: '', note: '',
          why: '소스맵이 배포되면 원본 코드가 복원됩니다.',
          fix: '프로덕션 빌드에서 소스맵을 빼세요.', cwe: 'CWE-540', refs: []
        });
      }
    });

    var candidates = nodes.filter(function (n) { return isInteresting(n.path) && (n.size || 0) < 220000; });
    // 중요한 파일 우선 (.env, SQL, 설정 → 일반 소스)
    var weight = function (p) {
      if (/(^|\/)\.env/i.test(p)) return 0;
      if (/\.sql$|firestore\.rules$/i.test(p)) return 1;
      if (/(_headers|vercel\.json|next\.config|netlify|nginx|package\.json)$/i.test(p)) return 2;
      if (/(api|server|functions|workers?)\//i.test(p)) return 3;
      return 5;
    };
    candidates.sort(function (a, b) { return weight(a.path) - weight(b.path) || a.path.localeCompare(b.path); });
    var maxFiles = opts.maxFiles || 45;
    var picked = candidates.slice(0, maxFiles);

    var files = [], failed = [];
    var sha = tree.sha || branch;
    var CONC = 6;
    for (var i = 0; i < picked.length; i += CONC) {
      var chunk = picked.slice(i, i + CONC);
      var results = await Promise.all(chunk.map(function (n) {
        var raw = 'https://raw.githubusercontent.com/' + parsed.owner + '/' + parsed.repo + '/' + sha + '/' +
          n.path.split('/').map(encodeURIComponent).join('/');
        return fetch(raw, { mode: 'cors', cache: 'no-store' })
          .then(function (r) { return r.ok ? r.text().then(function (t) { return { path: n.path, content: t }; }) : { path: n.path, error: r.status }; })
          .catch(function () { return { path: n.path, error: 'network' }; });
      }));
      results.forEach(function (r) {
        if (r.error) failed.push({ path: r.path, error: r.error });
        else files.push({ path: r.path, content: r.content });
      });
      if (typeof opts.onProgress === 'function') opts.onProgress(files.length, picked.length);
    }

    return {
      ok: true,
      repo: meta.full_name,
      url: meta.html_url,
      branch: branch,
      stars: meta.stargazers_count,
      sizeKb: sizeKb,
      private: !!meta.private,
      files: files,
      failed: failed,
      treeFindings: treeFindings,
      treeTruncated: !!tree.truncated,
      totalCandidates: candidates.length,
      picked: picked.length,
      message: files.length ? '' : '읽을 수 있는 소스 파일을 찾지 못했습니다.'
    };
  }

  return {
    VERSION: VERSION,
    SECURITY_HEADERS: SECURITY_HEADERS,
    PROBE_PATHS: PROBE_PATHS,
    PROBE_WORKER: PROBE_WORKER,
    HEADER_EASY: HEADER_EASY,
    normalizeUrl: normalizeUrl,
    probeUrl: probeUrl,
    probeViaWorker: probeViaWorker,
    isPrivateTarget: isPrivateTarget,
    headerScoreOf: headerScoreOf,
    parseRepo: parseRepo,
    scanRepo: scanRepo,
    confirmExposure: confirmExposure
  };
});
