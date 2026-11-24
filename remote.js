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

  var VERSION = '1.0.0';
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
    normalizeUrl: normalizeUrl,
    probeUrl: probeUrl,
    parseRepo: parseRepo,
    scanRepo: scanRepo,
    confirmExposure: confirmExposure
  };
});
