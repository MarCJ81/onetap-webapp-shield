/* ============================================================================
   core.js · 원탭 웹앱 실드 스캔 엔진
   ----------------------------------------------------------------------------
   입력: files [{ path, content }]  (붙여넣기 1개, 업로드 N개, GitHub 저장소 N개)
   출력: 점수 · 등급 · 심각도별 카운트 · 발견 항목 · 스택 추정 · 수정 프롬프트 · 리포트

   규칙 자체는 rules.js(SHIELD_RULES)에 있고, 이 파일은 실행기다.
   브라우저 · Node 공용. 의존성 0.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./rules.js'));
  else root.SHIELD = factory(root.SHIELD_RULES);
})(typeof globalThis !== 'undefined' ? globalThis : this, function (RULES) {
  'use strict';

  var VERSION = '1.1.0';
  var MAX_FINDINGS = 400;
  var MAX_PER_RULE_FILE = 40;

  /* ── 기본 유틸 ───────────────────────────────────────────────────────── */

  function entropy(str) {
    var s = String(str || '');
    if (!s.length) return 0;
    var freq = Object.create(null), i, ch;
    for (i = 0; i < s.length; i++) { ch = s[i]; freq[ch] = (freq[ch] || 0) + 1; }
    var e = 0;
    for (var k in freq) {
      var p = freq[k] / s.length;
      e -= p * Math.log2(p);
    }
    return Math.round(e * 100) / 100;
  }

  function looksRepeated(s) {
    if (!s) return true;
    if (/^(.)\1+$/.test(s)) return true;
    var uniq = Object.create(null), n = 0;
    for (var i = 0; i < s.length; i++) if (!uniq[s[i]]) { uniq[s[i]] = 1; n++; }
    return n <= 3 && s.length > 12;
  }

  // 'bar' 같은 짧은 단어가 무작위 키 안에 우연히 들어가는 경우를 피하려고
  // 구분자로 감싼 형태만 자리표시자로 본다(예: YOUR_API_KEY, my-sample-token).
  var PLACEHOLDER_WORDS = /(?:^|[_\-.])(your|example|sample|dummy|placeholder|change[_-]?me|replace[_-]?me|insert[_-]?here|redacted|notreal|todo)(?:[_\-.]|$)/i;
  var PLACEHOLDER_EXACT = /^(?:foo|bar|baz|qux|none|null|undefined|password|passwd|secret|token|apikey|api_key|changeme|xxxx+|test|dummy|abc|abc123)$/i;
  var PLACEHOLDER_EXPR = /(\$\{|\{\{|<[^>]*>|process\.env|import\.meta\.env|os\.environ|getenv\(|ENV\[|\.\.\.|\*\*\*)/;

  function isPlaceholder(value, line) {
    var v = String(value || '');
    if (!v || v.length < 8) return true;
    if (PLACEHOLDER_EXACT.test(v)) return true;
    if (PLACEHOLDER_WORDS.test(v)) return true;
    if (PLACEHOLDER_EXPR.test(v)) return true;
    if (PLACEHOLDER_WORDS.test(line || '') && !/[A-Za-z0-9]{24,}/.test(v)) return true;
    if (looksRepeated(v)) return true;
    if (/^(?:0+|1+|a+|z+|x+|\?+|-+|_+)$/i.test(v)) return true;
    if (/(?:abcdef|qwerty|asdfgh|password123)/i.test(v)) return true;
    if (/^\d+$/.test(v) && v.length < 20) return true;
    if (/^[A-Z_]+$/.test(v)) return true;           // ENV_STYLE_NAME
    return false;
  }

  function maskSecret(value) {
    var v = String(value || '');
    if (!v) return '';
    if (v.length <= 10) return v.slice(0, 1) + '…' + v.slice(-1);
    if (v.length <= 24) return v.slice(0, 4) + '…' + v.slice(-3);
    return v.slice(0, 6) + '…' + v.slice(-4) + ' (' + v.length + '자)';
  }

  function snippetOf(line, col, value) {
    var s = String(line || '').trim();
    if (value) s = s.split(value).join(maskSecret(value));
    if (s.length > 220) {
      var at = Math.max(0, (col || 0) - 60);
      s = (at > 0 ? '…' : '') + s.slice(at, at + 220) + '…';
    }
    return s;
  }

  function lineAt(content, index) {
    if (!content || index <= 0) return 1;
    var n = 1;
    for (var i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
    return n;
  }

  function base64UrlDecode(str) {
    try {
      var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      if (typeof atob === 'function') return decodeURIComponent(escape(atob(s)));
      if (typeof Buffer !== 'undefined') return Buffer.from(s, 'base64').toString('utf8');
    } catch (e) { /* noop */ }
    return '';
  }

  function escapeReg(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  var BINARY = /\.(png|jpe?g|gif|webp|avif|ico|bmp|svgz|woff2?|ttf|otf|eot|mp[34]|wav|ogg|webm|mov|zip|gz|tgz|bz2|xz|7z|rar|pdf|docx?|xlsx?|pptx?|hwp|hwpx|class|jar|exe|dll|so|dylib|wasm|db|sqlite3?|lock|map)$/i;
  var SKIP_DIR = /(^|\/)(node_modules|\.git|\.next|\.nuxt|dist|build|coverage|vendor|__pycache__|\.cache|out|target)\//i;
  var MINIFIED = /(\.min\.(js|css)$|bundle\.js$|chunk-[a-z0-9]+\.js$)/i;

  function isComment(line, path) {
    var t = String(line).trim();
    if (!t) return false;
    if (/^(<!--|\/\/|\/\*|\*)/.test(t)) return true;
    if (/^--/.test(t) && /\.sql$/i.test(path || '')) return true;
    if (/^#/.test(t) && /(\.(env|ini|cfg|conf|toml|ya?ml|py|rb|sh)$|\.env)/i.test(path || '')) return true;
    return false;
  }

  /* ── 시크릿 스캔 ─────────────────────────────────────────────────────── */

  function scanSecrets(file) {
    var out = [];
    var content = file.content;
    var rule, m, i;

    function push(rule, value, index, lineText, note) {
      var line = lineAt(content, index);
      out.push({
        ruleId: rule.id, name: rule.name, sev: rule.sev, cat: 'secret', kind: 'secret',
        path: file.path, line: line,
        snippet: snippetOf(lineText, Math.max(0, index - content.lastIndexOf('\n', index)), value),
        secretMasked: maskSecret(value), entropy: entropy(value),
        note: note || '', why: rule.why, fix: rule.fix, cwe: rule.cwe || 'CWE-798',
        refs: rule.refs || [RULES.REFS.owaspSecrets]
      });
    }

    for (i = 0; i < RULES.SECRET_RULES.length; i++) {
      rule = RULES.SECRET_RULES[i];
      if (rule.re) rule.re.lastIndex = 0;
      if (rule.context && !rule.context.test(content)) continue;
      while ((m = rule.re.exec(content))) {
        var raw = m[rule.g || 0];
        if (!raw) { if (m.index === rule.re.lastIndex) rule.re.lastIndex++; continue; }
        var lineStart = content.lastIndexOf('\n', m.index) + 1;
        var lineEnd = content.indexOf('\n', m.index);
        if (lineEnd === -1) lineEnd = content.length;
        var lineText = content.slice(lineStart, lineEnd);
        if (rule.minEntropy && entropy(raw) < rule.minEntropy) continue;
        if (isPlaceholder(raw, lineText)) continue;
        // 문서 주석 속 예시( // example: apiKey = "..." )는 시크릿이 아니다.
        if (/(?:\/\/|\/\*|#|<!--)\s*(?:example|sample|demo|e\.g\.|예시|예\))/i.test(lineText) && !/[A-Za-z0-9]{30,}/.test(raw)) continue;
        push(rule, raw, m.index, lineText);
        if (rule.re.lastIndex === m.index) rule.re.lastIndex++;
      }
    }

    // JWT — payload를 풀어 role을 본다(문자열만 보고 판단하지 않는다).
    var jwtRe = /\b(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\b/g, jm;
    while ((jm = jwtRe.exec(content))) {
      var payload = base64UrlDecode(jm[2]);
      var role = (payload.match(/"role"\s*:\s*"([a-z_]+)"/) || [])[1] || '';
      var isService = role === 'service_role' || role === 'supabase_admin';
      var lineIdx = lineAt(content, jm.index);
      var jLine = content.slice(content.lastIndexOf('\n', jm.index) + 1, (content.indexOf('\n', jm.index) === -1 ? content.length : content.indexOf('\n', jm.index)));
      out.push({
        ruleId: isService ? 'supabase-service-role-jwt' : (role === 'anon' ? 'supabase-anon-jwt' : 'jwt-token'),
        name: isService ? 'Supabase service_role JWT' : (role === 'anon' ? 'Supabase anon JWT' : 'JWT 토큰'),
        sev: isService ? 'critical' : (role === 'anon' ? 'low' : 'medium'),
        cat: 'secret', kind: 'secret', path: file.path, line: lineIdx,
        snippet: snippetOf(jLine, 0, jm[0]), secretMasked: maskSecret(jm[0]), entropy: entropy(jm[0]),
        note: isService ? 'payload의 role이 service_role — RLS를 우회하는 관리자 토큰입니다.'
          : (role === 'anon' ? 'anon 키는 공개 전제이지만, RLS가 없으면 전체 데이터가 열립니다.' : (role ? 'role=' + role : 'JWT')),
        why: isService ? 'service_role JWT는 모든 테이블을 RLS 없이 읽고 쓸 수 있습니다. 브라우저 번들에 있으면 DB 전체가 공개됩니다.'
          : 'JWT가 코드에 하드코딩되어 있으면 만료 전까지 그대로 재사용할 수 있습니다.',
        fix: isService ? '이 키를 폐기하고 서버(Route Handler·Edge Function)에서만 사용하세요. 클라이언트는 anon 키 + RLS로 보호하세요.'
          : '토큰을 환경변수/세션 저장소로 옮기고, 노출된 토큰은 폐기하세요.',
        cwe: isService ? 'CWE-269' : 'CWE-798', refs: [RULES.REFS.supabaseKeys]
      });
    }

    return out;
  }

  /* ── 줄 단위 SAST ────────────────────────────────────────────────────── */

  function scanLines(file) {
    var out = [];
    var path = file.path;
    var lines = file.content.split('\n');
    var rule, i, ln, text;
    var perRule = Object.create(null);

    for (var r = 0; r < RULES.CODE_RULES.length; r++) {
      rule = RULES.CODE_RULES[r];
      if (rule.fileScan) continue;
      if (rule.files && !rule.files.test(path)) continue;
      if ((rule.notFiles || RULES.DOCS).test(path)) continue;
      if (MINIFIED.test(path) && rule.cat !== 'secret') continue;
      perRule[rule.id] = 0;

      for (i = 0; i < lines.length; i++) {
        text = lines[i];
        if (text.length > 600) continue;
        if (!rule.allowComment && isComment(text, path)) continue;
        rule.re.lastIndex = 0;
        if (!rule.re.test(text)) continue;
        if (rule.unless && rule.unless.test(text)) continue;
        var sev = rule.sev;
        if (rule.escalate && rule.escalate.re.test(text)) sev = rule.escalate.sev;
        if (perRule[rule.id] >= MAX_PER_RULE_FILE) break;
        perRule[rule.id]++;
        out.push({
          ruleId: rule.id, name: rule.name, sev: sev, cat: rule.cat, kind: 'sast',
          path: path, line: i + 1,
          snippet: snippetOf(text, 0), note: '',
          why: rule.why, fix: rule.fix, cwe: rule.cwe || '', refs: rule.refs || []
        });
      }
    }
    return out;
  }

  function scanFileRules(file) {
    var out = [];
    for (var i = 0; i < RULES.FILE_RULES.length; i++) {
      var rule = RULES.FILE_RULES[i];
      if (!rule.files || !rule.files.test(file.path)) continue;
      if ((rule.notFiles || RULES.DOCS).test(file.path)) continue;
      var hits = [];
      try {
        if (rule.scan) hits = rule.scan(file) || [];
        else if (rule.fileScan) hits = rule.fileScan(file) || [];
        else if (rule.re) {
          var lines = file.content.split('\n');
          for (var j = 0; j < lines.length; j++) {
            if (!rule.allowComment && isComment(lines[j], file.path)) continue;
            rule.re.lastIndex = 0;
            if (rule.re.test(lines[j])) hits.push({ line: j + 1 });
            if (hits.length > MAX_PER_RULE_FILE) break;
          }
        }
      } catch (e) { hits = []; }
      for (var k = 0; k < hits.length && k < MAX_PER_RULE_FILE; k++) {
        var h = hits[k] || {};
        var lineNo = h.line || 1;
        out.push({
          ruleId: rule.id, name: rule.name, sev: rule.sev, cat: rule.cat, kind: 'file',
          path: file.path, line: lineNo,
          snippet: snippetOf((file.content.split('\n')[lineNo - 1] || ''), 0),
          note: h.note || '', why: rule.why, fix: rule.fix,
          cwe: rule.cwe || '', refs: rule.refs || []
        });
      }
    }
    return out;
  }

  function scanCodeFileRules(file) {
    var out = [];
    RULES.CODE_RULES.forEach(function (rule) {
      if (!rule.fileScan) return;
      if (rule.files && !rule.files.test(file.path)) return;
      if ((rule.notFiles || RULES.DOCS).test(file.path)) return;
      var hits = [];
      try { hits = rule.fileScan(file) || []; } catch (e) { hits = []; }
      hits.forEach(function (h) {
        out.push({
          ruleId: rule.id, name: rule.name, sev: rule.sev, cat: rule.cat, kind: 'sast',
          path: file.path, line: (h && h.line) || 1,
          snippet: snippetOf((file.content.split('\n')[((h && h.line) || 1) - 1] || ''), 0),
          note: (h && h.note) || '', why: rule.why, fix: rule.fix,
          cwe: rule.cwe || '', refs: rule.refs || []
        });
      });
    });
    return out;
  }

  /* ── 파일 준비 ───────────────────────────────────────────────────────── */

  function normalizeFiles(input) {
    var arr = Array.isArray(input) ? input : (input ? [input] : []);
    var files = [], skipped = [];
    arr.forEach(function (f) {
      if (!f) return;
      var path = String(f.path || f.name || 'pasted.txt').replace(/^\.?\//, '');
      var content = f.content != null ? f.content : (f.text || '');
      content = String(content);
      if (!path) path = 'pasted.txt';
      if (BINARY.test(path)) { skipped.push({ path: path, reason: 'binary' }); return; }
      if (SKIP_DIR.test(path) && !/package\.json$/.test(path)) { skipped.push({ path: path, reason: 'vendor' }); return; }
      if (content.length > 1200000) { skipped.push({ path: path, reason: 'too-large' }); return; }
      if (!content.trim()) { skipped.push({ path: path, reason: 'empty' }); return; }
      files.push({ path: path, content: content, lineAt: function (idx) { return lineAt(this.content, idx); }, lineOf: function (re) {
        var m = this.content.match(re); return m ? lineAt(this.content, m.index) : 0;
      } });
    });
    return { files: files, skipped: skipped };
  }

  /* ── AI 전송 전 시크릿 마스킹 ──────────────────────────────────────────
     스캔 결과에는 원문을 남기지 않지만, AI 리뷰에 코드를 보낼 때는
     코드 안의 실제 키가 그대로 나갈 수 있다. 그래서 전송 직전에 규칙으로
     값만 [REDACTED]로 바꾼다. (이 도구가 남의 키를 AI로 흘리면 안 된다.)
     ──────────────────────────────────────────────────────────────────── */
  var PEM_BLOCK_RE = new RegExp('-----BEGIN ' + '[^-]*' + 'PRIVATE KEY-----[\\s\\S]*?-----END ' + '[^-]*' + 'PRIVATE KEY-----', 'g');

  function redact(text) {
    var out = String(text == null ? '' : text).slice(0, 200000);
    // 개인키는 헤더만 지우면 본문(base64)이 남으므로 블록 전체를 먼저 지운다.
    out = out.replace(PEM_BLOCK_RE, '[REDACTED_PRIVATE_KEY]');
    RULES.SECRET_RULES.forEach(function (rule) {
      if (!rule.re) return;
      if (rule.context && !rule.context.test(out)) return;
      rule.re.lastIndex = 0;
      out = out.replace(rule.re, function (m) {
        var val = arguments[rule.g || 0];
        if (!val) return '[REDACTED]';
        if (rule.minEntropy && entropy(val) < rule.minEntropy) return m;
        if (isPlaceholder(val, '')) return m;
        var at = m.indexOf(val);
        if (at < 0) return '[REDACTED]';
        return m.slice(0, at) + '[REDACTED]' + m.slice(at + val.length);
      });
    });
    out = out.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}(?:\.[A-Za-z0-9_-]{8,})?\b/g, '[REDACTED_JWT]');
    return out;
  }

  /* ── 스택 추정 & 방어 추천 ───────────────────────────────────────────── */

  function detectStack(files) {
    var all = files.map(function (f) { return f.content; }).join('\n');
    var paths = files.map(function (f) { return f.path; }).join('\n');
    var stack = [];
    function add(id, label) { if (!stack.some(function (s) { return s.id === id; })) stack.push({ id: id, label: label }); }

    if (/next\.config|"next"\s*:/.test(all + paths) || /from ['"]next\//.test(all)) add('next', 'Next.js');
    if (/"react"\s*:|from ['"]react['"]/.test(all)) add('react', 'React');
    if (/supabase|createClient\s*\(/.test(all) || /supabase\//.test(paths)) add('supabase', 'Supabase');
    if (/firebase|firestore/i.test(all)) add('firebase', 'Firebase');
    if (/stripe/i.test(all)) add('stripe', 'Stripe');
    if (/openai|anthropic|gemini/i.test(all)) add('llm', 'LLM API');
    if (/express\s*\(|from ['"]express['"]/.test(all)) add('express', 'Express');
    if (/prisma/i.test(all)) add('prisma', 'Prisma');
    if (/MONGO|mongodb/i.test(all)) add('mongo', 'MongoDB');
    if (/fastapi|django|flask/i.test(all)) add('python', 'Python');
    if (/wrangler|cloudflare/i.test(all)) add('cloudflare', 'Cloudflare');
    if (/vercel/i.test(all + paths)) add('vercel', 'Vercel');
    if (!stack.length) add('static', '정적 웹');
    return stack;
  }

  function recommendHosting(stack) {
    var ids = stack.map(function (s) { return s.id; });
    if (ids.indexOf('next') >= 0) return 'next';
    if (ids.indexOf('vercel') >= 0) return 'vercel';
    if (ids.indexOf('express') >= 0) return 'nginx';
    if (ids.indexOf('cloudflare') >= 0) return 'cloudflare';
    return 'cloudflare';
  }

  /* ── 점수 ────────────────────────────────────────────────────────────── */

  var CAP = { critical: 100, high: 46, medium: 26, low: 10, info: 0 };

  function gradeOf(points) {
    if (points >= 99) return { grade: 'A+', label: '모범 방어', tone: 'ok' };
    if (points >= 95) return { grade: 'A', label: '안전', tone: 'ok' };
    if (points >= 90) return { grade: 'A-', label: '양호', tone: 'ok' };
    if (points >= 85) return { grade: 'B+', label: '경미한 구멍', tone: 'ok' };
    if (points >= 78) return { grade: 'B', label: '주의 필요', tone: 'warn' };
    if (points >= 70) return { grade: 'B-', label: '주의 필요', tone: 'warn' };
    if (points >= 60) return { grade: 'C+', label: '취약', tone: 'warn' };
    if (points >= 50) return { grade: 'C', label: '취약', tone: 'warn' };
    if (points >= 35) return { grade: 'D', label: '위험', tone: 'bad' };
    return { grade: 'F', label: '즉시 조치', tone: 'bad' };
  }

  function scoreFindings(findings) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) { if (counts[f.sev] != null) counts[f.sev]++; });
    var raw = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) {
      var w = (RULES.SEVERITY[f.sev] || RULES.SEVERITY.info).weight;
      raw[f.sev] += w;
    });
    var deduction = 0;
    Object.keys(raw).forEach(function (sev) {
      deduction += Math.min(raw[sev], CAP[sev] || 0);
    });
    var points = Math.max(0, Math.round((100 - deduction) * 10) / 10);
    var g = gradeOf(points);
    return {
      points: points, grade: g.grade, label: g.label, tone: g.tone,
      counts: counts, deduction: Math.round(deduction * 10) / 10,
      raw: raw
    };
  }

  /* ── 정렬·중복 제거 ──────────────────────────────────────────────────── */

  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function dedupe(findings) {
    var seen = Object.create(null), out = [];
    var secretLines = Object.create(null);
    var envContent = Object.create(null);
    findings.forEach(function (f) {
      if (f.kind === 'secret') secretLines[f.path + ':' + f.line] = 1;
      if (f.ruleId === 'env-file-committed') envContent[f.path] = 1;
    });
    findings.forEach(function (f) {
      // 저장소 트리에서 .env 존재를 잡았고 내용까지 스캔했다면 하나로 본다.
      if (f.ruleId === 'repo-env-committed' && envContent[f.path]) return;
      // 일반 비밀값 규칙은 같은 줄에 구체적 시크릿이 이미 잡혔으면 중복이다.
      if (f.ruleId === 'generic-secret' && secretLines[f.path + ':' + f.line]) {
        var other = findings.some(function (g) { return g.kind === 'secret' && g.ruleId !== 'generic-secret' && g.path === f.path && g.line === f.line; });
        if (other) return;
      }
      var key = [f.ruleId, f.path, f.line, f.secretMasked || '', f.note || ''].join('|');
      if (seen[key]) return;
      seen[key] = 1;
      out.push(f);
    });
    return out;
  }

  function sortFindings(findings) {
    return findings.sort(function (a, b) {
      return (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) ||
        String(a.path).localeCompare(String(b.path)) ||
        (a.line - b.line) ||
        String(a.ruleId).localeCompare(String(b.ruleId));
    });
  }

  /* ── 메인 스캔 ───────────────────────────────────────────────────────── */

  function scan(input, opts) {
    opts = opts || {};
    var t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    var norm = normalizeFiles(input);
    var files = norm.files;
    var findings = [];
    var lines = 0;

    files.forEach(function (file) {
      lines += file.content.split('\n').length;
      findings = findings.concat(scanSecrets(file));
      findings = findings.concat(scanLines(file));
      findings = findings.concat(scanFileRules(file));
      findings = findings.concat(scanCodeFileRules(file));
    });

    if (files.length >= 2 && !files.some(function (f) { return /(^|\/)\.gitignore$/i.test(f.path); })) {
      findings.push({
        ruleId: 'gitignore-absent', name: '.gitignore 없음', sev: 'medium', cat: 'git', kind: 'file',
        path: '.gitignore', line: 1, snippet: '', note: '여러 파일을 스캔했지만 .gitignore가 없습니다.',
        why: '.env·개인키·DB 파일이 그대로 커밋될 수 있습니다.',
        fix: '방어팩의 .gitignore를 저장소 루트에 추가하세요.', cwe: 'CWE-538', refs: []
      });
    }
    if (opts.extraFindings && opts.extraFindings.length) findings = findings.concat(opts.extraFindings);

    findings = dedupe(findings);
    // .env를 쓰지 않는 라이브러리 저장소에 '.gitignore에 .env 누락'을 경고하지 않는다.
    var usesEnv = files.some(function (f) {
      return !/(^|\/)\.gitignore$/i.test(f.path) && /(process\.env|import\.meta\.env|dotenv|\.env)/.test(f.content);
    });
    if (!usesEnv) findings = findings.filter(function (f) { return f.ruleId !== 'gitignore-missing-entries'; });
    findings = sortFindings(findings).slice(0, MAX_FINDINGS);

    var stack = detectStack(files);
    var score = scoreFindings(findings);
    var byCat = {};
    findings.forEach(function (f) { byCat[f.cat] = (byCat[f.cat] || 0) + 1; });

    var t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    return {
      version: VERSION,
      findings: findings,
      score: score,
      counts: score.counts,
      byCat: byCat,
      stack: stack,
      hosting: recommendHosting(stack),
      files: files.map(function (f) { return { path: f.path, chars: f.content.length, lines: f.content.split('\n').length }; }),
      skipped: norm.skipped,
      totals: { files: files.length, lines: lines, findings: findings.length },
      scope: {
        static: true,
        runtime: false,
        note: '정적 규칙 분석입니다. 실제 침투 테스트·런타임 검증은 아닙니다.'
      },
      ms: Math.max(0, Math.round(t1 - t0))
    };
  }

  /* ── 수정 프롬프트 ───────────────────────────────────────────────────── */

  function fixPrompt(finding, ctx) {
    ctx = ctx || {};
    var f = finding || {};
    var en = !!(typeof window !== 'undefined' && window.ONETAP_I18N && window.ONETAP_I18N.lang && window.ONETAP_I18N.lang() === 'en');
    if (en) {
      var e = [
        'Fix this security issue in my current code now. Keep every other behaviour and screen the same.', '',
        '## Issue',
        '- Type: ' + (f.name || f.ruleId) + ' (' + (f.sev || 'medium') + ')',
        '- Where: ' + (f.path || 'code') + (f.line ? ':' + f.line : ''),
        f.cwe ? '- Class: ' + f.cwe : '',
        '- Risk: ' + (f.why || ''),
        f.note ? '- Observed: ' + f.note : '', '',
        '## Problem code', '```',
        (f.snippet || '(the part in my code)'), '```', '',
        '## Requirements',
        '1. Replace it with a safe approach: ' + (f.fix || 'validate input and use a safe API'),
        '2. Keep secrets out of the code — move them to environment variables and show the name and a .env example.',
        '3. Fix the same problem elsewhere in the file too.',
        '4. Show the full fixed file and summarise in three lines what changed and why.'
      ];
      if (ctx.extra) e.push('5. ' + ctx.extra);
      return e.join('\n').replace(/\n{3,}/g, '\n\n');
    }
    var head = '아래 보안 취약점을 지금 코드에서 고쳐줘. 다른 동작과 화면은 그대로 유지해.';
    var lines = [
      head, '',
      '## 취약점',
      '- 종류: ' + (f.name || f.ruleId) + ' (' + (f.sev || 'medium') + ')',
      '- 위치: ' + (f.path || 'code') + (f.line ? ':' + f.line : ''),
      f.cwe ? '- 분류: ' + f.cwe : '',
      '- 위험: ' + (f.why || ''),
      f.note ? '- 관찰: ' + f.note : '',
      '',
      '## 문제 코드',
      '```',
      (f.snippet || '(붙여넣은 코드에서 해당 부분)'),
      '```',
      '',
      '## 요구사항',
      '1. 위 위치를 안전한 방식으로 바꿔줘: ' + (f.fix || '입력 검증과 안전한 API로 교체'),
      '2. 비밀값은 코드에 두지 말고 환경변수로 옮겨줘. 이름과 .env 예시도 알려줘.',
      '3. 같은 문제가 파일 다른 곳에도 있으면 함께 고쳐줘.',
      '4. 수정한 파일 전체를 보여주고, 무엇이 왜 바뀌었는지 3줄로 요약해줘.'
    ];
    if (ctx.extra) lines.push('5. ' + ctx.extra);
    return lines.filter(function (l) { return l !== '' || true; }).join('\n').replace(/\n{3,}/g, '\n\n');
  }

  function renderMarkdown(text) {
    var esc = String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    var blocks = [];
    // 코드펜스는 먼저 떼어내 다른 치환에 영향받지 않게 한다(언어 토큰도 제거).
    esc = esc.replace(/```[ \t]*([A-Za-z0-9+#.-]*)[ \t]*\n?([\s\S]*?)```/g, function (m, lang, code) {
      blocks.push('<pre><code>' + code.replace(/\n$/, '') + '</code></pre>');
      return '\n@@CODE' + (blocks.length - 1) + '@@\n';
    });

    function inline(s) {
      return s
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>');
    }
    function cells(line) {
      return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(function (c) { return inline(c.trim()); });
    }

    var lines = esc.split('\n');
    var html = [], listOpen = false, i = 0;
    function closeList() { if (listOpen) { html.push('</ul>'); listOpen = false; } }

    while (i < lines.length) {
      var ln = lines[i];
      var code = ln.trim().match(/^@@CODE(\d+)@@$/);
      if (code) {
        closeList();
        html.push(blocks[Number(code[1])] || '');
        i++; continue;
      }
      // 파이프 테이블 (헤더 + --- 구분선)
      if (ln.indexOf('|') >= 0 && i + 1 < lines.length && /-{2,}/.test(lines[i + 1]) && /^[\s|:-]+$/.test(lines[i + 1].replace(/-/g, ''))) {
        closeList();
        var head = cells(ln);
        i += 2;
        var rows = [];
        while (i < lines.length && lines[i].indexOf('|') >= 0 && lines[i].trim()) { rows.push(cells(lines[i])); i++; }
        html.push('<table><thead><tr>' + head.map(function (h) { return '<th>' + h + '</th>'; }).join('') +
          '</tr></thead><tbody>' + rows.map(function (r) {
            return '<tr>' + r.map(function (c) { return '<td>' + c + '</td>'; }).join('') + '</tr>';
          }).join('') + '</tbody></table>');
        continue;
      }
      var m = ln.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
      if (m) {
        if (!listOpen) { html.push('<ul>'); listOpen = true; }
        html.push('<li>' + inline(m[1]) + '</li>');
        i++; continue;
      }
      closeList();
      var h = ln.match(/^(#{1,6})\s+(.*)$/);
      if (h) {
        var lv = Math.min(4, h[1].length + 2);
        html.push('<h' + lv + '>' + inline(h[2]) + '</h' + lv + '>');
        i++; continue;
      }
      if (ln.trim()) html.push('<p>' + inline(ln) + '</p>');
      i++;
    }
    closeList();
    return html.join('');
  }

  /* ── 리포트 ──────────────────────────────────────────────────────────── */

  function pad(n) { return n < 10 ? '0' + n : '' + n; }

  function stamp(date) {
    var d = date || new Date();
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function reportMarkdown(result, meta) {
    meta = meta || {};
    var r = result || {};
    var s = r.score || scoreFindings([]);
    var pts = s.points == null ? 100 : s.points;
    var out = [];
    out.push('# 웹앱 보안 리포트' + (meta.title ? ' — ' + meta.title : ''));
    out.push('');
    out.push('**보안 점수 ' + pts + ' / 100 · 등급 ' + s.grade + ' (' + s.label + ')**');
    out.push('');
    out.push('- 스캔 일시: ' + (meta.date || stamp()));
    out.push('- 스캔 대상: ' + (meta.source || '붙여넣은 코드') + ' · 파일 ' + ((r.totals && r.totals.files) || 0) + '개 / ' + ((r.totals && r.totals.lines) || 0) + '줄');
    out.push('- 취약점: ' + (r.totals ? r.totals.findings : 0) + '건 (치명적 ' + (s.counts ? s.counts.critical : 0) + ' · 높음 ' + (s.counts ? s.counts.high : 0) + ' · 보통 ' + (s.counts ? s.counts.medium : 0) + ' · 낮음 ' + (s.counts ? s.counts.low : 0) + ')');
    if (r.stack && r.stack.length) out.push('- 추정 스택: ' + r.stack.map(function (x) { return x.label; }).join(', '));
    out.push('- 도구: OneTap WebApp Shield v' + VERSION + ' (정적 규칙 엔진)');
    out.push('');
    out.push('> 이 리포트는 소스·설정 파일에 대한 정적 분석 결과입니다. 런타임 침투 테스트나 실제 공격 검증이 아니며, 규칙에 없는 취약점은 잡지 못할 수 있습니다.');
    out.push('');

    out.push('## 심각도 요약');
    out.push('');
    out.push('| 심각도 | 건수 |');
    out.push('| --- | --- |');
    ['critical', 'high', 'medium', 'low', 'info'].forEach(function (k) {
      out.push('| ' + RULES.SEVERITY[k].label + ' | ' + ((s.counts && s.counts[k]) || 0) + ' |');
    });
    out.push('');

    if (!r.findings || !r.findings.length) {
      out.push('## 발견 항목');
      out.push('');
      out.push('규칙에 걸린 항목이 없습니다. (스캔 범위 밖의 취약점은 별도 점검이 필요합니다.)');
      out.push('');
    } else {
      out.push('## 발견 항목');
      out.push('');
      r.findings.forEach(function (f, i) {
        out.push('### ' + (i + 1) + '. [' + (RULES.SEVERITY[f.sev] || {}).label + '] ' + f.name);
        out.push('');
        out.push('- 위치: `' + f.path + (f.line ? ':' + f.line : '') + '`');
        if (f.cwe) out.push('- 분류: ' + f.cwe);
        if (f.note) out.push('- 관찰: ' + f.note);
        if (f.snippet) out.push('- 코드: `' + String(f.snippet).replace(/`/g, "'") + '`');
        out.push('- 위험: ' + (f.why || ''));
        out.push('- 수정: ' + (f.fix || ''));
        out.push('');
      });
    }

    if (meta.extras && meta.extras.length) {
      out.push('## 추가 점검');
      out.push('');
      meta.extras.forEach(function (x) { out.push('- ' + x); });
      out.push('');
    }
    out.push('## 미확인 · 한계');
    out.push('');
    out.push('- 브라우저에서 다른 도메인의 응답 헤더를 읽지 못한 경우(CORS), 서버 헤더는 "미확인"으로 남습니다.');
    out.push('- 의존성 CVE는 OSV.dev 조회 결과이며, 실제 설치된 버전과 다를 수 있습니다.');
    out.push('- 로직·비즈니스 규칙 취약점(예: 남의 주문 조회)은 정적 규칙으로 잡지 못합니다.');
    out.push('');
    out.push('---');
    out.push('Generated by OneTap WebApp Shield · https://marcj81.github.io/onetap-webapp-shield/');
    return out.join('\n');
  }

  function reportJson(result, meta) {
    meta = meta || {};
    return JSON.stringify({
      tool: 'onetap-webapp-shield', version: VERSION,
      generatedAt: new Date().toISOString(),
      generatedLabel: meta.date || stamp(),
      source: meta.source || '',
      title: meta.title || '',
      score: result.score, counts: result.counts,
      totals: result.totals, stack: result.stack,
      scope: result.scope,
      findings: (result.findings || []).map(function (f) {
        return {
          rule: f.ruleId, name: f.name, severity: f.sev, category: f.cat,
          path: f.path, line: f.line, note: f.note || '',
          snippet: f.snippet, cwe: f.cwe || '',
          why: f.why, fix: f.fix
        };
      }),
      mitigations: meta.extras || []
    }, null, 2);
  }

  function badgeSvg(points, grade, label) {
    var tone = points >= 80 ? '#0B7A55' : (points >= 60 ? '#A9550A' : '#B4211C');
    var g = String(grade || '');
    var w = 196;
    return [
      '<svg xmlns="http://www.w3.org/2000/svg" width="' + w + '" height="44" viewBox="0 0 ' + w + ' 44" role="img" aria-label="WebApp Shield ' + points + '/100 ' + g + '">',
      '<rect width="' + w + '" height="44" rx="9" fill="#0C0D0F"/>',
      '<path d="M20 11l9 3.4v6.8c0 5.6-3.7 9.9-9 11.8-5.3-1.9-9-6.2-9-11.8v-6.8z" fill="none" stroke="#3DE0A8" stroke-width="1.8" stroke-linejoin="round"/>',
      '<path d="M16.6 21.4l2.6 2.6 4.9-5.2" fill="none" stroke="#3DE0A8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
      '<text x="40" y="19" fill="#F4F5F7" font-family="ui-sans-serif,system-ui,sans-serif" font-size="11" letter-spacing=".06em">WEBAPP SHIELD</text>',
      '<text x="40" y="34" fill="' + tone + '" font-family="ui-monospace,Menlo,monospace" font-size="14" font-weight="700">' + points + '/100 · ' + g + '</text>',
      '</svg>'
    ].join('');
  }

  /* ── 내보내기 ────────────────────────────────────────────────────────── */

  return {
    VERSION: VERSION,
    RULES: RULES,
    entropy: entropy,
    maskSecret: maskSecret,
    isPlaceholder: isPlaceholder,
    redact: redact,
    normalizeFiles: normalizeFiles,
    scan: scan,
    scanSecrets: scanSecrets,
    detectStack: detectStack,
    recommendHosting: recommendHosting,
    scoreFindings: scoreFindings,
    gradeOf: gradeOf,
    sortFindings: sortFindings,
    fixPrompt: fixPrompt,
    reportMarkdown: reportMarkdown,
    reportJson: reportJson,
    renderMarkdown: renderMarkdown,
    badgeSvg: badgeSvg,
    stamp: stamp,
    lineAt: lineAt
  };
});
