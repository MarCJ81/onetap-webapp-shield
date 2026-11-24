/* ============================================================================
   app.js · 원탭 웹앱 실드 UI
   ----------------------------------------------------------------------------
   - 입력 즉시 로컬 스캔 (rules.js + core.js)
   - GitHub 저장소 · 배포 URL 실측 (remote.js)
   - 방어팩 생성 (defense.js), OSV.dev 조회 (osv.js)
   - 무료 AI 체험 + BYOK (engines/free-ai-client.js)
   - 리포트 MD/JSON/배지

   화면에 들어오는 모든 외부 문자열(코드 조각·AI 답변·저장소 경로)은
   textContent로만 넣는다. innerHTML은 우리가 만든 정적 SVG에만 쓴다.
   ========================================================================== */
(function () {
  'use strict';

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var STORE = 'shield.settings.v1';
  var BYOK = 'shield.byok.v1';

  var S = {
    tab: 'scan',
    mode: 'code',
    code: { path: 'src/app.js', text: '' },
    uploaded: [],
    repo: { files: [], findings: [], label: '', branch: '', failed: 0 },
    urlProbe: null,
    urlFindings: [],
    result: null,
    filter: 'all',
    open: Object.create(null),
    groupByFile: false,
    hosting: 'cloudflare',
    csp: [],
    inlineStyle: true,
    upgrade: true,
    osv: null,
    osvBusy: false,
    pkgTouched: false,
    ai: { text: '', provider: '', busy: false },
    byok: { provider: 'gemini', key: '', model: 'gemini-2.5-flash' },
    toastTimer: null
  };

  var FREE = window.FreeAI;
  var PRESETS = window.SAMPLES ? window.SAMPLES.getPresets() : [];
  var HOSTINGS = window.DEFENSE.HOSTINGS;

  /* ── 작은 도우미 ─────────────────────────────────────────────────────── */

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function icon(paths, size) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 20 20');
    svg.setAttribute('width', size || 13);
    svg.setAttribute('height', size || 13);
    svg.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', paths);
    p.setAttribute('fill', 'none');
    p.setAttribute('stroke', 'currentColor');
    p.setAttribute('stroke-width', '1.7');
    p.setAttribute('stroke-linecap', 'round');
    p.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(p);
    return svg;
  }

  function toast(msg) {
    var t = $('#toast');
    t.textContent = msg;
    t.classList.add('is-on');
    clearTimeout(S.toastTimer);
    S.toastTimer = setTimeout(function () { t.classList.remove('is-on'); }, 1900);
  }

  function copyText(text, okMsg) {
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) { /* noop */ }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(okMsg || '복사했습니다'); }, function () {
        fallback(); toast(okMsg || '복사했습니다');
      });
    } else {
      fallback(); toast(okMsg || '복사했습니다');
    }
  }

  function download(filename, content, type) {
    var blob = content instanceof Uint8Array
      ? new Blob([content], { type: type || 'application/octet-stream' })
      : new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function stampName(prefix, ext) {
    var d = new Date();
    function p(n) { return n < 10 ? '0' + n : '' + n; }
    return prefix + '-' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + '.' + ext;
  }

  function saveSettings() {
    try {
      localStorage.setItem(STORE, JSON.stringify({
        theme: document.documentElement.getAttribute('data-theme'),
        hosting: S.hosting, csp: S.csp, inlineStyle: S.inlineStyle,
        upgrade: S.upgrade, groupByFile: S.groupByFile
      }));
    } catch (e) { /* noop */ }
  }

  function loadSettings() {
    try {
      var raw = localStorage.getItem(STORE);
      if (!raw) return;
      var d = JSON.parse(raw);
      if (d.theme === 'light' || d.theme === 'dark') document.documentElement.setAttribute('data-theme', d.theme);
      if (d.hosting && HOSTINGS.some(function (h) { return h.id === d.hosting; })) S.hosting = d.hosting;
      if (Array.isArray(d.csp)) S.csp = d.csp;
      if (typeof d.inlineStyle === 'boolean') S.inlineStyle = d.inlineStyle;
      if (typeof d.upgrade === 'boolean') S.upgrade = d.upgrade;
      if (typeof d.groupByFile === 'boolean') S.groupByFile = d.groupByFile;
    } catch (e) { /* noop */ }
  }

  function loadByok() {
    try {
      var raw = localStorage.getItem(BYOK);
      if (!raw) return;
      var d = JSON.parse(raw);
      if (d && d.key) S.byok = { provider: d.provider || 'gemini', key: d.key, model: d.model || 'gemini-2.5-flash' };
    } catch (e) { /* noop */ }
  }

  /* ── 소스 파일 집합 ─────────────────────────────────────────────────── */

  function currentFiles() {
    if (S.mode === 'code') {
      var t = S.code.text;
      if (!t.trim()) return [];
      return [{ path: S.code.path.trim() || 'pasted.txt', content: t }];
    }
    if (S.mode === 'files') return S.uploaded.slice();
    if (S.mode === 'github') return S.repo.files.slice();
    return [];
  }

  function sourceLabel() {
    if (S.mode === 'code') return '붙여넣은 코드 · ' + (S.code.path || 'pasted.txt');
    if (S.mode === 'files') return '업로드한 파일 ' + S.uploaded.length + '개';
    if (S.mode === 'github') return 'GitHub ' + (S.repo.label || '저장소');
    if (S.mode === 'url') return '배포 URL ' + (S.urlProbe ? S.urlProbe.target : '');
    return '';
  }

  /* ── 스캔 ───────────────────────────────────────────────────────────── */

  var scanTimer = null;
  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(rescan, 220);
  }

  function rescan() {
    var files = currentFiles();
    var extra = [];
    if (S.mode === 'github') extra = S.repo.findings.slice();
    if (S.mode === 'url') extra = S.urlFindings.slice();

    if (!files.length && !extra.length) {
      S.result = null;
      renderAll();
      return;
    }

    var res = window.SHIELD.scan(files, { extraFindings: extra });

    if (S.mode === 'url') {
      var p = S.urlProbe;
      if (!p || p.headerStatus !== 'checked') {
        res.score = Object.assign({}, res.score, {
          points: null, grade: '?',
          label: (p && p.headerStatus === 'unreachable') ? '접속 실패' : '헤더 미확인',
          tone: 'warn', deduction: null
        });
      }
    }
    S.result = res;
    maybePrefillPackage(files);
    renderAll();
  }

  function maybePrefillPackage(files) {
    if (S.pkgTouched) return;
    var pkg = (files || []).filter(function (f) { return /(^|\/)package\.json$/i.test(f.path); })[0];
    if (pkg && !$('#pkgText').value.trim()) $('#pkgText').value = pkg.content.slice(0, 60000);
  }

  /* ── 렌더: 점수 ─────────────────────────────────────────────────────── */

  var SEV_KO = { critical: '치명적', high: '높음', medium: '보통', low: '낮음', info: '참고' };
  var TONE_COLOR = { ok: '#2BE0A8', warn: '#F2C94C', bad: '#FF6B6B' };

  function renderScore() {
    var r = S.result;
    var gauge = $('#scoreGauge');
    var num = $('#scoreNum');
    var grade = $('#scoreGrade');
    var label = $('#scoreLabel');
    var sub = $('#scoreSub');
    var chips = $('#sevChips');
    var bars = $('#catBars');
    var scope = $('#scanScope');

    chips.textContent = '';
    bars.textContent = '';

    if (!r) {
      gauge.style.setProperty('--p', 0);
      gauge.style.setProperty('--tone', 'var(--surface-3)');
      num.textContent = '—';
      grade.textContent = '—';
      grade.className = 'badge grade';
      label.textContent = '검사 대기';
      sub.textContent = '코드를 넣으면 즉시 채점합니다.';
      scope.textContent = '';
      scope.appendChild(el('b', null, '검사 범위'));
      scope.appendChild(document.createTextNode(' 정적 규칙 분석 · 런타임 침투 테스트 아님'));
      return;
    }

    var pts = r.score.points;
    var tone = r.score.tone || 'warn';
    gauge.style.setProperty('--p', pts == null ? 0 : Math.max(4, pts));
    gauge.style.setProperty('--tone', TONE_COLOR[tone] || '#F2C94C');
    num.textContent = pts == null ? '—' : String(pts);
    grade.textContent = r.score.grade;
    grade.className = 'badge grade ' + (pts == null ? '' : tone);
    label.textContent = r.score.label;

    if (pts == null) {
      sub.textContent = '이 오리진의 응답 헤더를 브라우저가 읽지 못했습니다. 아래 내용은 확인된 항목만 반영합니다.';
    } else if (!r.totals.findings) {
      sub.textContent = '규칙에 걸린 항목이 없습니다. 스캔 범위 밖 취약점은 별도 점검이 필요합니다.';
    } else {
      var parts = [];
      if (r.counts.critical) parts.push('치명적 ' + r.counts.critical + '건');
      if (r.counts.high) parts.push('높음 ' + r.counts.high + '건');
      if (r.counts.medium) parts.push('보통 ' + r.counts.medium + '건');
      if (r.counts.low) parts.push('낮음 ' + r.counts.low + '건');
      sub.textContent = parts.join(' · ') + (r.counts.critical || r.counts.high ? ' — 배포 전 수정이 필요합니다.' : ' — 경미한 항목부터 정리하세요.');
    }

    ['critical', 'high', 'medium', 'low'].forEach(function (sev) {
      var c = el('span', 'sev-chip' + (r.counts[sev] ? '' : ' is-zero'));
      c.setAttribute('data-sev', sev);
      c.appendChild(el('b', null, String(r.counts[sev])));
      c.appendChild(document.createTextNode(SEV_KO[sev]));
      chips.appendChild(c);
    });

    var cats = Object.keys(r.byCat).map(function (k) { return { id: k, n: r.byCat[k] }; })
      .sort(function (a, b) { return b.n - a.n; }).slice(0, 6);
    if (!cats.length) {
      bars.appendChild(el('span', 'cat-empty', '카테고리별 발견 없음'));
    } else {
      var max = cats[0].n;
      cats.forEach(function (c) {
        var row = el('div', 'cat-row');
        row.appendChild(el('span', null, window.SHIELD.RULES.CATEGORIES[c.id] || c.id));
        var track = el('div', 'cat-track');
        var fill = el('div', 'cat-fill');
        fill.style.width = Math.max(6, Math.round(c.n / max * 100)) + '%';
        track.appendChild(fill);
        row.appendChild(track);
        row.appendChild(el('em', null, String(c.n)));
        bars.appendChild(row);
      });
    }

    scope.textContent = '';
    scope.appendChild(el('b', null, '검사 범위'));
    var meta = ' 파일 ' + r.totals.files + '개 · ' + r.totals.lines + '줄 · ' + r.ms + 'ms · 정적 분석(런타임 아님)';
    if (r.skipped.length) meta += ' · 제외 ' + r.skipped.length + '개';
    if (S.mode === 'url') meta += ' · URL 모드(확인된 헤더·노출 파일만 반영)';
    scope.appendChild(document.createTextNode(meta));
  }

  function renderHeadStats() {
    var r = S.result;
    $('#statFiles').textContent = r ? r.totals.files : 0;
    $('#statLines').textContent = r ? r.totals.lines : 0;
    $('#statMs').textContent = r ? r.ms : 0;
    var badge = $('#tabScanCount');
    if (r && r.totals.findings) {
      badge.hidden = false;
      badge.textContent = String(r.totals.findings);
    } else {
      badge.hidden = true;
    }
  }

  function renderStack() {
    var panel = $('#stackPanel');
    var wrap = $('#stackChips');
    wrap.textContent = '';
    if (!S.result || !S.result.stack.length) { panel.hidden = true; return; }
    panel.hidden = false;
    S.result.stack.forEach(function (s) {
      wrap.appendChild(el('span', 'stack-chip', s.label));
    });
  }

  /* ── 렌더: 발견 항목 ────────────────────────────────────────────────── */

  function sevRank(s) { return ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 })[s] || 9; }

  function visibleFindings() {
    if (!S.result) return [];
    return S.result.findings.filter(function (f) { return S.filter === 'all' || f.sev === S.filter; });
  }

  function renderFilters() {
    var box = $('#findingFilters');
    box.textContent = '';
    var counts = S.result ? S.result.counts : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var total = S.result ? S.result.totals.findings : 0;
    var all = el('button', 'fchip' + (S.filter === 'all' ? ' is-on' : ''), '전체 ');
    all.type = 'button';
    all.setAttribute('data-filter', 'all');
    all.appendChild(el('b', null, String(total)));
    box.appendChild(all);

    ['critical', 'high', 'medium', 'low'].forEach(function (sev) {
      var b = el('button', 'fchip' + (S.filter === sev ? ' is-on' : ''));
      b.type = 'button';
      b.setAttribute('data-filter', sev);
      b.setAttribute('data-sev', sev);
      b.appendChild(document.createTextNode(SEV_KO[sev] + ' '));
      b.appendChild(el('b', null, String(counts[sev])));
      box.appendChild(b);
    });
  }

  function findingNode(f) {
    var key = f.ruleId + '|' + f.path + '|' + f.line + '|' + (f.secretMasked || '');
    var art = el('article', 'finding');
    art.setAttribute('data-sev', f.sev);
    art.setAttribute('data-key', key);

    var head = el('button', 'finding-head');
    head.type = 'button';
    head.setAttribute('aria-expanded', S.open[key] ? 'true' : 'false');
    head.appendChild(el('span', 'sev-dot'));

    var title = el('span', 'finding-title');
    title.appendChild(el('strong', null, f.name));
    title.appendChild(el('span', null, (f.path || '') + (f.line ? ':' + f.line : '')));
    head.appendChild(title);

    var right = el('span', 'finding-right');
    right.appendChild(el('span', 'sev-label', SEV_KO[f.sev] || f.sev));
    right.appendChild(icon('M7 4l6 6-6 6', 13));
    var chev = right.lastChild;
    chev.setAttribute('class', 'chev');
    head.appendChild(right);
    art.appendChild(head);

    var body = el('div', 'finding-body');
    if (S.open[key]) art.classList.add('is-open');

    if (f.note) body.appendChild(el('p', 'finding-note', f.note));

    if (f.snippet) {
      var pre = el('pre', 'finding-snippet');
      pre.textContent = f.snippet;
      body.appendChild(pre);
    }

    var grid = el('div', 'fgrid');
    var b1 = el('div', 'fblock');
    b1.appendChild(el('h4', null, '왜 위험한가'));
    b1.appendChild(el('p', null, f.why || ''));
    var b2 = el('div', 'fblock');
    b2.appendChild(el('h4', null, '고치는 법'));
    b2.appendChild(el('p', null, f.fix || ''));
    grid.appendChild(b1);
    grid.appendChild(b2);
    body.appendChild(grid);

    var foot = el('div', 'finding-foot');
    var meta = el('div', 'finding-meta');
    if (f.cwe) meta.appendChild(el('span', null, f.cwe));
    meta.appendChild(el('span', null, '규칙 ' + f.ruleId));
    if (f.kind === 'secret' && f.secretMasked) meta.appendChild(el('span', null, '값 ' + f.secretMasked));
    foot.appendChild(meta);

    var actions = el('div', 'finding-actions');
    var copy = el('button', 'btn btn-primary btn-xs');
    copy.type = 'button';
    copy.setAttribute('data-copy-prompt', key);
    copy.appendChild(icon('M8 6V4.5h8.5V13H14M4 8h8.5v9H4z', 12));
    copy.appendChild(document.createTextNode('수정 프롬프트 복사'));
    actions.appendChild(copy);

    if ((f.refs || []).length) {
      var link = document.createElement('a');
      link.className = 'btn btn-ghost btn-xs';
      link.href = f.refs[0];
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = '근거 문서';
      actions.appendChild(link);
    }
    foot.appendChild(actions);
    body.appendChild(foot);
    art.appendChild(body);

    head.addEventListener('click', function () {
      var now = art.classList.toggle('is-open');
      head.setAttribute('aria-expanded', now ? 'true' : 'false');
      if (now) S.open[key] = 1; else delete S.open[key];
    });

    return art;
  }

  function renderFindings() {
    renderFilters();
    var list = $('#findingsList');
    var empty = $('#findingsEmpty');
    list.textContent = '';
    var items = visibleFindings();
    $('#findingCount').textContent = String(S.result ? S.result.totals.findings : 0);

    if (!S.result) {
      empty.hidden = false;
      empty.textContent = '';
      var mark = el('div', 'empty-mark');
      mark.appendChild(icon('M20 6l12 4.4v8.9c0 7.5-4.9 13.3-12 15.8-7.1-2.5-12-8.3-12-15.8v-8.9z', 34));
      empty.appendChild(mark);
      empty.appendChild(el('strong', null, '아직 검사한 코드가 없습니다'));
      var p = el('p');
      p.appendChild(document.createTextNode('위에 코드를 붙여넣거나 '));
      var b = el('button', 'linklike', '취약 예시');
      b.type = 'button';
      b.setAttribute('data-action', 'open-presets');
      p.appendChild(b);
      p.appendChild(document.createTextNode('를 불러오세요.'));
      empty.appendChild(p);
      return;
    }

    if (!items.length) {
      empty.hidden = false;
      empty.textContent = '';
      empty.appendChild(el('div', 'empty-mark')).appendChild(icon('M4 10.6l3.6 3.6L16 5.6', 30));
      empty.appendChild(el('strong', null, S.filter === 'all' ? '규칙에 걸린 항목이 없습니다' : '이 심각도에 해당하는 항목이 없습니다'));
      empty.appendChild(el('p', null, S.filter === 'all' ? '스캔 범위 밖 취약점은 별도 점검이 필요합니다.' : '전체 보기로 다른 항목을 확인하세요.'));
      return;
    }
    empty.hidden = true;

    var lastPath = null;
    items.forEach(function (f) {
      if (S.groupByFile && f.path !== lastPath) {
        list.appendChild(el('div', 'group-head', f.path || '(파일 없음)'));
        lastPath = f.path;
      }
      list.appendChild(findingNode(f));
    });
  }

  function renderAll() {
    renderScore();
    renderHeadStats();
    renderStack();
    renderFindings();
    renderReport();
    renderAiSummary();
  }

  /* ── 소스 UI ────────────────────────────────────────────────────────── */

  function setMode(mode) {
    S.mode = mode;
    $$('#modeSeg .seg-btn').forEach(function (b) {
      var on = b.getAttribute('data-mode') === mode;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    [['code', '#mode-code'], ['files', '#mode-files'], ['github', '#mode-github'], ['url', '#mode-url']].forEach(function (pair) {
      var panel = $(pair[1]);
      var on = pair[0] === mode;
      panel.hidden = !on;
      panel.classList.toggle('is-on', on);
    });
    $('#autoNote').textContent = mode === 'code' ? '입력하면 자동 검사'
      : mode === 'files' ? '파일을 넣으면 자동 검사'
        : mode === 'github' ? 'GitHub API 조회' : '같은 오리진만 헤더 확인';
    renderFileChips();
    rescan();
  }

  function renderFileChips() {
    var wrap = $('#fileChips');
    wrap.textContent = '';
    var files = currentFiles();
    // 파일 모드는 왼쪽 목록에서 이미 보이므로 중복 칩을 띄우지 않는다.
    if (S.mode === 'code' || S.mode === 'files' || !files.length) { wrap.hidden = true; return; }
    wrap.hidden = false;
    files.slice(0, 24).forEach(function (f) {
      var chip = el('span', 'file-chip');
      chip.appendChild(document.createTextNode(f.path));
      var lines = (f.content.match(/\n/g) || []).length + 1;
      chip.appendChild(el('span', 'fc-line', lines + '줄'));
      if (S.mode !== 'github') {
        var x = el('button', null, '×');
        x.type = 'button';
        x.setAttribute('aria-label', f.path + ' 제거');
        x.addEventListener('click', function () {
          S.uploaded = S.uploaded.filter(function (u) { return u.path !== f.path; });
          renderFileList();
          renderFileChips();
          rescan();
        });
        chip.appendChild(x);
      }
      wrap.appendChild(chip);
    });
    if (files.length > 24) wrap.appendChild(el('span', 'fc-line', '+' + (files.length - 24) + '개'));
  }

  function renderFileList() {
    var box = $('#fileList');
    box.textContent = '';
    S.uploaded.forEach(function (f) {
      var row = el('div', 'file-row');
      row.appendChild(el('span', 'fpath', f.path));
      row.appendChild(el('span', 'fsize', Math.max(1, Math.round(f.content.length / 1024)) + 'KB'));
      var x = el('button', null, '×');
      x.type = 'button';
      x.setAttribute('aria-label', f.path + ' 제거');
      x.addEventListener('click', function () {
        S.uploaded = S.uploaded.filter(function (u) { return u.path !== f.path; });
        renderFileList(); renderFileChips(); rescan();
      });
      row.appendChild(x);
      box.appendChild(row);
    });
    $('#fileNote').textContent = S.uploaded.length
      ? S.uploaded.length + '개 파일 · 브라우저 안에서만 읽었습니다.'
      : '파일은 브라우저 안에서만 읽습니다. 업로드된 파일은 어디로도 전송되지 않습니다.';
  }

  function addFiles(fileList) {
    var list = Array.prototype.slice.call(fileList || []);
    var remaining = 40 - S.uploaded.length;
    if (remaining <= 0) { toast('파일은 최대 40개까지'); return; }
    var pending = list.slice(0, remaining);
    var loaded = 0;
    pending.forEach(function (file) {
      if (file.size > 900000) { toast(file.name + ' — 900KB 초과로 건너뜀'); done(); return; }
      if (/\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp[34]|zip|pdf)$/i.test(file.name)) { done(); return; }
      var fr = new FileReader();
      fr.onload = function () {
        var path = file.webkitRelativePath || file.name;
        S.uploaded = S.uploaded.filter(function (u) { return u.path !== path; });
        S.uploaded.push({ path: path, content: String(fr.result) });
        done();
      };
      fr.onerror = done;
      fr.readAsText(file);
    });
    function done() {
      loaded++;
      if (loaded >= pending.length) {
        renderFileList(); renderFileChips(); rescan();
      }
    }
  }

  /* ── 프리셋 ─────────────────────────────────────────────────────────── */

  function renderPresets() {
    var box = $('#presetList');
    box.textContent = '';
    PRESETS.forEach(function (p) {
      var b = el('button', 'preset-item');
      b.type = 'button';
      b.setAttribute('data-preset', p.id);
      b.appendChild(el('strong', null, p.label));
      b.appendChild(el('span', null, p.desc));
      b.appendChild(el('span', 'p-tag' + (p.tone === 'ok' ? ' ok' : ''), p.short));
      box.appendChild(b);
    });
  }

  function loadPreset(id) {
    var p = PRESETS.filter(function (x) { return x.id === id; })[0];
    if (!p) return;
    S.uploaded = p.files.map(function (f) { return { path: f.path, content: f.content }; });
    S.pkgTouched = false;
    renderFileList();
    setMode('files');
    closePresets();
    $('#fileInput').value = '';
    toast('예시 "' + p.label + '" 불러옴');
  }

  function openPresets() {
    $('#presetMenu').hidden = false;
    var btn = $('[data-action="toggle-presets"]');
    btn.setAttribute('aria-expanded', 'true');
  }
  function closePresets() {
    $('#presetMenu').hidden = true;
    var btn = $('[data-action="toggle-presets"]');
    btn.setAttribute('aria-expanded', 'false');
  }

  /* ── GitHub / URL ───────────────────────────────────────────────────── */

  function ghToken() {
    try { return sessionStorage.getItem('shield.ghtoken') || ''; } catch (e) { return ''; }
  }

  async function scanGithub() {
    var url = $('#ghUrl').value.trim();
    if (!url) { setStatus('#ghStatus', '저장소 주소를 입력하세요.', 'error'); return; }
    var btn = $('#btnGhScan');
    btn.disabled = true;
    setStatus('#ghStatus', 'GitHub에서 파일 목록을 가져오는 중…', 'busy');
    try {
      var res = await window.REMOTE.scanRepo(url, {
        token: ghToken(),
        maxFiles: 45,
        onProgress: function (done, total) { setStatus('#ghStatus', '파일 읽는 중 ' + done + '/' + total, 'busy'); }
      });
      if (!res.ok) {
        setStatus('#ghStatus', res.message || '저장소를 읽지 못했습니다.', 'error');
        return;
      }
      S.repo = {
        files: res.files, findings: res.treeFindings || [], label: res.repo,
        branch: res.branch, failed: (res.failed || []).length
      };
      setMode('github');
      var msg = res.files.length + '개 파일 · ' + res.branch + ' 브랜치' +
        (res.picked < res.totalCandidates ? ' (후보 ' + res.totalCandidates + '개 중 우선 ' + res.picked + '개)' : '') +
        ((res.failed || []).length ? ' · 실패 ' + res.failed.length : '');
      setStatus('#ghStatus', msg + ' — 결과는 스캔 탭에 반영됐습니다.', 'ok');
    } catch (e) {
      setStatus('#ghStatus', 'GitHub 조회 중 오류: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
    }
  }

  function setStatus(sel, msg, kind) {
    var n = $(sel);
    if (!n) return;
    n.textContent = msg;
    n.className = (n.id === 'ghStatus' || n.id === 'urlStatus') ? 'micro' : 'status-line';
    if (n.id === 'ghStatus' || n.id === 'urlStatus') n.classList.add('status-line');
    n.classList.remove('is-busy', 'is-error', 'is-ok');
    if (kind) n.classList.add('is-' + kind);
  }

  async function scanUrl() {
    var url = $('#urlInput').value.trim();
    if (!url) { setStatus('#urlStatus', '배포 주소를 입력하세요.', 'error'); return; }
    var btn = $('#btnUrlScan');
    btn.disabled = true;
    setStatus('#urlStatus', '헤더와 노출 파일을 확인하는 중…', 'busy');
    try {
      var res = await window.REMOTE.probeUrl(url, { sameOriginBase: location.origin });
      if (!res.ok) { setStatus('#urlStatus', res.message, 'error'); return; }
      S.urlProbe = res;
      S.urlFindings = res.findings.slice();
      setMode('url');
      renderUrlResult(res);
      var head = res.headerStatus === 'checked'
        ? '헤더를 실제로 읽었습니다 (점수 ' + res.headerScore + '/100).'
        : (res.headerStatus === 'limited' || res.headerStatus === 'cors-blocked'
          ? '헤더는 CORS로 읽지 못해 미확인입니다. 터미널 명령을 쓰세요.'
          : '응답을 읽지 못했습니다.');
      setStatus('#urlStatus', head + ' 결과는 스캔 탭에 반영됐습니다.', res.headerStatus === 'checked' ? 'ok' : 'busy');
      if (res.headers['content-security-policy']) { /* noop */ }
    } catch (e) {
      setStatus('#urlStatus', '실측 중 오류: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
    }
  }

  function renderUrlResult(res) {
    var box = $('#urlResult');
    box.textContent = '';
    box.hidden = false;

    var line = el('div', 'micro');
    line.appendChild(el('b', null, 'HTTP ' + (res.httpStatus || '—')));
    line.appendChild(document.createTextNode(' · ' + (res.headerStatus === 'checked' ? '헤더 확인됨'
      : res.headerStatus === 'limited' ? '헤더 제한적(CORS)' : res.headerStatus === 'cors-blocked' ? '헤더 미확인(CORS)' : '접속 실패')));
    if (res.headerStatus === 'checked' && res.headerScore != null) {
      line.appendChild(document.createTextNode(' · 헤더 점수 ' + res.headerScore + '/100'));
    }
    box.appendChild(line);

    var grid = el('div', 'hdr-grid');
    window.REMOTE.SECURITY_HEADERS.forEach(function (h) {
      var v = res.headers[h.key];
      var state = res.headerStatus === 'checked' ? (v ? 'ok' : 'miss') : 'unk';
      var item = el('div', 'hdr-item ' + state);
      item.appendChild(el('span', 'hname', h.label));
      item.appendChild(el('span', 'hstate', state === 'ok' ? '있음' : state === 'miss' ? '없음' : '미확인'));
      if (v) item.title = v.slice(0, 300);
      grid.appendChild(item);
    });
    box.appendChild(grid);

    var probes = el('div', 'probe-list');
    (res.probes || []).forEach(function (p) {
      var row = el('div', 'probe-row');
      row.appendChild(el('span', null, '/' + p.path));
      var st = el('span', 'pstat ' + p.status,
        p.status === 'exposed' ? '노출' : p.status === 'blocked' ? '차단' : p.status === 'unconfirmed' ? '확인 불가' : '미확인');
      row.appendChild(st);
      if (p.httpStatus) row.appendChild(el('span', null, String(p.httpStatus)));
      probes.appendChild(row);
    });
    box.appendChild(probes);
    if (res.note) box.appendChild(el('p', 'micro', res.note));
  }

  /* ── 방어팩 ─────────────────────────────────────────────────────────── */

  function cspOptions() {
    return { services: C_SERVICES(), inlineStyle: S.inlineStyle, upgrade: S.upgrade };
  }
  function C_SERVICES() { return S.csp.slice(); }

  function renderDefense() {
    var hostBox = $('#hostingTabs');
    hostBox.textContent = '';
    HOSTINGS.forEach(function (h) {
      var b = el('button', 'seg-btn' + (h.id === S.hosting ? ' is-on' : ''), h.label);
      b.type = 'button';
      b.setAttribute('data-hosting', h.id);
      b.setAttribute('aria-pressed', h.id === S.hosting ? 'true' : 'false');
      hostBox.appendChild(b);
    });

    var svcBox = $('#cspServices');
    svcBox.textContent = '';
    window.DEFENSE.SERVICES.forEach(function (s) {
      var lab = el('label', 'svc');
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = s.id;
      cb.checked = S.csp.indexOf(s.id) >= 0;
      lab.appendChild(cb);
      lab.appendChild(el('span', null, s.label));
      if (s.note) lab.appendChild(el('em', null, s.note));
      svcBox.appendChild(lab);
    });

    $('#optInlineStyle').checked = S.inlineStyle;
    $('#optUpgrade').checked = S.upgrade;

    var host = HOSTINGS.filter(function (h) { return h.id === S.hosting; })[0] || HOSTINGS[0];
    $('#hostingNote').textContent = host.note;
    $('#headerPath').textContent = host.path;
    $('#headerCode').textContent = window.DEFENSE.headersFile(S.hosting, cspOptions());
    $('#cspPreview').textContent = window.DEFENSE.csp(cspOptions());
    $('#terminalCommands').textContent = window.DEFENSE.terminalCommands(urlTarget());
    renderKit();
  }

  function urlTarget() {
    var v = ''; try { v = $('#urlInput').value.trim(); } catch (e) { v = ''; }
    if (!v && S.urlProbe) v = S.urlProbe.target;
    return v || 'https://example.com';
  }

  function renderKit() {
    var files = window.DEFENSE.kit(Object.assign({ hosting: S.hosting }, cspOptions()));
    var grid = $('#kitGrid');
    grid.textContent = '';
    $('#kitCount').textContent = files.length + '개 파일';
    files.forEach(function (f) {
      var card = el('div', 'kit-card');
      card.appendChild(el('strong', null, f.label));
      card.appendChild(el('code', null, f.path));
      card.appendChild(el('p', null, f.note || ''));
      var actions = el('div', 'kit-actions');
      var cp = el('button', 'btn btn-ghost btn-xs', '복사');
      cp.type = 'button';
      cp.setAttribute('data-kit-copy', f.id);
      var dl = el('button', 'btn btn-ghost btn-xs', '저장');
      dl.type = 'button';
      dl.setAttribute('data-kit-download', f.id);
      actions.appendChild(cp);
      actions.appendChild(dl);
      card.appendChild(actions);
      card.setAttribute('data-kit-id', f.id);
      grid.appendChild(card);
    });
    S._kit = files;
  }

  function kitFile(id) {
    return (S._kit || []).filter(function (f) { return f.id === id; })[0];
  }

  function downloadKitZip() {
    var files = window.DEFENSE.kit(Object.assign({ hosting: S.hosting }, cspOptions()));
    var bytes = window.DEFENSE.zip(files);
    download('onetap-webapp-shield-kit.zip', bytes, 'application/zip');
    toast('가드레일 키트 ZIP을 내려받았습니다');
  }

  /* ── 의존성 CVE ─────────────────────────────────────────────────────── */

  async function runOsv() {
    if (S.osvBusy) return;
    var text = $('#pkgText').value;
    if (!text.trim()) { setStatus('#osvStatus', 'package.json을 먼저 넣어주세요.', 'error'); return; }
    var parsed = window.OSV.parsePackageJson(text);
    if (!parsed.ok) { setStatus('#osvStatus', parsed.error, 'error'); return; }
    if (!parsed.deps.length) { setStatus('#osvStatus', '의존성을 찾지 못했습니다(dependencies/devDependencies).', 'error'); return; }

    S.osvBusy = true;
    $('#btnOsv').disabled = true;
    setStatus('#osvStatus', 'OSV.dev 조회 중… ' + parsed.deps.length + '개 패키지', 'busy');
    try {
      var res = await window.OSV.lookup(parsed.deps);
      S.osv = res;
      renderOsv(res, parsed);
      var label = res.status === 'live' || res.status === 'clean' ? 'OSV.dev 실시간 응답' : res.status === 'fallback' ? '내장 참고 DB(오프라인)' : '결과 없음';
      setStatus('#osvStatus', label + ' · 취약점 ' + (res.totalVulns || 0) + '건', res.status === 'fallback' ? 'busy' : 'ok');
    } catch (e) {
      setStatus('#osvStatus', '조회 실패: ' + e.message, 'error');
    } finally {
      S.osvBusy = false;
      $('#btnOsv').disabled = false;
    }
  }

  function renderOsv(res, parsed) {
    var list = $('#osvList');
    var empty = $('#osvEmpty');
    var summary = $('#osvSummary');
    list.textContent = '';
    summary.textContent = '';

    $('#osvSource').textContent = res.status === 'fallback' ? '내장 참고 DB (실시간 아님)' : 'OSV.dev';
    empty.hidden = true;

    if (res.status === 'fallback') {
      var banner = el('div', 'osv-banner', res.message || '네트워크가 없어 내장 참고 DB로 점검했습니다.');
      list.appendChild(banner);
    } else if (res.status === 'clean' || res.status === 'live') {
      list.appendChild(el('div', 'osv-banner live', res.status === 'clean' ? 'OSV.dev 기준 알려진 취약점이 없습니다.' : 'OSV.dev 실시간 조회 결과입니다.'));
    }

    var counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    var rows = [];
    (res.deps || []).forEach(function (d) {
      (d.vulns || []).forEach(function (v) {
        var sev = v.severity || 'unknown';
        counts[sev] = (counts[sev] || 0) + 1;
        rows.push({ dep: d, v: v });
      });
    });
    rows.sort(function (a, b) {
      var r = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      return (r[a.v.severity] - r[b.v.severity]) || a.dep.name.localeCompare(b.dep.name);
    });

    var stats = [
      ['total', res.totalVulns || 0, '취약점'],
      ['critical', counts.critical, '치명적'],
      ['high', counts.high, '높음'],
      ['medium', counts.medium, '보통'],
      ['low', counts.low, '낮음']
    ];
    stats.forEach(function (s) {
      var box = el('div', 'cve-stat ' + s[0]);
      box.appendChild(el('b', null, String(s[1])));
      box.appendChild(el('span', null, s[2]));
      summary.appendChild(box);
    });

    if (!rows.length) {
      empty.hidden = false;
      empty.textContent = '';
      empty.appendChild(el('strong', null, '알려진 취약점이 없습니다'));
      empty.appendChild(el('p', null, (res.status === 'fallback' ? '내장 DB 기준입니다. 네트워크가 되면 실제 조회로 다시 확인하세요.' : 'OSV.dev 기준 · ' + parsed.deps.length + '개 패키지')));
      return;
    }

    rows.slice(0, 80).forEach(function (row) {
      var v = row.v;
      var item = el('article', 'cve-item');
      item.setAttribute('data-sev', v.severity || 'unknown');
      var top = el('div', 'cve-top');
      top.appendChild(el('strong', null, v.cve || v.id));
      if (v.cve && v.id && v.cve !== v.id) top.appendChild(el('span', 'cve-meta', v.id));
      top.appendChild(el('span', 'cve-sev', SEV_KO[v.severity] || '미상'));
      top.appendChild(el('span', 'cve-pkg', row.dep.name + '@' + row.dep.version));
      item.appendChild(top);
      item.appendChild(el('p', 'cve-sum', v.summary || ''));
      var meta = el('div', 'cve-meta');
      if (v.fixed) meta.appendChild(el('span', null, '수정 버전 ' + v.fixed));
      else meta.appendChild(el('span', null, '수정 버전 미확인'));
      if (v.link) {
        var a = document.createElement('a');
        a.href = v.link; a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.textContent = '상세';
        meta.appendChild(a);
      }
      item.appendChild(meta);
      list.appendChild(item);
    });
    if (rows.length > 80) list.appendChild(el('p', 'micro', '외 ' + (rows.length - 80) + '건은 JSON/리포트에서 확인하세요.'));
  }

  /* ── AI 리뷰 ────────────────────────────────────────────────────────── */

  function aiPayloadPrompt() {
    var r = S.result;
    var limit = 2000;
    var head = [
      '너는 웹앱 보안 리뷰어다. 아래 정적 스캔 결과를 보고, 가장 위험한 것부터 고치는 순서와 구체적 방법을 한국어로 짧게 답해라.',
      '형식: 1) 우선순위 3개(각 2줄) 2) 바로 적용할 코드/설정 3) 배포 전 확인.',
      '모르는 것은 추측하지 말고 "확인 필요"라고 써라.'
    ].join('\n');

    var findings = (r ? r.findings : []).slice(0, 10).map(function (f, i) {
      return (i + 1) + '. [' + SEV_KO[f.sev] + '] ' + f.name + ' @ ' + f.path + ':' + f.line + (f.note ? ' — ' + f.note : '');
    }).join('\n');

    var stack = r ? r.stack.map(function (s) { return s.label; }).join(', ') : '';
    var code = '';
    if ($('#optAiCode').checked && r && r.files.length) {
      var primary = currentFiles()[0];
      if (primary) {
        // 전송 전에 키·토큰을 [REDACTED]로 가린다.
        var safe = window.SHIELD.redact(primary.content);
        code = '코드 일부(' + primary.path + ', 시크릿 마스킹됨):\n' + safe.slice(0, 1400);
      }
    }

    var budget = limit - head.length - (findings ? findings.length + 40 : 0) - (stack.length + 20);
    if (code.length > budget) code = code.slice(0, Math.max(300, budget)) + '\n…(생략)';

    var prompt = head + '\n\n[발견]\n' + (findings || '없음') + '\n\n[스택] ' + (stack || '미상') + (code ? '\n\n' + code : '');
    return prompt.slice(0, limit);
  }

  function renderAiSummary() {
    var box = $('#aiSummary');
    box.textContent = '';
    var r = S.result;
    if (!r) {
      box.appendChild(el('p', 'ai-ctx-empty', '먼저 스캔하세요. 발견 항목과 스택을 요약해 AI에 보냅니다.'));
      return;
    }
    var rows = [
      ['발견', r.totals.findings + '건'],
      ['치명적·높음', (r.counts.critical + r.counts.high) + '건'],
      ['파일', r.totals.files + '개'],
      ['스택', r.stack.map(function (s) { return s.label; }).join(', ') || '미상']
    ];
    rows.forEach(function (p) {
      var row = el('div', 'ai-ctx-row');
      row.appendChild(el('span', null, p[0]));
      row.appendChild(el('b', null, p[1]));
      box.appendChild(row);
    });
    var top = r.findings.slice(0, 3).map(function (f) { return f.name; });
    if (top.length) box.appendChild(el('p', 'ai-ctx-row muted', top.join(' · ')));
  }

  function updateAiButton() {
    var consent = $('#optAiConsent').checked;
    var has = !!(S.result && S.result.findings.length);
    var btn = $('#btnAiReview');
    btn.disabled = !consent || !has || S.ai.busy;
    btn.textContent = S.ai.busy ? '리뷰 생성 중…' : (S.byok.key ? '내 AI로 심층 리뷰' : '무료 AI로 심층 리뷰');
  }

  function aiMarkdown(text) { return window.SHIELD.renderMarkdown(text); }

  function setAiOutput(html, provider) {
    var out = $('#aiOutput');
    out.textContent = '';
    var div = el('div', 'ai-md');
    div.innerHTML = html;
    out.appendChild(div);
    var pill = $('#aiProviderPill');
    if (provider) { pill.hidden = false; pill.textContent = provider; }
    else pill.hidden = true;
  }

  async function runAi() {
    if (S.ai.busy) return;
    if (!$('#optAiConsent').checked) { toast('코드 전송 동의가 필요합니다'); return; }
    if (!S.result || !S.result.findings.length) { toast('먼저 스캔하세요'); return; }
    S.ai.busy = true;
    updateAiButton();
    var out = $('#aiOutput');
    out.textContent = '';
    out.appendChild(el('p', 'ai-msg', '리뷰를 생성하는 중입니다… (최대 30초)'));

    var prompt = aiPayloadPrompt();
    var system = '너는 실무 웹앱 보안 리뷰어다. 짧고 구체적으로, 실행 가능한 수정만 말한다. 확실하지 않은 것은 확인 필요라고 표시한다.';

    var result;
    if (S.byok.key) {
      result = await callByok(prompt, system);
    } else {
      try {
        if (FREE && FREE.configure) FREE.configure({ app: 'webapp-shield' });
        result = await FREE.generate({ task: 'text', prompt: prompt, system: system });
      } catch (e) {
        result = { ok: false, message: '무료 AI 호출 중 오류: ' + e.message };
      }
    }

    S.ai.busy = false;
    updateAiButton();

    if (result && result.ok) {
      var provider = (result.provider || (S.byok.key ? S.byok.provider : 'free-ai'));
      S.ai.text = result.text;
      setAiOutput(aiMarkdown(result.text), provider + (result.remaining != null ? ' · 남은 ' + result.remaining + '회' : ''));
      return;
    }

    var msg = (result && result.message) || 'AI 응답을 받지 못했습니다.';
    var box = el('div', 'ai-msg error');
    box.appendChild(el('p', null, msg));
    if (result && result.reason === 'origin_not_allowed') {
      box.appendChild(el('p', 'micro', '무료 체험은 배포 도메인(허용된 출처)에서만 열립니다. 지금 주소에서는 내 AI 키를 연결해 사용하세요.'));
    }
    if (result && (result.reason === 'free_quota_exceeded' || result.reason === 'global_daily_cap' || result.reason === 'shared_network_limit')) {
      box.appendChild(el('p', 'micro', '무료 체험 한도입니다. 내 Gemini 키를 연결하면 계속할 수 있습니다.'));
      var a = document.createElement('a');
      a.className = 'btn btn-ghost btn-sm cta';
      a.href = 'https://aistudio.google.com/apikey';
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.textContent = '무료 Gemini 키 발급';
      box.appendChild(a);
    }
    out.textContent = '';
    out.appendChild(box);
    var pill = $('#aiProviderPill');
    pill.hidden = true;
  }

  async function callByok(prompt, system) {
    var key = S.byok.key;
    var model = S.byok.model || 'gemini-2.5-flash';
    try {
      if (S.byok.provider === 'gemini') {
        var res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent?key=' + encodeURIComponent(key), {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: system }] },
            contents: [{ role: 'user', parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.3, maxOutputTokens: 900 }
          })
        });
        var j = await res.json();
        if (!res.ok) return { ok: false, message: 'Gemini 오류: ' + ((j.error && j.error.message) || res.status) };
        var t = (((j.candidates || [])[0] || {}).content || {}).parts || [];
        return { ok: true, text: t.map(function (p) { return p.text || ''; }).join(''), provider: 'gemini' };
      }
      if (S.byok.provider === 'openai') {
        var r2 = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key },
          body: JSON.stringify({ model: model || 'gpt-4o-mini', messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }], max_tokens: 900 })
        });
        var j2 = await r2.json();
        if (!r2.ok) return { ok: false, message: 'OpenAI 오류: ' + ((j2.error && j2.error.message) || r2.status) };
        return { ok: true, text: (((j2.choices || [])[0] || {}).message || {}).content || '', provider: 'openai' };
      }
      var r3 = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': key,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({ model: model || 'claude-3-5-haiku-latest', max_tokens: 900, system: system, messages: [{ role: 'user', content: prompt }] })
      });
      var j3 = await r3.json();
      if (!r3.ok) return { ok: false, message: 'Claude 오류: ' + ((j3.error && j3.error.message) || r3.status) };
      return { ok: true, text: ((j3.content || [])[0] || {}).text || '', provider: 'claude' };
    } catch (e) {
      return { ok: false, message: 'AI 연결 실패: ' + e.message + ' (브라우저 CORS·키 권한을 확인하세요)' };
    }
  }

  function renderByok() {
    $$('#byokProvider .seg-btn').forEach(function (b) {
      var on = b.getAttribute('data-provider') === S.byok.provider;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    $('#byokKey').value = S.byok.key || '';
    $('#byokModel').value = S.byok.model || '';
    $('#byokStatus').textContent = S.byok.key
      ? '연결됨 · ' + S.byok.provider + ' / ' + S.byok.model + ' · 키는 이 브라우저(localStorage)에만 있습니다.'
      : '연결하지 않아도 무료 체험으로 리뷰할 수 있습니다.';
  }

  function saveByok() {
    var key = $('#byokKey').value.trim();
    var model = $('#byokModel').value.trim();
    if (!key) { toast('API 키를 입력하세요'); return; }
    S.byok = { provider: S.byok.provider, key: key, model: model };
    try { localStorage.setItem(BYOK, JSON.stringify(S.byok)); } catch (e) { /* noop */ }
    renderByok();
    updateAiButton();
    toast('이 브라우저에만 저장했습니다');
  }

  function clearByok() {
    S.byok.key = '';
    try { localStorage.removeItem(BYOK); } catch (e) { /* noop */ }
    renderByok();
    updateAiButton();
    toast('연결을 해제했습니다');
  }

  /* ── 리포트 ─────────────────────────────────────────────────────────── */

  function reportMeta() {
    return {
      title: S.mode === 'github' ? (S.repo.label || '') : (S.mode === 'code' ? S.code.path : (S.mode === 'url' ? urlTarget() : '업로드 파일')),
      source: sourceLabel(),
      date: window.SHIELD.stamp(),
      extras: reportExtras()
    };
  }

  function reportExtras() {
    var extras = [];
    if (S.mode === 'url' && S.urlProbe) {
      if (S.urlProbe.headerStatus !== 'checked') extras.push('서버 보안 헤더: 브라우저 CORS로 미확인 (터미널 curl로 확인 필요)');
      else extras.push('서버 보안 헤더 점수: ' + S.urlProbe.headerScore + '/100');
      var exposed = (S.urlProbe.probes || []).filter(function (p) { return p.status === 'exposed'; });
      if (exposed.length) extras.push('공개된 파일: ' + exposed.map(function (p) { return p.path; }).join(', '));
    }
    if (S.mode === 'github') extras.push('GitHub 저장소: ' + S.repo.label + ' (' + S.repo.branch + ') · 읽은 파일 ' + S.repo.files.length + '개');
    if (S.osv && S.osv.totalVulns) extras.push('OSV.dev 취약점 ' + S.osv.totalVulns + '건 (' + (S.osv.status === 'fallback' ? '내장 DB' : '실시간') + ')');
    return extras;
  }

  function renderReport() {
    var preview = $('#reportPreview');
    var badge = $('#badgePreview');
    var facts = $('#reportFacts');
    facts.textContent = '';

    if (!S.result) {
      preview.textContent = '아직 스캔 결과가 없습니다. 스캔 탭에서 코드를 검사하세요.';
      badge.textContent = '—';
      return;
    }
    var md = window.SHIELD.reportMarkdown(S.result, reportMeta());
    preview.textContent = md;

    var pts = S.result.score.points;
    var svg = window.SHIELD.badgeSvg(pts == null ? 0 : pts, S.result.score.grade, S.result.score.label);
    badge.innerHTML = svg;

    var rows = [
      ['점수', (pts == null ? '미확인' : pts + ' / 100')],
      ['등급', S.result.score.grade],
      ['발견', S.result.totals.findings + '건'],
      ['파일', S.result.totals.files + '개'],
      ['스택', S.result.stack.map(function (s) { return s.label; }).join(', ') || '미상'],
      ['대상', sourceLabel() || '—']
    ];
    rows.forEach(function (r) {
      var row = el('div', 'fact-row');
      row.appendChild(el('span', null, r[0]));
      row.appendChild(el('b', null, r[1]));
      facts.appendChild(row);
    });
  }

  function downloadReport(ext) {
    if (!S.result) { toast('먼저 스캔하세요'); return; }
    var meta = reportMeta();
    if (ext === 'json') {
      download(stampName('webapp-shield-report', 'json'), window.SHIELD.reportJson(S.result, meta), 'application/json');
    } else {
      download(stampName('webapp-shield-report', 'md'), window.SHIELD.reportMarkdown(S.result, meta), 'text/markdown;charset=utf-8');
    }
    toast('리포트를 내려받았습니다');
  }

  /* ── 탭 ─────────────────────────────────────────────────────────────── */

  function setTab(name) {
    if (['scan', 'defense', 'deps', 'ai', 'report'].indexOf(name) < 0) name = 'scan';
    S.tab = name;
    $$('.tab').forEach(function (t) {
      var on = t.getAttribute('data-tab') === name;
      t.classList.toggle('is-active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $$('.view').forEach(function (v) {
      var on = v.id === 'view-' + name;
      v.hidden = !on;
      v.classList.toggle('is-active', on);
    });
    try {
      if (history.replaceState) history.replaceState(null, '', '#' + name);
    } catch (e) { /* noop */ }
    if (name === 'defense') renderDefense();
    if (name === 'report') renderReport();
    if (name === 'ai') { renderAiSummary(); updateAiButton(); }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* ── 이벤트 ─────────────────────────────────────────────────────────── */

  function bind() {
    // 탭
    $$('.tab').forEach(function (t) {
      t.addEventListener('click', function () { setTab(t.getAttribute('data-tab')); });
    });

    // 헤더/전역 액션
    document.addEventListener('click', function (e) {
      var target = e.target.closest('[data-action]');
      if (!target) return;
      var action = target.getAttribute('data-action');
      if (action === 'toggle-theme') {
        var cur = document.documentElement.getAttribute('data-theme');
        var next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        document.querySelector('meta[name="theme-color"]').setAttribute('content', next === 'dark' ? '#07090C' : '#F5F7F9');
        saveSettings();
      } else if (action === 'open-help') {
        var d = $('#helpDialog');
        if (d.showModal) d.showModal(); else d.setAttribute('open', '');
      } else if (action === 'close-help') {
        $('#helpDialog').close();
      } else if (action === 'go-scan') {
        e.preventDefault();
        setTab('scan');
      } else if (action === 'toggle-presets') {
        if ($('#presetMenu').hidden) openPresets(); else closePresets();
      } else if (action === 'open-presets') {
        openPresets();
      } else if (action === 'clear-code') {
        $('#codeText').value = '';
        S.code.text = '';
        updateCodeMeta();
        rescan();
      } else if (action === 'sample-code') {
        var safe = PRESETS.filter(function (p) { return p.id === 'safe-baseline'; })[0];
        if (!safe) return;
        var api = safe.files.filter(function (f) { return /api\//.test(f.path); })[0] || safe.files[0];
        S.code.path = api.path; $('#codePath').value = api.path;
        S.code.text = api.content; $('#codeText').value = api.content;
        updateCodeMeta(); rescan();
      } else if (action === 'copy-headers') {
        copyText($('#headerCode').textContent, '헤더 파일을 복사했습니다');
      } else if (action === 'download-headers') {
        var host = HOSTINGS.filter(function (h) { return h.id === S.hosting; })[0];
        download(host.path.split('/').pop(), $('#headerCode').textContent);
        toast('헤더 파일을 저장했습니다');
      } else if (action === 'copy-csp') {
        copyText($('#cspPreview').textContent, 'CSP를 복사했습니다');
      } else if (action === 'copy-terminal') {
        copyText($('#terminalCommands').textContent, '터미널 명령을 복사했습니다');
      } else if (action === 'download-zip') {
        downloadKitZip();
      } else if (action === 'load-pkg-sample') {
        $('#pkgText').value = window.SAMPLES.PACKAGE_JSON;
        S.pkgTouched = true;
      } else if (action === 'clear-pkg') {
        $('#pkgText').value = '';
        S.pkgTouched = true;
      } else if (action === 'copy-report') {
        if (!S.result) { toast('먼저 스캔하세요'); return; }
        copyText(window.SHIELD.reportMarkdown(S.result, reportMeta()), '리포트 Markdown을 복사했습니다');
      } else if (action === 'download-md') {
        downloadReport('md');
      } else if (action === 'download-json') {
        downloadReport('json');
      } else if (action === 'print') {
        window.print();
      } else if (action === 'copy-badge') {
        if (!S.result) { toast('먼저 스캔하세요'); return; }
        var file = 'shield-badge.svg';
        copyText('<img src="' + file + '" alt="WebApp Shield ' + (S.result.score.points == null ? '' : S.result.score.points + '/100') + ' ' + S.result.score.grade + '" height="44" />', '배지 HTML을 복사했습니다 (SVG 저장 후 같은 폴더에 두세요)');
      } else if (action === 'download-badge') {
        if (!S.result) { toast('먼저 스캔하세요'); return; }
        download('shield-badge.svg', window.SHIELD.badgeSvg(S.result.score.points == null ? 0 : S.result.score.points, S.result.score.grade, S.result.score.label), 'image/svg+xml');
        toast('배지 SVG를 저장했습니다');
      } else if (action === 'copy-ai') {
        if (!S.ai.text) { toast('복사할 리뷰가 없습니다'); return; }
        copyText(S.ai.text, 'AI 리뷰를 복사했습니다');
      }
    });

    // ESC: 프리셋 닫기
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closePresets();
    });
    document.addEventListener('click', function (e) {
      if (!e.target.closest('.preset-wrap') && !e.target.closest('[data-action="open-presets"]')) closePresets();
    });

    // 소스 모드
    $('#modeSeg').addEventListener('click', function (e) {
      var b = e.target.closest('[data-mode]');
      if (b) setMode(b.getAttribute('data-mode'));
    });

    // 코드
    var ta = $('#codeText');
    ta.addEventListener('input', function () {
      S.code.text = ta.value;
      updateCodeMeta();
      scheduleScan();
    });
    $('#codePath').addEventListener('input', function () {
      S.code.path = $('#codePath').value;
      scheduleScan();
    });

    // 프리셋
    renderPresets();
    $('#presetList').addEventListener('click', function (e) {
      var b = e.target.closest('[data-preset]');
      if (b) loadPreset(b.getAttribute('data-preset'));
    });

    // 파일 업로드
    var dz = $('#dropZone');
    var fi = $('#fileInput');
    dz.addEventListener('click', function () { fi.click(); });
    dz.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fi.click(); }
    });
    fi.addEventListener('change', function () { addFiles(fi.files); fi.value = ''; });
    ['dragenter', 'dragover'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('is-drag'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('is-drag'); });
    });
    dz.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
    });

    // GitHub
    $('#btnGhScan').addEventListener('click', scanGithub);
    $('#ghUrl').addEventListener('keydown', function (e) { if (e.key === 'Enter') scanGithub(); });
    $('#ghToken').addEventListener('input', function () {
      try { sessionStorage.setItem('shield.ghtoken', $('#ghToken').value.trim()); } catch (e) { /* noop */ }
    });

    // URL
    $('#btnUrlScan').addEventListener('click', scanUrl);
    $('#urlInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') scanUrl(); });
    $('#urlInput').addEventListener('input', function () {
      if (S.tab === 'defense') $('#terminalCommands').textContent = window.DEFENSE.terminalCommands(urlTarget());
    });

    // 필터
    $('#findingFilters').addEventListener('click', function (e) {
      var b = e.target.closest('[data-filter]');
      if (!b) return;
      S.filter = b.getAttribute('data-filter');
      renderFindings();
    });
    $('#optGroup').addEventListener('change', function () {
      S.groupByFile = this.checked;
      saveSettings();
      renderFindings();
    });

    // 발견 항목: 프롬프트 복사
    $('#findingsList').addEventListener('click', function (e) {
      var b = e.target.closest('[data-copy-prompt]');
      if (!b) return;
      var key = b.getAttribute('data-copy-prompt');
      var f = S.result && S.result.findings.filter(function (x) {
        return (x.ruleId + '|' + x.path + '|' + x.line + '|' + (x.secretMasked || '')) === key;
      })[0];
      if (!f) return;
      copyText(window.SHIELD.fixPrompt(f), '수정 프롬프트를 복사했습니다 — AI 코딩 도구에 붙여넣으세요');
    });

    // 방어팩
    $('#hostingTabs').addEventListener('click', function (e) {
      var b = e.target.closest('[data-hosting]');
      if (!b) return;
      S.hosting = b.getAttribute('data-hosting');
      saveSettings();
      renderDefense();
    });
    $('#cspServices').addEventListener('change', function (e) {
      var cb = e.target.closest('input[type="checkbox"]');
      if (!cb) return;
      var id = cb.value;
      if (cb.checked) { if (S.csp.indexOf(id) < 0) S.csp.push(id); }
      else S.csp = S.csp.filter(function (x) { return x !== id; });
      saveSettings();
      renderDefense();
    });
    $('#optInlineStyle').addEventListener('change', function () {
      S.inlineStyle = this.checked; saveSettings(); renderDefense();
    });
    $('#optUpgrade').addEventListener('change', function () {
      S.upgrade = this.checked; saveSettings(); renderDefense();
    });
    $('#kitGrid').addEventListener('click', function (e) {
      var cp = e.target.closest('[data-kit-copy]');
      if (cp) {
        var f = kitFile(cp.getAttribute('data-kit-copy'));
        if (f) copyText(f.content, f.label + ' 복사했습니다');
        return;
      }
      var dl = e.target.closest('[data-kit-download]');
      if (dl) {
        var f2 = kitFile(dl.getAttribute('data-kit-download'));
        if (f2) {
          download(f2.path.split('/').pop(), f2.content);
          toast(f2.label + ' 저장했습니다');
        }
      }
    });

    // 의존성
    $('#btnOsv').addEventListener('click', runOsv);
    $('#pkgText').addEventListener('input', function () { S.pkgTouched = true; });

    // AI
    $('#optAiConsent').addEventListener('change', updateAiButton);
    $('#optAiCode').addEventListener('change', updateAiButton);
    $('#btnAiReview').addEventListener('click', runAi);
    $('#byokProvider').addEventListener('click', function (e) {
      var b = e.target.closest('[data-provider]');
      if (!b) return;
      S.byok.provider = b.getAttribute('data-provider');
      var defaults = { gemini: 'gemini-2.5-flash', openai: 'gpt-4o-mini', anthropic: 'claude-3-5-haiku-latest' };
      if (!$('#byokModel').value.trim() || /^gemini|^gpt-|^claude-/.test($('#byokModel').value.trim())) {
        $('#byokModel').value = defaults[S.byok.provider];
      }
      S.byok.model = $('#byokModel').value.trim();
      renderByok();
    });
    $('#btnByokSave').addEventListener('click', saveByok);
    $('#btnByokClear').addEventListener('click', clearByok);

    // 다이얼로그 backdrop 클릭 닫기
    var dlg = $('#helpDialog');
    dlg.addEventListener('click', function (e) {
      var r = dlg.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) dlg.close();
    });

    // 해시 탭
    window.addEventListener('hashchange', function () {
      var h = (location.hash || '').replace('#', '');
      if (h && h !== S.tab) setTab(h);
    });
  }

  function updateCodeMeta() {
    var t = $('#codeText').value;
    var lines = t ? t.split('\n').length : 0;
    $('#codeMeta').textContent = t.length + '자 · ' + lines + '줄 · 이 브라우저에서만 분석';
  }

  /* ── 초기화 ─────────────────────────────────────────────────────────── */

  function init() {
    loadSettings();
    loadByok();
    if (window.FREE && window.FREE.configure) window.FREE.configure({ app: 'webapp-shield' });

    var rules = window.SHIELD.RULES;
    var count = rules.SECRET_RULES.length + rules.CODE_RULES.length + rules.FILE_RULES.length;
    $('#ruleCount').textContent = String(count);

    S.code.text = $('#codeText').value;
    $('#codePath').value = S.code.path;
    updateCodeMeta();

    $('#ghToken').value = ghToken();
    $('#optGroup').checked = S.groupByFile;

    renderDefense();
    renderFileList();
    renderByok();
    renderAiSummary();
    updateAiButton();
    bind();

    var h = (location.hash || '').replace('#', '');
    setTab(h || 'scan');
    renderAll();

    // 첫 방문: 빈 화면 대신 예시를 조용히 채우지는 않는다(사용자 코드로 오해하지 않도록).
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
