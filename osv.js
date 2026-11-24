/* ============================================================================
   osv.js · 실제 의존성 CVE 조회 (OSV.dev 공식 무료 API)
   ----------------------------------------------------------------------------
   package.json의 dependencies / devDependencies를 읽어
     POST https://api.osv.dev/v1/querybatch
   로 버전별 취약점을 조회하고, 각 취약점의 상세(GHSA/CVE, 심각도, 수정 버전)를
     GET  https://api.osv.dev/v1/vulns/{id}
   로 가져온다. 네트워크가 없으면 내장 참고 DB로 폴백하되, 화면에는 반드시
   "내장 참고 DB"라고 표시한다(실시간 조회 결과로 오인되지 않게).

   OSV.dev는 무료·키 불필요·CORS 허용. 브라우저 · node 공용.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.OSV = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var API = 'https://api.osv.dev';
  var MAX_QUERIES = 200;
  var MAX_DETAILS = 40;

  /* ── package.json 파싱 ───────────────────────────────────────────────── */

  function cleanVersion(raw) {
    var v = String(raw || '').trim();
    if (!v) return { version: '', skip: '버전 없음' };
    if (/^(?:workspace|file|link|portal):/i.test(v)) return { version: '', skip: '로컬 경로 의존성' };
    if (/^(?:git|https?|ssh):/i.test(v) || /github:/i.test(v)) return { version: '', skip: 'git/URL 의존성' };
    if (/^(?:\*|latest|x)$/i.test(v)) return { version: '', skip: '버전 범위 없음' };
    // npm:alias@1.2.3
    var alias = v.match(/^npm:[^@]+@(.+)$/);
    if (alias) v = alias[1];
    // >=1.2.3 <2  → 1.2.3
    var range = v.match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
    if (range) return { version: range[1] };
    return { version: '', skip: '버전 해석 불가: ' + v };
  }

  function parsePackageJson(text) {
    var data;
    try { data = JSON.parse(String(text || '')); }
    catch (e) { return { ok: false, error: 'package.json 형식이 아닙니다: ' + e.message, deps: [], skipped: [] }; }
    if (!data || typeof data !== 'object') return { ok: false, error: 'package.json 형식이 아닙니다.', deps: [], skipped: [] };

    var deps = [], skipped = [];
    [['dependencies', false], ['devDependencies', true], ['optionalDependencies', false]].forEach(function (pair) {
      var block = data[pair[0]];
      if (!block || typeof block !== 'object') return;
      Object.keys(block).forEach(function (name) {
        var c = cleanVersion(block[name]);
        if (!c.version) { skipped.push({ name: name, raw: String(block[name]), reason: c.skip }); return; }
        deps.push({ name: name, version: c.version, raw: String(block[name]), dev: pair[1], ecosystem: 'npm' });
      });
    });
    return { ok: true, deps: deps, skipped: skipped, name: data.name || '', count: deps.length };
  }

  /* ── semver 비교 (내장 DB용 최소 구현) ──────────────────────────────── */

  function parts(v) {
    var m = String(v).match(/(\d+)\.(\d+)\.(\d+)/);
    if (!m) return null;
    return [Number(m[1]), Number(m[2]), Number(m[3])];
  }

  function compare(a, b) {
    var pa = parts(a), pb = parts(b);
    if (!pa || !pb) return 0;
    for (var i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1; }
    return 0;
  }

  function lt(a, b) { return compare(a, b) < 0; }

  /* ── 내장 참고 DB (네트워크 실패 시에만, 화면에 출처 표시) ──────────── */

  var FALLBACK_DB = [
    { name: 'lodash', below: '4.17.21', id: 'GHSA-35jh-r3h4-6jhm', cve: 'CVE-2021-23337', severity: 'high', summary: 'template 함수의 명령 주입', fixed: '4.17.21' },
    { name: 'lodash', below: '4.17.19', id: 'GHSA-p6mc-m468-83gw', cve: 'CVE-2020-8203', severity: 'high', summary: 'prototype pollution (zipObjectDeep)', fixed: '4.17.19' },
    { name: 'axios', below: '1.6.0', id: 'GHSA-wf5p-g6vw-rhxx', cve: 'CVE-2023-45857', severity: 'medium', summary: 'XSRF 토큰이 제3자 호스트로 유출', fixed: '1.6.0' },
    { name: 'express', below: '4.19.2', id: 'GHSA-rv95-896h-c2vc', cve: 'CVE-2024-29041', severity: 'medium', summary: 'malformed URL로 open redirect', fixed: '4.19.2' },
    { name: 'jsonwebtoken', below: '9.0.0', id: 'GHSA-27h2-hvpr-p74q', cve: 'CVE-2022-23529', severity: 'high', summary: '비밀키 검증 우회로 RCE 가능', fixed: '9.0.0' },
    { name: 'body-parser', below: '1.20.3', id: 'GHSA-qwcr-r2fm-qrc7', cve: 'CVE-2024-45590', severity: 'high', summary: 'URL 인코딩 body로 DoS', fixed: '1.20.3' },
    { name: 'path-to-regexp', below: '0.1.10', id: 'GHSA-9wv6-86v2-598j', cve: 'CVE-2024-45296', severity: 'high', summary: '정규식 backtracking ReDoS', fixed: '0.1.12' },
    { name: 'ws', below: '8.17.1', id: 'GHSA-3h5v-q93c-6h6q', cve: 'CVE-2024-37890', severity: 'high', summary: '많은 헤더로 DoS', fixed: '8.17.1' },
    { name: 'minimist', below: '1.2.6', id: 'GHSA-xvch-5gv4-984h', cve: 'CVE-2021-44906', severity: 'critical', summary: 'prototype pollution', fixed: '1.2.6' },
    { name: 'next', below: '14.2.25', id: 'GHSA-f82v-jwr5-mffw', cve: 'CVE-2025-29927', severity: 'critical', summary: 'x-middleware-subrequest 헤더로 인증 미들웨어 우회', fixed: '14.2.25' },
    { name: 'multer', below: '2.0.0', id: 'GHSA-4pg4-qvpc-4q3h', cve: 'CVE-2025-47935', severity: 'high', summary: '메모리 누수로 DoS', fixed: '2.0.0' },
    { name: 'undici', below: '5.28.4', id: 'GHSA-3787-6prv-h9w3', cve: 'CVE-2024-24758', severity: 'medium', summary: '프록시 인증 헤더 유출', fixed: '5.28.4' }
  ];

  function fallbackLookup(deps) {
    var results = [], total = 0;
    deps.forEach(function (d) {
      var hits = FALLBACK_DB.filter(function (f) {
        return f.name.toLowerCase() === d.name.toLowerCase() && lt(d.version, f.below);
      }).map(function (f) {
        return {
          id: f.id, aliases: [f.cve], summary: f.summary, severity: f.severity,
          severityLabel: labelOf(f.severity), fixed: f.fixed,
          link: 'https://osv.dev/vulnerability/' + f.id, source: 'fallback'
        };
      });
      total += hits.length;
      results.push({ name: d.name, version: d.version, vulns: hits });
    });
    return { status: 'fallback', source: '내장 참고 DB', checkedAt: new Date().toISOString(), deps: results, totalVulns: total };
  }

  /* ── OSV 응답 해석 ──────────────────────────────────────────────────── */

  function labelOf(sev) {
    var s = String(sev || '').toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
    if (s === 'moderate') return 'medium';   // GHSA 표기
    if (s === 'important') return 'high';    // 일부 배포판 표기
    return 'unknown';
  }

  function severityFrom(vuln) {
    var label = (vuln.database_specific && vuln.database_specific.severity) || '';
    if (labelOf(label) !== 'unknown') return labelOf(label);
    var arr = vuln.severity || [];
    for (var i = 0; i < arr.length; i++) {
      var score = arr[i] && arr[i].score;
      if (typeof score === 'number') {
        if (score >= 9) return 'critical';
        if (score >= 7) return 'high';
        if (score >= 4) return 'medium';
        return 'low';
      }
      if (typeof score === 'string') {
        var m = score.match(/CVSS:3\.[01]\/.*\/?S:[A-Z]\/.*\/?C:[A-Z]\/.*\/?A:[A-Z]/);
        if (m) return 'high';
      }
    }
    return 'unknown';
  }

  function fixedFrom(vuln, pkgName) {
    var best = '';
    (vuln.affected || []).forEach(function (aff) {
      if (pkgName && aff.package && aff.package.name && aff.package.name.toLowerCase() !== pkgName.toLowerCase()) return;
      (aff.ranges || []).forEach(function (range) {
        (range.events || []).forEach(function (ev) {
          if (ev.fixed && (!best || lt(best, ev.fixed))) best = ev.fixed;
        });
      });
    });
    return best;
  }

  function detailsOf(vuln, pkgName) {
    var aliases = (vuln.aliases || []).filter(function (a) { return /^CVE-/.test(a); });
    var cve = aliases[0] || '';
    var sev = severityFrom(vuln);
    return {
      id: vuln.id,
      aliases: (vuln.aliases || []).slice(0, 6),
      cve: cve,
      summary: vuln.summary || (vuln.details || '').split('\n')[0].slice(0, 200) || vuln.id,
      severity: sev,
      severityLabel: labelOf(sev),
      fixed: fixedFrom(vuln, pkgName),
      published: vuln.published || '',
      link: 'https://osv.dev/vulnerability/' + vuln.id,
      source: 'osv.dev'
    };
  }

  /* ── 실제 조회 ──────────────────────────────────────────────────────── */

  function post(url, body, timeoutMs) {
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = null;
    var opts = {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
      mode: 'cors',
      cache: 'no-store'
    };
    if (controller) opts.signal = controller.signal;

    return new Promise(function (resolve) {
      var settled = false;
      function done(v) { if (!settled) { settled = true; if (timer) clearTimeout(timer); resolve(v); } }
      if (timeoutMs) {
        timer = setTimeout(function () {
          if (controller) { try { controller.abort(); } catch (e) { /* noop */ } }
          done({ ok: false, reason: 'timeout' });
        }, timeoutMs);
      }
      fetch(url, opts).then(function (res) {
        return res.text().then(function (t) {
          var body = null;
          try { body = t ? JSON.parse(t) : null; } catch (e) { body = null; }
          if (res.ok) done({ ok: true, body: body, status: res.status });
          else done({ ok: false, reason: 'http_' + res.status, status: res.status, body: body });
        });
      }).catch(function (e) {
        done({ ok: false, reason: (controller && controller.signal && controller.signal.aborted) ? 'timeout' : 'network' });
      });
    });
  }

  function getJson(url, timeoutMs) {
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var opts = { mode: 'cors', cache: 'no-store', headers: { accept: 'application/json' } };
    if (controller) opts.signal = controller.signal;
    return new Promise(function (resolve) {
      var settled = false;
      var timer = null;
      function done(v) { if (!settled) { settled = true; if (timer) clearTimeout(timer); resolve(v); } }
      if (timeoutMs) timer = setTimeout(function () { if (controller) { try { controller.abort(); } catch (e) {} } done({ ok: false }); }, timeoutMs);
      fetch(url, opts).then(function (r) { return r.ok ? r.json().then(function (j) { done({ ok: true, body: j }); }) : done({ ok: false, status: r.status }); })
        .catch(function () { done({ ok: false }); });
    });
  }

  async function lookup(deps, opts) {
    opts = opts || {};
    var list = (deps || []).slice(0, MAX_QUERIES);
    if (!list.length) {
      return { status: 'empty', source: 'osv.dev', checkedAt: new Date().toISOString(), deps: [], totalVulns: 0, message: '조회할 의존성이 없습니다.' };
    }
    if (typeof fetch !== 'function') {
      var fb0 = fallbackLookup(list);
      fb0.message = '이 환경에서는 네트워크 조회를 할 수 없어 내장 참고 DB로만 확인했습니다.';
      return fb0;
    }

    var queries = list.map(function (d) {
      return { package: { name: d.name, ecosystem: d.ecosystem || 'npm' }, version: d.version };
    });

    var res = await post(API + '/v1/querybatch', { queries: queries }, opts.timeoutMs || 20000);
    if (!res.ok) {
      var fb = fallbackLookup(list);
      fb.message = res.reason === 'timeout'
        ? 'OSV.dev 응답이 늦어 내장 참고 DB로 임시 점검했습니다. 잠시 뒤 다시 조회하세요.'
        : (res.reason === 'network'
          ? 'OSV.dev에 연결하지 못해 내장 참고 DB로 임시 점검했습니다(실시간 아님).'
          : 'OSV.dev가 오류를 반환해(' + res.reason + ') 내장 참고 DB로 임시 점검했습니다.');
      fb.error = res.reason;
      return fb;
    }

    var results = (res.body && res.body.results) || [];
    var index = [];
    var idSet = Object.create(null);

    results.forEach(function (r, i) {
      var dep = list[i];
      if (!dep) return;
      var ids = (r && r.vulns ? r.vulns : []).map(function (v) { return v.id; }).filter(Boolean);
      ids.forEach(function (id) { idSet[id] = 1; });
      index.push({ dep: dep, ids: ids });
    });

    var uniqueIds = Object.keys(idSet).slice(0, MAX_DETAILS);
    var detail = Object.create(null);
    var CONC = 5;
    for (var i = 0; i < uniqueIds.length; i += CONC) {
      var batch = uniqueIds.slice(i, i + CONC);
      var settled = await Promise.all(batch.map(function (id) {
        return getJson(API + '/v1/vulns/' + encodeURIComponent(id), opts.timeoutMs || 15000);
      }));
      settled.forEach(function (s, k) {
        if (s && s.ok && s.body) detail[batch[k]] = s.body;
      });
    }

    var out = [], total = 0;
    index.forEach(function (entry) {
      var vulns = entry.ids.map(function (id) {
        var d = detail[id];
        if (!d) return { id: id, aliases: [], cve: '', summary: '상세 정보를 가져오지 못했습니다.', severity: 'unknown', severityLabel: 'unknown', fixed: '', link: 'https://osv.dev/vulnerability/' + id, source: 'osv.dev' };
        return detailsOf(d, entry.dep.name);
      });
      total += vulns.length;
      out.push({ name: entry.dep.name, version: entry.dep.version, dev: !!entry.dep.dev, vulns: vulns });
    });

    return {
      status: total ? 'live' : 'clean',
      source: 'osv.dev',
      checkedAt: new Date().toISOString(),
      deps: out,
      totalVulns: total,
      packagesWithVulns: out.filter(function (d) { return d.vulns.length; }).length,
      detailMissing: uniqueIds.filter(function (id) { return !detail[id]; }).length,
      truncated: Object.keys(idSet).length > MAX_DETAILS,
      message: total ? '' : 'OSV.dev 기준 알려진 취약점이 없습니다.'
    };
  }

  return {
    VERSION: VERSION,
    API: API,
    parsePackageJson: parsePackageJson,
    cleanVersion: cleanVersion,
    compare: compare,
    lookup: lookup,
    fallbackLookup: fallbackLookup,
    severityFrom: severityFrom,
    FALLBACK_DB: FALLBACK_DB
  };
});
