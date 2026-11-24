/* ============================================================================
   free-ai-client.js · 무료 AI 맛보기 클라이언트 (의존성 없는 UMD)
   ----------------------------------------------------------------------------
   웹앱에 <script src="free-ai-client.js"></script> 로 넣고 두 줄만 쓰면 된다.

     FreeAI.configure({ endpoint: WORKER_ENDPOINT });   // 아래 DEFAULT_ENDPOINT
     FreeAI.generate({ task:'text', prompt:'...', system:'...' }).then(render);

   결과 모양은 packages/pro-api-connector.js 의 generate() 와 같다.
     { ok:true, mode:'free', text, remaining, limit, resetAt, provider }
     { ok:false, reason, message, cta }   ← 한도 소진도 여기로 온다

   연결된 Pro 가 있으면 FreeAI.routeWith(ProConnector, req) 가 알아서 Pro 로 보낸다.
   ========================================================================== */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(root);
  else root.FreeAI = factory(root);
})(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
  'use strict';

  var VERSION = '1.0.0';
  var STORAGE_KEY = 'freeai.endpoint.v1';
  var VISITOR_KEY = 'freeai.visitor.v1';
  var DEFAULT_ENDPOINT = 'https://free-ai-taste.onetap-ai.workers.dev';
  var DEFAULT_TIMEOUT = 30000;

  var config = {
    endpoint: '',
    app: '',
    timeoutMs: DEFAULT_TIMEOUT,
    busyRetry: 1,        // 503 all_providers_busy 일 때 자동 재시도 횟수
    busyRetryDelayMs: 900
  };

  var last = { remaining: null, limit: null, resetAt: '', provider: '', at: 0 };

  function trim(v) { return String(v === null || v === undefined ? '' : v).replace(/^\s+|\s+$/g, ''); }

  function isHttpUrl(u) {
    var s = trim(u);
    return !!s && !/\s/.test(s) && /^https?:\/\/[^\s]+$/i.test(s);
  }

  function readStored() {
    try {
      return root.localStorage ? trim(root.localStorage.getItem(STORAGE_KEY)) : '';
    } catch (e) { return ''; }
  }

  function writeStored(value) {
    try {
      if (!root.localStorage) return false;
      if (value) root.localStorage.setItem(STORAGE_KEY, value);
      else root.localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch (e) { return false; }
  }

  /** 브라우저가 한 번 만드는 무작위 체험 ID. 계정·기기 지문과 무관하고, 지우면 새로 생긴다. */
  function visitorId() {
    try {
      if (!root.localStorage) return '';
      var saved = root.localStorage.getItem(VISITOR_KEY);
      if (saved && /^[A-Za-z0-9_-]{8,64}$/.test(saved)) return saved;
      var made = '';
      if (root.crypto && typeof root.crypto.randomUUID === 'function') {
        made = root.crypto.randomUUID().replace(/-/g, '');
      } else {
        made = 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 12);
      }
      root.localStorage.setItem(VISITOR_KEY, made);
      return made;
    } catch (e) { return ''; }
  }

  function endpointOf(opts) {
    var explicit = trim(opts && opts.endpoint);
    if (explicit) return explicit;
    if (config.endpoint) return config.endpoint;
    var stored = readStored();
    if (stored) return stored;
    return trim(DEFAULT_ENDPOINT);
  }

  function configure(opts) {
    var o = opts || {};
    if (o.endpoint !== undefined) {
      var ep = trim(o.endpoint).replace(/\/+$/, '');
      config.endpoint = ep;
      writeStored(ep);
    }
    if (o.app !== undefined) config.app = trim(o.app).replace(/[^A-Za-z0-9-]/g, '').slice(0, 32);
    if (o.timeoutMs !== undefined) {
      var n = Number(o.timeoutMs);
      if (isFinite(n) && n >= 1000) config.timeoutMs = n;
    }
    if (o.busyRetry !== undefined) {
      var r = Number(o.busyRetry);
      if (isFinite(r) && r >= 0 && r <= 3) config.busyRetry = r;
    }
    return status();
  }

  function status() {
    return {
      version: VERSION,
      endpoint: endpointOf(),
      app: config.app,
      ready: isHttpUrl(endpointOf()),
      remaining: last.remaining,
      limit: last.limit,
      resetAt: last.resetAt,
      provider: last.provider,
      checkedAt: last.at
    };
  }

  function normalizeError(res, body) {
    var msg = (body && (body.message || (body.error && body.error.message))) || '';
    if (!msg) {
      if (res === 'network') msg = '무료 체험 서버에 연결하지 못했어요. 인터넷을 확인해 주세요.';
      else if (res === 'timeout') msg = '무료 체험 응답이 늦어요. 잠시 뒤 다시 시도해 주세요.';
      else msg = '무료 체험 중 문제가 생겼어요.';
    }
    return msg;
  }

  function post(path, payload, opts) {
    var endpoint = endpointOf(opts);
    if (!isHttpUrl(endpoint)) {
      return Promise.resolve({
        ok: false, mode: 'free', reason: 'not_configured',
        message: '무료 체험 주소가 아직 설정되지 않았어요. FreeAI.configure({ endpoint }) 를 먼저 실행해 주세요.'
      });
    }
    if (typeof root.fetch !== 'function') {
      return Promise.resolve({
        ok: false, mode: 'free', reason: 'no_fetch', message: '이 브라우저에서는 무료 체험을 쓸 수 없어요.'
      });
    }

    var url = endpoint + path;
    var timeoutMs = (opts && opts.timeoutMs) || config.timeoutMs;
    var controller = typeof root.AbortController === 'function' ? new root.AbortController() : null;
    var timer = null;
    var settled = false;

    var fetchInit = {
      method: payload === null ? 'GET' : 'POST',
      headers: { accept: 'application/json' },
      credentials: 'omit',
      mode: 'cors',
      cache: 'no-store'
    };
    if (payload !== null) fetchInit.headers['content-type'] = 'application/json';
    var vid = visitorId();
    if (vid) fetchInit.headers['x-free-ai-visitor'] = vid;
    if (payload !== null) fetchInit.body = JSON.stringify(payload);
    if (controller) fetchInit.signal = controller.signal;

    return new Promise(function (resolve) {
      function finish(result) {
        if (settled) return;
        settled = true;
        if (timer) { clearTimeout(timer); timer = null; }
        if (result && result.ok) {
          if (result.remaining !== undefined && result.remaining !== null) last.remaining = result.remaining;
          if (result.limit !== undefined && result.limit !== null) last.limit = result.limit;
          if (result.resetAt) last.resetAt = result.resetAt;
          if (result.provider) last.provider = result.provider;
          last.at = Date.now();
        }
        resolve(result);
      }

      if (timeoutMs > 0) {
        timer = setTimeout(function () {
          if (controller) { try { controller.abort(); } catch (e) { /* noop */ } }
          finish({ ok: false, mode: 'free', reason: 'timeout', message: normalizeError('timeout') });
        }, timeoutMs);
      }

      root.fetch(url, fetchInit).then(function (res) {
        var remaining = null;
        var limit = null;
        try {
          var r = res.headers.get('x-free-ai-remaining');
          var l = res.headers.get('x-free-ai-limit');
          if (r !== null) remaining = Number(r);
          if (l !== null) limit = Number(l);
        } catch (e) { /* noop */ }

        return res.text().then(function (text) {
          var body = null;
          try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }

          if (res.ok && body && body.ok !== false) {
            finish({
              ok: true, mode: 'free', text: trim(body.text),
              provider: body.provider || '', model: body.model || '',
              usage: body.usage || null,
              remaining: body.remaining !== undefined ? body.remaining : remaining,
              limit: body.limit !== undefined ? body.limit : limit,
              resetAt: body.resetAt || '', requestId: body.requestId || ''
            });
            return;
          }

          var reason = (body && body.reason) || (res.status === 429 ? 'free_quota_exceeded' : 'http_' + res.status);
          finish({
            ok: false, mode: 'free', reason: reason,
            message: normalizeError(res.status, body),
            status: res.status,
            remaining: body && body.remaining !== undefined ? body.remaining : (remaining === null ? 0 : remaining),
            limit: body && body.limit !== undefined ? body.limit : limit,
            resetAt: (body && body.resetAt) || '',
            cta: (body && body.cta) || null,
            alternatives: (body && body.alternatives) || [],
            retryAfter: (body && body.retryAfter) || 0
          });
        });
      }).catch(function (err) {
        var aborted = controller && controller.signal && controller.signal.aborted;
        finish({
          ok: false, mode: 'free',
          reason: aborted ? 'timeout' : 'network_error',
          message: normalizeError(aborted ? 'timeout' : 'network')
        });
      });
    });
  }

  function wait(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  /** 503(모든 제공자 혼잡)은 잠깐 뒤 한 번 더 시도하면 대개 성공한다. */
  function isBusy(result) {
    return !!result && result.ok !== true &&
      (result.reason === 'all_providers_busy' || result.status === 503);
  }

  function generate(request, opts) {
    var req = request || {};
    var o = opts || {};
    var payload = {
      task: trim(req.task) || 'text',
      prompt: trim(req.prompt),
      system: trim(req.system)
    };
    if (req.options && typeof req.options === 'object') payload.options = req.options;
    if (req.model) payload.model = trim(req.model);
    if (config.app || o.app) payload.app = config.app || trim(o.app);

    var retries = o.busyRetry !== undefined ? Number(o.busyRetry) : config.busyRetry;
    var delay = o.busyRetryDelayMs !== undefined ? Number(o.busyRetryDelayMs) : config.busyRetryDelayMs;
    var attempt = 0;

    function run() {
      return post('/v1/generate', payload, o).then(function (res) {
        if (isBusy(res) && attempt < retries) {
          attempt++;
          return wait(delay).then(run);
        }
        res.attempts = attempt + 1;
        return res;
      });
    }
    return run();
  }

  function usage(opts) {
    return post('/v1/usage', null, opts);
  }

  function health(opts) {
    return post('/health', null, opts);
  }

  /** 연결된 Pro 가 있으면 Pro 로, 없으면 무료 맛보기로 보낸다. 결과 모양은 같다. */
  function routeWith(pro, request, opts) {
    if (pro && typeof pro.isConnected === 'function' && pro.isConnected()) {
      if (typeof pro.generate === 'function') return pro.generate(request, opts);
    }
    return generate(request, opts);
  }

  /** 한도 소진 응답을 화면에 그대로 쓸 수 있는 문구 묶음으로 바꾼다. */
  function limitCard(result) {
    var r = result || {};
    if (r.ok || (r.reason !== 'free_quota_exceeded' && r.reason !== 'global_daily_cap' && r.reason !== 'shared_network_limit')) return null;
    var cta = r.cta || {};
    return {
      title: r.reason === 'global_daily_cap' ? '오늘 무료 체험분이 다 찼어요'
        : (r.reason === 'shared_network_limit' ? '이 회선의 무료 체험이 다 찼어요' : '무료 체험을 다 쓰셨어요'),
      body: r.message || '',
      resetAt: r.resetAt || '',
      primary: cta.label
        ? { label: cta.label, href: cta.keyUrl || '', kind: cta.kind || 'connect_key' }
        : { label: '내 무료 키로 계속하기', href: 'https://aistudio.google.com/apikey', kind: 'connect_key' },
      secondary: (r.alternatives || []).map(function (a) {
        return { label: a.label, kind: a.kind };
      })
    };
  }

  return {
    VERSION: VERSION,
    configure: configure,
    status: status,
    generate: generate,
    usage: usage,
    health: health,
    routeWith: routeWith,
    limitCard: limitCard,
    isBusy: isBusy,
    isQuota: function (r) {
      return !!r && r.ok !== true && (r.reason === 'free_quota_exceeded' ||
        r.reason === 'global_daily_cap' || r.reason === 'shared_network_limit');
    },
    reset: function () { config.endpoint = ''; writeStored(''); return status(); }
  };
});
