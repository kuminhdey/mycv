// quizbot.js — ES Module for GitHub Pages
// Usage (on the quiz page, in DevTools Console):
//   await import('https://<username>.github.io/<repo>/quizbot.js')
//     .then(m => m.runQuiz({ maxQuestions: 5 }))
//
// Access control: ECIES (P-256 ECDH + HKDF + AES-GCM)
// - Publisher: encrypt timestamp_ms with PUBLIC KEY -> JSON {v,epk,iv,salt,ct} (b64url) -> Base64 whole JSON.
// - Consumer (this file): PRIVATE KEY is embedded; user pastes Access Token (Base64), decrypt -> timestamp, check TTL <= 60s.
//
// After the quiz runs, this module prints an image in the console from a Base64 PNG (donation banner).

'use strict';

/* =========================
 * 1) ACCESS via ECIES (P-256 ECDH + HKDF + AES-GCM)
 * ========================= */
const ACCESS = {
  TTL_MS: 300_000, // token freshness window (60s)
  // ⚠️ SECURITY: Private key is embedded for demo/testing only. Do not ship secrets in public repos.
  PRIVATE_KEY_PEM: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEgJFaFBqdftZlPV9i35xiaLDXNjQ9ty3RSPBtZzBCcfoAoGCCqGSM49
AwEHoUQDQgAESrM8zwj/ZCRdoO7ilyhYIiv3npJB0ekBk3qhcphSojfc9sbUs5Px
KBhMizvvmq81fqWJ7JeBGUn8o81y6DGuzQ==
-----END EC PRIVATE KEY-----`,
};

const _enc = new TextEncoder();
const _dec = new TextDecoder();

// Base64 (standard) -> string UTF-8
function _b64ToStr(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return _dec.decode(u8);
}

// Base64URL -> Uint8Array
function _b64uToU8(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from([...bin].map(c => c.charCodeAt(0)));
}

// ----- PEM helpers + SEC1 -> PKCS#8 -----
function _strip(pem, begin, end) {
  return pem.replace(begin, '').replace(end, '').replace(/\s+/g, '');
}
function _pemBlockToU8(pem, begin, end) {
  const b64 = _strip(pem.trim(), begin, end);
  const bin = atob(b64);
  return Uint8Array.from([...bin].map(c => c.charCodeAt(0)));
}
function _encLen(n) {
  if (n < 128) return Uint8Array.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}
function _asn1(tag, content) {
  const len = _encLen(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag; out.set(len, 1); out.set(content, 1 + len.length);
  return out;
}
const _seq = (content) => _asn1(0x30, content);
const _oct = (content) => _asn1(0x04, content);

// SEC1 EC PRIVATE KEY -> PKCS#8 PrivateKeyInfo (prime256v1)
function _sec1ToPkcs8(sec1U8) {
  const int0 = Uint8Array.from([0x02, 0x01, 0x00]); // INTEGER 0
  const oid = (...x) => Uint8Array.from([0x06, x.length, ...x]);
  const idEcPublicKey = oid(0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01);      // 1.2.840.10045.2.1
  const prime256v1    = oid(0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07); // 1.2.840.10045.3.1.7
  const algId         = _seq(new Uint8Array([...idEcPublicKey, ...prime256v1]));
  return _seq(new Uint8Array([...int0, ...algId, ..._oct(sec1U8)]));
}

async function _importPrivateKeyEC(pem) {
  let keyData, fmt = 'pkcs8';
  if (pem.includes('BEGIN EC PRIVATE KEY')) {
    const sec1 = _pemBlockToU8(pem, '-----BEGIN EC PRIVATE KEY-----', '-----END EC PRIVATE KEY-----');
    keyData = _sec1ToPkcs8(sec1);
  } else if (pem.includes('BEGIN PRIVATE KEY')) {
    keyData = _pemBlockToU8(pem, '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----');
  } else {
    throw new Error('Private key PEM không hợp lệ (cần EC PRIVATE KEY hoặc PRIVATE KEY).');
  }
  return crypto.subtle.importKey('pkcs8', keyData.buffer, { name:'ECDH', namedCurve:'P-256' }, false, ['deriveKey','deriveBits']);
}

/** Decrypt Access Token (Base64 of JSON {v,epk,iv,salt,ct}) -> timestamp (ms) */
async function _decryptTokenB64ToTimestampMs(tokenB64) {
  const json = _b64ToStr(String(tokenB64 || ''));
  const t = JSON.parse(json);
  if (!t || t.v !== 1) throw new Error('Token không hợp lệ');

  const priv = await _importPrivateKeyEC(ACCESS.PRIVATE_KEY_PEM);
  const ephPub = await crypto.subtle.importKey('raw', _b64uToU8(t.epk), { name:'ECDH', namedCurve:'P-256' }, false, []);

  const shared = await crypto.subtle.deriveBits({ name:'ECDH', public: ephPub }, priv, 256);
  const hkdfBase = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt: _b64uToU8(t.salt), info: _enc.encode('ecies-p256-timestamp') },
    hkdfBase,
    { name:'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const tsBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: _b64uToU8(t.iv) }, aesKey, _b64uToU8(t.ct));
  const tsStr = new TextDecoder().decode(new Uint8Array(tsBuf));
  if (!/^\d{10,}$/.test(tsStr)) throw new Error('Timestamp không hợp lệ');
  return Number(tsStr);
}

/** Cached access with prompt-once-then-reuse; re-prompt on invalid/expired */
async function _ensureAccessGranted() {
  let tokenB64 = (window.__QUIZBOT_TOKEN_B64 || '').trim();
  while (true) {
    // if not cached, ask user
    if (!tokenB64) {
      tokenB64 = prompt('Dán Access Token (Base64 của JSON ECIES):', '') || '';
      tokenB64 = tokenB64.trim();
      if (!tokenB64) throw new Error('Thiếu Access Token');
    }

    try {
      const ts = await _decryptTokenB64ToTimestampMs(tokenB64);
      const delta = Math.abs(Date.now() - ts);
      if (delta > ACCESS.TTL_MS) throw new Error('expired');
      // success: cache and return
      window.__QUIZBOT_TOKEN_B64 = tokenB64;
      return true;
    } catch (e) {
      console.warn('[access] token invalid/expired → yêu cầu nhập lại:', e?.message || e);
      window.__QUIZBOT_TOKEN_B64 = '';
      const again = prompt('Access Token không hợp lệ hoặc đã hết hạn.\nVui lòng dán token mới (hoặc Cancel để dừng):', '') || '';
      tokenB64 = again.trim();
      if (!tokenB64) throw new Error('Access bị từ chối (token rỗng).');
    }
  }
}

/* =========================
 * 2) QUIZ CONFIG & STATE
 * ========================= */
const CONFIG = {
  MODEL: 'gemini-2.0-flash',          // <<<<<< switched default model here
  DELAY_AFTER_SELECT: 600,
  DELAY_BEFORE_NEXT: 400,
  LOAD_TIMEOUT_MS: 15000,
  POLL_INTERVAL_MS: 250,
  MAX_RETRIES: 5,
  BASE_BACKOFF_MS: 1200,
  BACKOFF_FACTOR: 2,
};

const STATE = {
  apiKey: '',
  selectors: {
    question: 'p.para-big.disable-select, p.para-big, .para-big.disable-select',
    optionLabels: 'ul.list-block li label', // for radio
    nextButtonFinder: (root) => {
      const byAria = [...root.querySelectorAll('button')]
        .find(b => ((b.getAttribute('aria-label') || '').toLowerCase().includes('next')));
      if (byAria) return byAria;
      const byText = [...root.querySelectorAll('button')]
        .find(b => (b.textContent || '').trim().toLowerCase().match(/\b(next|tiếp|câu tiếp|next question)\b/));
      return byText || null;
    },
    getRoot: () => {
      const iframe = document.querySelector('iframe[data-name="iframe-lesson-player"]');
      return (iframe?.contentDocument || iframe?.contentWindow?.document || document);
    },
  },
};

const _sleep = (ms) => new Promise(r => setTimeout(r, ms));

/* =========================
 * 3) Gemini API call
 * ========================= */
async function _promptApiKey() {
  const msg = 'Nhập GEMINI API key (tạo tại https://aistudio.google.com/app/apikey):';
  const val = prompt(msg, (window.__QUIZBOT_API_KEY || '')) || '';
  const key = val.trim();
  return key || null;
}

async function _geminiGenerateContentOnce({ system, user, model, temperature }) {
  const base = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  let attempt = 0, lastErr;

  while (attempt <= CONFIG.MAX_RETRIES) {
    try {
      const resp = await fetch(`${base}?key=${encodeURIComponent(STATE.apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: system ? { role: 'system', parts: [{ text: system }] } : undefined,
          contents: [{ role: 'user', parts: [{ text: user }] }],
          generationConfig: { temperature }
        })
      });

      if (resp.status === 429 || (resp.status >= 500 && resp.status < 600)) {
        const retryAfter = resp.headers.get('retry-after');
        let waitMs = retryAfter ? Number(retryAfter) * 1000 : null;
        if (!waitMs || Number.isNaN(waitMs)) {
          const jitter = Math.floor(Math.random() * 400);
          waitMs = CONFIG.BASE_BACKOFF_MS * Math.pow(CONFIG.BACKOFF_FACTOR, attempt) + jitter;
        }
        console.warn(`Gemini ${resp.status}. Retry #${attempt + 1} in ${waitMs}ms`);
        await _sleep(waitMs); attempt++; continue;
      }

      if (!resp.ok) {
        const txt = await resp.text().catch(()=> '');
        throw new Error(`Gemini ${resp.status} ${resp.statusText} — ${txt}`);
      }

      const data = await resp.json();
      const text =
        data?.candidates?.[0]?.content?.parts?.map(p => p.text).join('')?.trim() ||
        data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
        '';
      if (!text) throw new Error('Gemini trả về rỗng');
      return text;
    } catch (e) {
      lastErr = e;
      const jitter = Math.floor(Math.random() * 400);
      const waitMs = CONFIG.BASE_BACKOFF_MS * Math.pow(CONFIG.BACKOFF_FACTOR, attempt) + jitter;
      console.warn(`Gemini request failed (attempt ${attempt + 1}/${CONFIG.MAX_RETRIES + 1}): ${e?.message || e}. Retry in ${waitMs}ms`);
      await _sleep(waitMs); attempt++;
    }
  }
  throw lastErr || new Error('Gemini request failed after retries');
}

/** Call Gemini with current key; if it ultimately fails, prompt for new key once and retry */
async function _geminiGenerateContent({ system, user, model = CONFIG.MODEL, temperature = 0 }) {
  // ensure key from cache or prompt
  if (!STATE.apiKey) {
    STATE.apiKey = (window.__QUIZBOT_API_KEY || '').trim();
  }
  if (!STATE.apiKey) {
    const k = await _promptApiKey();
    if (!k) throw new Error('Không có API key.');
    STATE.apiKey = k; window.__QUIZBOT_API_KEY = k;
  }

  try {
    return await _geminiGenerateContentOnce({ system, user, model, temperature });
  } catch (e) {
    console.warn('[Gemini] thất bại sau max retries. Thử nhập API key mới...', e?.message || e);
    const k = await _promptApiKey();
    if (!k) throw e;
    STATE.apiKey = k; window.__QUIZBOT_API_KEY = k;
    // retry a fresh round
    return await _geminiGenerateContentOnce({ system, user, model, temperature });
  }
}

/* =========================
 * 4) DOM extractors
 * ========================= */
function _getRoot() { return STATE.selectors.getRoot(); }

function _extractRadioOptions(root) {
  const labels = [...root.querySelectorAll(STATE.selectors.optionLabels)];
  if (!labels.length) return null;
  return labels.map(label => {
    const li = label.closest('li');
    const radio = li?.querySelector('input[type="radio"]');
    const text = (label.innerText || li?.innerText || '').trim();
    return { li, radio, label, text };
  });
}

function _extractCheckboxOptions(root) {
  const inputs = [...root.querySelectorAll('ul.list-block li input[type="checkbox"]')];
  if (!inputs.length) return null;
  return inputs.map(input => {
    let text =
      input.closest('div.custom-test-case-checkbox')?.querySelector('span')?.innerText?.trim() ||
      input.getAttribute('aria-label') ||
      input.closest('li')?.innerText?.trim() || '';
    text = text.replace(/^.*?:\s*/, '').replace(/\(see .*$/i, '').trim();
    return { input, text };
  });
}

function _parseIndicesArray(raw, maxLen) {
  let arr = [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) arr = parsed;
    else if (Array.isArray(parsed.indices)) arr = parsed.indices;
    else if (typeof parsed.index === 'number') arr = [parsed.index];
  } catch (_e) {
    const m = raw.match(/"indices"\s*:\s*\[([^\]]*)\]/i);
    if (m && m[1]) {
      arr = m[1].split(/[, ]+/).map(x => Number(x)).filter(n => Number.isFinite(n));
    } else {
      arr = (raw.match(/\d+/g) || []).map(Number).filter(Number.isFinite);
    }
  }
  const seen = new Set(), clean = [];
  for (const n of arr) {
    const k = Math.trunc(n);
    if (!Number.isInteger(k)) continue;
    if (k < 0 || k >= maxLen) continue;
    if (!seen.has(k)) { seen.add(k); clean.push(k); }
  }
  return clean;
}

/* =========================
 * 5) Answer one question
 * ========================= */
async function _answerOne(root = _getRoot()) {
  const qEl = root.querySelector(STATE.selectors.question);
  const question = (qEl?.innerText || '').trim();

  // Try checkbox first
  const cbItems = _extractCheckboxOptions(root);
  if (cbItems?.length) {
    const options = cbItems.map(it => it.text);
    const systemPrompt =
      'Bạn là trợ lý làm trắc nghiệm. CÓ THỂ có NHIỀU đáp án đúng. ' +
      'Chỉ được trả về JSON: {"indices":[<0-based ints>], "reason":"<ngắn gọn>"} — không thêm chữ nào khác.';
    const userPrompt = [
      `Câu hỏi: ${question}`,
      `Các lựa chọn (0-based):`,
      ...options.map((op, i) => `  ${i}. ${op}`),
      `Yêu cầu: Chỉ trả về JSON {"indices":[...], "reason":"..."} (0-based).`
    ].join('\n');

    const raw = await _geminiGenerateContent({ system: systemPrompt, user: userPrompt, temperature: 0 });
    const indices = _parseIndicesArray(raw, options.length);
    if (!indices.length) throw new Error('Model không trả về indices hợp lệ cho checkbox');

    for (const idx of indices) {
      const it = cbItems[idx];
      if (!it?.input) continue;
      if (!it.input.checked) {
        it.input.click();
        it.input.dispatchEvent(new Event('change', { bubbles: true }));
        it.input.dispatchEvent(new Event('input', { bubbles: true }));
      }
      await _sleep(60);
    }
    console.log('%c✔ Checkbox:', 'color:#16a34a;font-weight:700', indices, indices.map(i => options[i]));
    let reason = ''; try { reason = JSON.parse(raw)?.reason || ''; } catch {}
    return { type: 'multi', question, options, indices, reason };
  }

  // Fallback: radio
  const rItems = _extractRadioOptions(root);
  if (!rItems?.length) throw new Error('Không tìm thấy lựa chọn (checkbox/radio).');
  const options = rItems.map(it => it.text);

  const systemPrompt =
    'Bạn là trợ lý làm trắc nghiệm. Chỉ chọn 1 đáp án đúng nhất. ' +
    'Chỉ được trả về JSON: {"index": <0-based int>, "reason": "<ngắn gọn>"} — không kèm chữ nào khác.';
  const userPrompt = [
    `Câu hỏi: ${question}`,
    `Các lựa chọn (0-based):`,
    ...options.map((op, i) => `  ${i}. ${op}`),
    `Yêu cầu: Chỉ trả về JSON đúng chuẩn: {"index": <int>, "reason": "<ngắn gọn>"}.`
  ].join('\n');

  const raw = await _geminiGenerateContent({ system: systemPrompt, user: userPrompt, temperature: 0 });
  let index = -1, reason = '';
  try { const p = JSON.parse(raw); index = Number(p.index); reason = String(p.reason || ''); }
  catch {
    const m = raw.match(/"index"\s*:\s*(\d+)/) || raw.match(/\b(\d+)\b/);
    if (m) index = Number(m[1]);
  }
  if (!Number.isInteger(index) || index < 0 || index >= options.length) {
    throw new Error('Model trả về index không hợp lệ (radio)');
  }

  const target = rItems[index];
  if (target?.label) target.label.click();
  else if (target?.radio) {
    target.radio.checked = true;
    target.radio.dispatchEvent(new Event('change', { bubbles: true }));
    target.radio.dispatchEvent(new Event('input', { bubbles: true }));
    target.radio.click();
  } else if (target?.li) { target.li.click(); }

  console.log('%c✔ Radio:', 'color:#16a34a;font-weight:700', index, options[index]);
  if (reason) console.log('Lý do:', reason);
  return { type: 'single', question, options, index, reason };
}

/* =========================
 * 6) Navigation
 * ========================= */
async function _clickNext(root = _getRoot()) {
  await _sleep(CONFIG.DELAY_AFTER_SELECT);
  const btn = STATE.selectors.nextButtonFinder(root);
  if (!btn) { console.warn('Không tìm thấy nút Next.'); return false; }
  await _sleep(CONFIG.DELAY_BEFORE_NEXT);
  btn.click();
  console.log('%c➡️  Next', 'color:#2563eb;font-weight:700');
  return true;
}

async function _waitForNextQuestion(prevText, root = _getRoot()) {
  const start = Date.now();
  while (Date.now() - start < CONFIG.LOAD_TIMEOUT_MS) {
    await _sleep(CONFIG.POLL_INTERVAL_MS);
    const q = root.querySelector(STATE.selectors.question);
    const txt = q?.innerText?.trim();
    if (txt && txt !== prevText) { await _sleep(150); return txt; }
  }
  throw new Error('Hết thời gian chờ câu hỏi mới');
}

/* =========================
 * 7) Console image (donation banner)
 * ========================= */
const DONATE_IMG_B64 = `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`;// (rút gọn vì dài)

function printConsoleImageFromBase64(base64, { width = 256, height = 256, title = '🙏 If this helped, consider a coffee!' } = {}) {
  try {
    const style = [
      'font-size:1px',
      `padding:${Math.floor(height/2)}px ${Math.floor(width/2)}px`,
      `background:url(data:image/png;base64,${base64}) no-repeat`,
      `background-size:${width}px ${height}px`,
      'line-height:0',
      'margin:8px 0',
      'border-radius:8px'
    ].join(';');
    console.log('%c ', style);
  } catch {
    console.log('Donate image (data URL):', `data:image/png;base64,${base64}`);
  }
  if (title) console.log('%c' + title, 'color:#16a34a;font-weight:700;font-size:14px');
}

/* =========================
 * 8) Public API
 * ========================= */
export async function runQuiz(opts = {}) {
  const { apiKey, maxQuestions = Infinity } = opts;

  // Access gate (ECIES token Base64)
  await _ensureAccessGranted();

  if (apiKey) {
    STATE.apiKey = String(apiKey).trim();
    window.__QUIZBOT_API_KEY = STATE.apiKey;
  } else if (!STATE.apiKey) {
    STATE.apiKey = (window.__QUIZBOT_API_KEY || '').trim();
    if (!STATE.apiKey) {
      const k = await _promptApiKey();
      if (!k) throw new Error('Không có API key → dừng.');
      STATE.apiKey = k; window.__QUIZBOT_API_KEY = k;
    }
  }

  let count = 0;
  const results = [];
  while (count < maxQuestions) {
    const root = _getRoot();
    const curQEl = root.querySelector(STATE.selectors.question);
    const prevText = curQEl?.innerText?.trim() ?? '';

    const one = await _answerOne(root);
    results.push(one);

    const moved = await _clickNext(root);
    if (!moved) { console.log('%c⏹ Dừng: không có nút Next.', 'color:#f97316;font-weight:700'); break; }

    try {
      await _waitForNextQuestion(prevText, root);
      console.log('%c⏭ Câu hỏi mới đã tải', 'color:#10b981;font-weight:700');
    } catch (e) {
      console.warn('⚠ Có thể là câu cuối.', e?.message || e);
      break;
    }
    count++;
  }

  console.log('%c🏁 Hoàn tất vòng lặp.', 'color:#9333ea;font-weight:700');
  // Print donation image/banner
  printConsoleImageFromBase64(DONATE_IMG_B64, { width: 256, height: 256, title: '🙏 Nếu hữu ích, mời mình ly cà phê nhé!' });
  return results;
}

// Optional helpers
export function setApiKey(k) { STATE.apiKey = String(k || '').trim(); window.__QUIZBOT_API_KEY = STATE.apiKey; }
export function setTTL(ms) { ACCESS.TTL_MS = Math.max(0, Number(ms) || 0); }
export function setSelectors(partial) { Object.assign(STATE.selectors, partial || {}); }

// Dev helper: decrypt token to see timestamp
export async function debugDecryptAccessTokenB64(tokenB64) {
  return _decryptTokenB64ToTimestampMs(tokenB64);
}

// Attach to window (handy if loaded inline)
if (typeof window !== 'undefined') {
  window.QuizBot = { runQuiz, setApiKey, setTTL, setSelectors, debugDecryptAccessTokenB64 };
}
