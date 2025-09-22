// quizbot.js — ES module, no API key inside
// Public API:
//   - import { runQuiz, setApiKey, setSelectors } from './quizbot.js'
//   - OR window.QuizBot.runQuiz(...)

const CONFIG = {
  MODEL: 'gemini-1.5-flash', // or 'gemini-1.5-pro'
  DELAY_AFTER_SELECT: 600,
  DELAY_BEFORE_NEXT: 400,
  LOAD_TIMEOUT_MS: 15000,
  POLL_INTERVAL_MS: 250,
  MAX_RETRIES: 5,
  BASE_BACKOFF_MS: 1200,
  BACKOFF_FACTOR: 2,
};

let STATE = {
  apiKey: '',
  // selectors có thể chỉnh nếu trang thay đổi
  selectors: {
    question: 'p.para-big.disable-select',
    optionLabels: 'ul.list-block li label',
    optionLis: 'ul.list-block li',
    nextButtonFinder: (root) =>
      [...root.querySelectorAll('button')]
        .find(b => (b.getAttribute('aria-label')||'').toLowerCase().includes('next question')),
    // Nếu quiz ở trong iframe
    getRoot: () => {
      const iframe = document.querySelector('iframe[data-name="iframe-lesson-player"]');
      const idoc = iframe?.contentDocument || iframe?.contentWindow?.document;
      return idoc || document;
    },
  },
};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

export function setApiKey(key) {
  STATE.apiKey = String(key || '').trim();
}

export function setSelectors(partial) {
  Object.assign(STATE.selectors, partial || {});
}

async function geminiGenerateContent({ system, user, model = CONFIG.MODEL, temperature = 0 }) {
  if (!STATE.apiKey) throw new Error('Chưa có API key. Gọi setApiKey("<YOUR_KEY>") hoặc truyền apiKey khi runQuiz().');

  const base = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  let attempt = 0;
  let lastErr;

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
        await sleep(waitMs);
        attempt++;
        continue;
      }

      if (!resp.ok) {
        const txt = await resp.text().catch(()=>'');
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
      await sleep(waitMs);
      attempt++;
    }
  }
  throw lastErr || new Error('Gemini request failed after retries');
}

function getRoot() {
  return STATE.selectors.getRoot();
}

async function answerOne(root = getRoot()) {
  const qEl = root.querySelector(STATE.selectors.question);
  if (!qEl) throw new Error(`Không tìm thấy thẻ câu hỏi: ${STATE.selectors.question}`);

  const question = qEl.innerText.trim();
  const labelEls = [...root.querySelectorAll(STATE.selectors.optionLabels)];
  if (labelEls.length === 0) throw new Error(`Không tìm thấy danh sách lựa chọn: ${STATE.selectors.optionLabels}`);
  const options = labelEls.map(l => l.innerText.trim());

  const systemPrompt =
    'Bạn là trợ lý làm trắc nghiệm. Chỉ chọn 1 đáp án đúng nhất. ' +
    'Chỉ được trả về JSON: {"index": <0-based int>, "reason": "<ngắn gọn>"} — không kèm chữ nào khác.';

  const userPrompt = [
    `Câu hỏi: ${question}`,
    `Các lựa chọn (0-based):`,
    ...options.map((op, i) => `  ${i}. ${op}`),
    `Yêu cầu: Chỉ trả về JSON đúng chuẩn: {"index": <int>, "reason": "<ngắn gọn>"}.`
  ].join('\n');

  const raw = await geminiGenerateContent({ system: systemPrompt, user: userPrompt, temperature: 0 });

  let index = -1, reason = '';
  try {
    const parsed = JSON.parse(raw);
    index = Number(parsed.index);
    reason = String(parsed.reason || '');
  } catch (_e) {
    const m = raw.match(/"index"\s*:\s*(\d+)/) || raw.match(/\b(\d+)\b/);
    if (m) index = Number(m[1]);
  }

  if (!Number.isInteger(index) || index < 0 || index >= options.length) {
    console.warn('Phản hồi model:', raw);
    throw new Error('Model trả về index không hợp lệ');
  }

  const liEls = [...root.querySelectorAll(STATE.selectors.optionLis)];
  const targetLi = liEls[index];
  if (!targetLi) throw new Error('Không tìm thấy <li> tương ứng với index');
  const radio = targetLi.querySelector('input[type="radio"]');
  const label = targetLi.querySelector('label');
  if (label) label.click();
  else if (radio) {
    radio.checked = true;
    radio.dispatchEvent(new Event('change', { bubbles: true }));
    radio.dispatchEvent(new Event('input', { bubbles: true }));
    radio.click();
  } else {
    throw new Error('Không tìm thấy input radio trong lựa chọn');
  }

  console.log('%c✔ Chọn:', 'color:#16a34a;font-weight:700', index, options[index]);
  if (reason) console.log('Lý do:', reason);

  return { question, options, index, reason };
}

async function clickNext(root = getRoot()) {
  await sleep(CONFIG.DELAY_AFTER_SELECT);
  const nextBtn = STATE.selectors.nextButtonFinder(root);
  if (!nextBtn) {
    console.warn('Không tìm thấy nút Next Question.');
    return false;
  }
  await sleep(CONFIG.DELAY_BEFORE_NEXT);
  nextBtn.click();
  console.log('%c➡️  Click Next Question', 'color:#2563eb;font-weight:700');
  return true;
}

async function waitForNextQuestion(prevText, root = getRoot()) {
  const start = Date.now();
  while (Date.now() - start < CONFIG.LOAD_TIMEOUT_MS) {
    await sleep(CONFIG.POLL_INTERVAL_MS);
    const q = root.querySelector(STATE.selectors.question);
    const txt = q?.innerText?.trim();
    if (txt && txt !== prevText) {
      await sleep(150);
      return txt;
    }
  }
  throw new Error('Hết thời gian chờ câu hỏi mới');
}

export async function runQuiz(opts = {}) {
  const {
    apiKey,
    maxQuestions = Infinity,
  } = opts;

  if (apiKey) setApiKey(apiKey);
  if (!STATE.apiKey) {
    const k = prompt('Nhập GEMINI_API_KEY (sẽ chỉ giữ trong bộ nhớ tạm của trang):', '');
    if (!k) throw new Error('Không có API key → dừng.');
    setApiKey(k);
  }

  let count = 0;
  while (count < maxQuestions) {
    const root = getRoot();
    const curQEl = root.querySelector(STATE.selectors.question);
    const prevText = curQEl?.innerText?.trim() ?? '';

    await answerOne(root).catch(err => {
      console.error('❌ Lỗi khi trả lời:', err);
      throw err;
    });

    const moved = await clickNext(root);
    if (!moved) {
      console.log('%c⏹ Dừng: không có nút Next.', 'color:#f97316;font-weight:700');
      break;
    }

    try {
      await waitForNextQuestion(prevText, root);
      console.log('%c⏭ Câu hỏi mới đã tải', 'color:#10b981;font-weight:700');
    } catch (e) {
      console.warn('⚠ Có thể là câu cuối.', e?.message || e);
      break;
    }

    count++;
  }
  console.log('%c🏁 Hoàn tất vòng lặp.', 'color:#9333ea;font-weight:700');
}

// Expose to window for console users who prefer non-module style
if (typeof window !== 'undefined') {
  window.QuizBot = {
    runQuiz,
    setApiKey,
    setSelectors,
    _STATE: STATE,
    _CONFIG: CONFIG,
  };
}
