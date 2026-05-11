// ===== CONFIG =====
const CONFIG = {
  MODEL: "gemini-flash-latest",
  MAX_RETRIES: 5,
  BASE_BACKOFF_MS: 1200,
};

// ===== STATE =====
const STATE = {
  apiKey: "",
};

// ===== UTILS =====
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ===== Gemini API =====
async function geminiRequest(prompt, system = "", temperature = 0) {
  if (!STATE.apiKey) {
    STATE.apiKey = promptUserApiKey();
    if (!STATE.apiKey) throw new Error("Missing API key");
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${CONFIG.MODEL}:generateContent?key=${STATE.apiKey}`;

  for (let i = 0; i <= CONFIG.MAX_RETRIES; i++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: system
            ? { role: "system", parts: [{ text: system }] }
            : undefined,
          contents: [
            { role: "user", parts: [{ text: prompt }] }
          ],
          generationConfig: { temperature }
        }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const json = await res.json();
      const text =
        json?.candidates?.[0]?.content?.parts?.[0]?.text || "";

      return text.trim();
    } catch (e) {
      console.warn("Retry Gemini:", e.message);
      await sleep(CONFIG.BASE_BACKOFF_MS * (i + 1));
    }
  }

  throw new Error("Gemini failed after retries");
}

// ===== DOM PARSE =====
function getQuestion() {
  return document
    .querySelector(".para-big")
    ?.innerText.trim();
}

function getRadioOptions() {
  const labels = [...document.querySelectorAll("ul.list-block li label")];
  if (!labels.length) return null;

  return labels.map((label) => {
    const li = label.closest("li");
    const input = li?.querySelector("input[type='radio']");
    return {
      text: label.innerText.trim(),
      input,
      li,
    };
  });
}

function getCheckboxOptions() {
  const inputs = [...document.querySelectorAll(
    "ul.list-block li input[type='checkbox']"
  )];

  if (!inputs.length) return null;

  return inputs.map((input) => ({
    input,
    text: input.closest("li")?.innerText.trim() || "",
  }));
}

// ===== PARSE RESPONSE =====
function parseIndex(text, max) {
  try {
    const json = JSON.parse(text);
    return Number(json.index);
  } catch {
    const m = text.match(/\d+/);
    return m ? Number(m[0]) : -1;
  }
}

function parseIndices(text, max) {
  try {
    const json = JSON.parse(text);
    return json.indices || [];
  } catch {
    return (text.match(/\d+/g) || []).map(Number);
  }
}

// ===== ANSWER =====
async function answerQuestion() {
  const question = getQuestion();
  if (!question) return;

  // checkbox (multi)
  const checkboxes = getCheckboxOptions();
  if (checkboxes) {
    const prompt = `
Câu hỏi: ${question}
Options:
${checkboxes.map((o, i) => `${i}. ${o.text}`).join("\n")}

Trả JSON:
{ "indices": [0,1], "reason": "..." }
`;

    const res = await geminiRequest(
      prompt,
      "Many answers possible. Return JSON only."
    );

    const indices = parseIndices(res, checkboxes.length);

    indices.forEach((i) => {
      if (checkboxes[i] && !checkboxes[i].input.checked) {
        checkboxes[i].input.click();
      }
    });

    console.log("✅ Checkbox:", indices);
    return;
  }

  // radio (single)
  const radios = getRadioOptions();
  if (!radios) throw new Error("No options found");

  const prompt = `
Câu hỏi: ${question}
Options:
${radios.map((o, i) => `${i}. ${o.text}`).join("\n")}

Trả JSON:
{ "index": 0, "reason": "..." }
`;

  const res = await geminiRequest(
    prompt,
    "One answer only. Return JSON."
  );

  const index = parseIndex(res, radios.length);

  if (index >= 0 && radios[index]) {
    radios[index].input?.click() || radios[index].li.click();
    console.log("✅ Radio:", index);
  }
}

// ===== NEXT BUTTON =====
function clickNext() {
  const btn = [...document.querySelectorAll("button")]
    .find((b) =>
      (b.innerText || "").toLowerCase().includes("next")
    );

  if (!btn) return false;

  btn.click();
  console.log("➡️ Next");
  return true;
}

// ===== MAIN LOOP =====
async function runQuiz(max = Infinity) {
  let count = 0;

  while (count < max) {
    await answerQuestion();

    await sleep(500);

    if (!clickNext()) break;

    await sleep(1500);
    count++;
  }

  console.log("🏁 Done");
}

// ===== API KEY =====
function promptUserApiKey() {
  return prompt("Enter Gemini API key:");
}

// expose global
window.quizBot = { runQuiz };
