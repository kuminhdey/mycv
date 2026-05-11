async function askAI(question, options, apiKey, multi = false) {
  const prompt = `
Bạn là trợ lý làm trắc nghiệm.
${multi ? "Có thể có nhiều đáp án đúng." : "Chỉ chọn 1 đáp án đúng nhất."}

Câu hỏi: ${question}

Các lựa chọn:
${options.map((o, i) => `${i}. ${o}`).join("\n")}

Chỉ trả về JSON:
${multi 
  ? '{"indices":[<number>], "reason":"..."}' 
  : '{"index":<number>, "reason":"..."}'}
`;

  const res = await fetch(
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=" + apiKey,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }]
      })
    }
  );

  const data = await res.json();
  const text =
    data?.candidates?.[0]?.content?.parts?.map(p => p.text).join("") || "";

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// lấy câu hỏi + đáp án
function getQuizData(root = document) {
  const question = root.querySelector(".para-big")?.innerText?.trim() || "";

  const checkboxes = [...root.querySelectorAll('input[type="checkbox"]')];
  if (checkboxes.length) {
    return {
      type: "multi",
      question,
      options: checkboxes.map(el =>
        el.closest("li")?.innerText.trim()
      ),
      elements: checkboxes
    };
  }

  const radios = [...root.querySelectorAll('input[type="radio"]')];
  return {
    type: "single",
    question,
    options: radios.map(el =>
      el.closest("li")?.innerText.trim()
    ),
    elements: radios
  };
}

// chọn đáp án
function selectAnswer(data, result) {
  if (!result) return;

  if (data.type === "multi" && result.indices) {
    result.indices.forEach(i => {
      data.elements[i]?.click();
    });
  } else if (data.type === "single" && result.index >= 0) {
    data.elements[result.index]?.click();
  }
}

// click next
function clickNext(root = document) {
  const btn = [...root.querySelectorAll("button")]
    .find(b => b.innerText.toLowerCase().includes("next"));
  if (btn) btn.click();
  return !!btn;
}

// main loop
async function runQuiz({ apiKey, max = Infinity }) {
  let count = 0;

  while (count < max) {
    const data = getQuizData();

    if (!data.question || !data.options.length) {
      console.log("Không tìm thấy câu hỏi");
      break;
    }

    console.log("Câu hỏi:", data.question);

    const result = await askAI(
      data.question,
      data.options,
      apiKey,
      data.type === "multi"
    );

    selectAnswer(data, result);

    await new Promise(r => setTimeout(r, 500));

    if (!clickNext()) {
      console.log("Hết câu hỏi");
      break;
    }

    await new Promise(r => setTimeout(r, 1000));
    count++;
  }
}
