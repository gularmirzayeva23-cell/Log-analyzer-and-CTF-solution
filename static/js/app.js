// server/static/js/app.js
console.log("SOC-CTF frontend loaded");

function toast(msg, kind = "info") {
    const area = document.getElementById("toast-area");
    if (!area) return alert(msg);
    const id = "t" + Date.now();
    const cls = kind === "success" ? "text-bg-success" : "text-bg-danger";
    area.insertAdjacentHTML("beforeend", `
    <div id="${id}" class="toast ${cls} border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body">${msg}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>
  `);
    const el = document.getElementById(id);
    const t = new bootstrap.Toast(el, { delay: 3500 });
    t.show();
}

function toggleHint(key) {
    const el = document.getElementById("hint-" + key);
    if (!el) return;
    el.style.display = (el.style.display === "none" || el.style.display === "") ? "block" : "none";
}

function setResult(key, ok, text) {
    const el = document.getElementById("res-" + key);
    if (!el) return;
    el.style.display = "block";
    el.textContent = text;
    el.className = ok ? "answer-result text-success" : "answer-result text-danger";
    const wrap = document.getElementById("qwrap-" + key);
    if (wrap && ok) wrap.classList.add("question-correct");
}

async function submitAnswer(key) {
    const inp = document.getElementById("ans-" + key);
    const nickEl = document.getElementById("global-nickname");
    if (!inp) return;
    const answer = inp.value.trim();
    const nickname = nickEl ? (nickEl.value.trim() || "") : "";
    if (!answer) {
        setResult(key, false, "Enter an answer.");
        return;
    }
    if (!nickname) {
        toast("Write your nickname first.", "danger");
        if (nickEl) nickEl.focus();
        return;
    }
    try {
        const r = await fetch("/api/submit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                question_key: key,
                nickname: nickname,
                answer: answer
            })
        });
        const data = await r.json();
        if (data.ok && data.result === "correct") {
            setResult(key, true, "✔ Correct — added to leaderboard");
            toast("Nice! Correct.", "success");
            inp.setAttribute("disabled", "disabled");
        } else if (data.ok && data.result === "wrong") {
            setResult(key, false, "✖ Wrong — try again.");
        } else {
            toast("Submit error: " + (data.error || "unknown"), "danger");
        }
    } catch (e) {
        console.error(e);
        toast("Network/server error", "danger");
    }
}