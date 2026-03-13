const BLOCK_OVERLAY_ID = "shieldx-block-overlay";
const CHALLENGE_OVERLAY_ID = "shieldx-challenge-overlay";

let credentialSignalSent = false;
let pageSignalSent = false;
let protectionMode = "idle";
let protectionReason = "ShieldX is verifying this page before allowing credential submission.";
let submitInterceptorsInstalled = false;


chrome.runtime.onMessage.addListener((message) => {
    if (!message?.action) {
        return;
    }

    const payload = message.payload || {};

    if (message.action === "safe") {
        protectionMode = "verified";
        removeOverlay(BLOCK_OVERLAY_ID);
        removeOverlay(CHALLENGE_OVERLAY_ID);
    }

    if (message.action === "block") {
        protectionMode = "block";
        showBlockOverlay(payload);
    }

    if (message.action === "warn") {
        protectionMode = "challenge";
        showChallengeOverlay(payload);
    }
});


function detectCredentialForms() {
    const passwordField = document.querySelector("input[type='password']");
    const creditCardField = document.querySelector(
        "input[autocomplete='cc-number'], input[name*='card' i], input[id*='card' i], input[placeholder*='card' i]"
    );
    const loginForm = document.querySelector(
        "form input[name*='user' i], form input[name*='email' i], form input[autocomplete='username']"
    );

    return Boolean(passwordField || creditCardField || loginForm);
}


function reportCredentialForm() {
    if (credentialSignalSent || !detectCredentialForms()) {
        return;
    }

    ensureSubmissionInterceptors();
    protectionMode = "pending";
    credentialSignalSent = true;
    chrome.runtime.sendMessage({
        action: "credentialFormDetected",
        url: window.location.href,
        pageFlags: collectPageFlags()
    });
}


function collectPageFlags() {
    const flags = [];
    const pageText = document.body?.innerText?.toLowerCase() || "";

    if (
        pageText.includes("demo mode") ||
        pageText.includes("test environment") ||
        pageText.includes("dummy credentials") ||
        pageText.includes("for phishing-detection research")
    ) {
        flags.push("demo_keywords");
    }

    if (
        pageText.includes("test card") ||
        pageText.includes("card number: 4111") ||
        pageText.includes("no real charge occurs")
    ) {
        flags.push("test_card_language");
    }

    if (
        pageText.includes(" admin") ||
        pageText.startsWith("admin") ||
        pageText.includes("admin panel")
    ) {
        flags.push("admin_surface");
    }

    return flags;
}


function reportPageSignals() {
    const pageFlags = collectPageFlags();
    if (pageSignalSent || pageFlags.length === 0) {
        return;
    }

    ensureSubmissionInterceptors();
    protectionMode = "pending";
    pageSignalSent = true;
    chrome.runtime.sendMessage({
        action: "pageSignalsDetected",
        url: window.location.href,
        formDetected: detectCredentialForms(),
        pageFlags
    });
}


function showBlockOverlay(payload) {
    removeOverlay(CHALLENGE_OVERLAY_ID);
    removeOverlay(BLOCK_OVERLAY_ID);

    const overlay = document.createElement("div");
    overlay.id = BLOCK_OVERLAY_ID;
    overlay.style.cssText = baseOverlayStyles("#180707", "#ffddd7");
    overlay.innerHTML = `
        <div style="${cardStyles("#241010", "#ffddd7", "#ff6b57")}">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;">
                <div>
                    <p style="margin:0 0 8px;font-size:12px;letter-spacing:0.18em;text-transform:uppercase;color:#ff8f7d;">ShieldX blocked this page</p>
                    <h1 style="margin:0;font-size:34px;line-height:1.1;">Unsafe website detected</h1>
                </div>
                <div style="padding:10px 14px;border-radius:999px;background:#ff6b57;color:#1b0705;font-weight:700;">BLOCKED</div>
            </div>
            <p style="margin:18px 0 0;font-size:16px;line-height:1.6;color:#ffd2cb;">${escapeHtml(payload.summary || "This page shows strong phishing or impersonation indicators.")}</p>
            ${renderReasons(payload.reasons, "#ffd2cb", "rgba(255,255,255,0.06)")}
            <div style="margin-top:24px;display:flex;gap:12px;flex-wrap:wrap;">
                <button id="shieldx-leave-page" style="${buttonStyles("#ff6b57", "#1b0705")}">Leave This Page</button>
                <button id="shieldx-view-url" style="${buttonStyles("transparent", "#ffddd7", "1px solid rgba(255,221,215,0.28)")}">Show URL</button>
            </div>
            <p id="shieldx-url-copy" style="display:none;margin-top:16px;font-size:13px;color:#ffb7ab;word-break:break-all;">${escapeHtml(window.location.href)}</p>
        </div>
    `;

    document.documentElement.appendChild(overlay);
    document.body.style.overflow = "hidden";

    overlay.querySelector("#shieldx-leave-page").addEventListener("click", () => {
        window.history.back();
    });
    overlay.querySelector("#shieldx-view-url").addEventListener("click", () => {
        const urlCopy = overlay.querySelector("#shieldx-url-copy");
        urlCopy.style.display = "block";
    });
}


function showChallengeOverlay(payload) {
    removeOverlay(CHALLENGE_OVERLAY_ID);
    removeOverlay(BLOCK_OVERLAY_ID);

    const { question, answer } = buildCaptcha();
    const overlay = document.createElement("div");
    overlay.id = CHALLENGE_OVERLAY_ID;
    overlay.style.cssText = baseOverlayStyles("#12100a", "#f9f0cb");
    overlay.innerHTML = `
        <div style="${cardStyles("#1d1a12", "#f9f0cb", "#f4b400")}">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;">
                <div>
                    <p style="margin:0 0 8px;font-size:12px;letter-spacing:0.18em;text-transform:uppercase;color:#ffd560;">ShieldX challenge</p>
                    <h1 style="margin:0;font-size:32px;line-height:1.1;">Verify before continuing</h1>
                </div>
                <div style="padding:10px 14px;border-radius:999px;background:#f4b400;color:#2c2200;font-weight:700;">CAPTCHA</div>
            </div>
            <p style="margin:18px 0 0;font-size:16px;line-height:1.6;color:#f9f0cb;">${escapeHtml(payload.summary || "This site needs an extra verification check.")}</p>
            ${renderReasons(payload.reasons, "#f5e6ab", "rgba(255,255,255,0.05)")}
            <label style="display:block;margin-top:20px;font-size:14px;color:#ffe7a2;">Solve this to continue</label>
            <div style="display:flex;align-items:center;gap:12px;margin-top:10px;flex-wrap:wrap;">
                <div style="min-width:120px;padding:12px 14px;border-radius:14px;background:#2b2416;font-size:20px;font-weight:700;color:#fff0bf;">${question}</div>
                <input id="shieldx-captcha-input" type="text" inputmode="numeric" style="flex:1;min-width:160px;padding:14px 16px;border-radius:14px;border:1px solid rgba(255,255,255,0.16);background:#15120d;color:#fff4d0;font-size:16px;" placeholder="Enter answer" />
            </div>
            <p id="shieldx-captcha-error" style="display:none;margin-top:12px;font-size:13px;color:#ffcc7b;">Incorrect answer. Please try again.</p>
            <div style="margin-top:24px;display:flex;gap:12px;flex-wrap:wrap;">
                <button id="shieldx-verify" style="${buttonStyles("#f4b400", "#2c2200")}">Verify And Continue</button>
                <button id="shieldx-leave" style="${buttonStyles("transparent", "#f9f0cb", "1px solid rgba(249,240,203,0.24)")}">Leave Page</button>
            </div>
        </div>
    `;

    document.documentElement.appendChild(overlay);
    document.body.style.overflow = "hidden";

    overlay.querySelector("#shieldx-verify").addEventListener("click", () => {
        const input = overlay.querySelector("#shieldx-captcha-input");
        const error = overlay.querySelector("#shieldx-captcha-error");
        if (Number(input.value.trim()) === answer) {
            protectionMode = "verified";
            removeOverlay(CHALLENGE_OVERLAY_ID);
            document.body.style.overflow = "";
            return;
        }

        error.style.display = "block";
    });

    overlay.querySelector("#shieldx-leave").addEventListener("click", () => {
        window.history.back();
    });
}


function renderReasons(reasons = [], textColor, backgroundColor) {
    const items = Array.isArray(reasons) ? reasons : [];
    const html = items.map((reason) => `
        <li style="padding:12px 14px;border-radius:14px;background:${backgroundColor};line-height:1.5;color:${textColor};">
            ${escapeHtml(reason)}
        </li>
    `).join("");

    return `
        <ul style="margin:22px 0 0;padding:0;list-style:none;display:grid;gap:10px;">
            ${html}
        </ul>
    `;
}


function baseOverlayStyles(background, color) {
    return `
        position:fixed;
        inset:0;
        z-index:2147483647;
        display:flex;
        align-items:center;
        justify-content:center;
        padding:24px;
        background:radial-gradient(circle at top, rgba(255,255,255,0.08), transparent 40%), ${background};
        color:${color};
        backdrop-filter:blur(6px);
    `;
}


function cardStyles(background, color, borderColor) {
    return `
        width:min(760px, 100%);
        padding:32px;
        border-radius:28px;
        border:1px solid ${borderColor};
        background:${background};
        box-shadow:0 30px 80px rgba(0, 0, 0, 0.45);
        color:${color};
        font-family:Segoe UI, Arial, sans-serif;
    `;
}


function buttonStyles(background, color, border = "none") {
    return `
        padding:14px 18px;
        border-radius:14px;
        border:${border};
        background:${background};
        color:${color};
        font-weight:700;
        cursor:pointer;
    `;
}


function buildCaptcha() {
    const left = Math.floor(Math.random() * 8) + 2;
    const right = Math.floor(Math.random() * 8) + 2;
    return {
        question: `${left} + ${right} = ?`,
        answer: left + right
    };
}


function removeOverlay(id) {
    const element = document.getElementById(id);
    if (element) {
        element.remove();
        document.body.style.overflow = "";
    }
}


function ensureSubmissionInterceptors() {
    if (submitInterceptorsInstalled) {
        return;
    }

    submitInterceptorsInstalled = true;

    document.addEventListener("submit", interceptSubmission, true);
    document.addEventListener("click", interceptSensitiveClick, true);
    document.addEventListener("keydown", interceptEnterSubmit, true);
}


function interceptSubmission(event) {
    if (!shouldBlockSensitiveAction()) {
        return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    notifyProtectionState();
}


function interceptSensitiveClick(event) {
    if (!shouldBlockSensitiveAction()) {
        return;
    }

    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
        return;
    }

    const clickable = target.closest("button, input[type='submit'], input[type='button'], a");
    if (!clickable) {
        return;
    }

    if (clickable.matches("a")) {
        return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    notifyProtectionState();
}


function interceptEnterSubmit(event) {
    if (!shouldBlockSensitiveAction()) {
        return;
    }

    if (event.key !== "Enter") {
        return;
    }

    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
        return;
    }

    if (!target.closest("form")) {
        return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    notifyProtectionState();
}


function shouldBlockSensitiveAction() {
    return protectionMode === "pending" || protectionMode === "challenge" || protectionMode === "block";
}


function notifyProtectionState() {
    if (protectionMode === "block") {
        return;
    }

    if (protectionMode === "challenge") {
        const existingOverlay = document.getElementById(CHALLENGE_OVERLAY_ID);
        if (existingOverlay) {
            return;
        }

        showChallengeOverlay({
            summary: "ShieldX requires verification before allowing this submission.",
            reasons: [protectionReason]
        });
        return;
    }

    if (protectionMode === "pending") {
        showChallengeOverlay({
            summary: "ShieldX is still analyzing this page. Submission is paused for safety.",
            reasons: [protectionReason]
        });
        protectionMode = "challenge";
    }
}


function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
}


if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reportCredentialForm, { once: true });
    document.addEventListener("DOMContentLoaded", reportPageSignals, { once: true });
} else {
    reportCredentialForm();
    reportPageSignals();
}


const observer = new MutationObserver(() => {
    reportCredentialForm();
    reportPageSignals();
    if (credentialSignalSent) {
        if (pageSignalSent) {
            observer.disconnect();
        }
    }
});

observer.observe(document.documentElement, {
    childList: true,
    subtree: true
});
