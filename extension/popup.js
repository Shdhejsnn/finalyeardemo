const verdictPill = document.getElementById("verdict-pill");
const riskScore = document.getElementById("risk-score");
const severityScore = document.getElementById("severity-score");
const siteUrl = document.getElementById("site-url");
const summary = document.getElementById("summary");
const checkedAt = document.getElementById("checked-at");
const reasonsList = document.getElementById("reasons-list");


chrome.runtime.sendMessage({ action: "getTabState" }, (state) => {
    renderState(state);
});


function renderState(state) {
    if (!state) {
        verdictPill.textContent = "Waiting";
        verdictPill.className = "verdict-pill neutral";
        summary.textContent = "Open or refresh a website to let ShieldX analyze it.";
        return;
    }

    siteUrl.textContent = state.url || "Unknown tab";
    riskScore.textContent = Number(state.risk_score || 0).toFixed(3);
    severityScore.textContent = state.severity ?? 0;
    summary.textContent = state.summary || "No summary available.";
    checkedAt.textContent = `Last checked: ${formatTime(state.checkedAt)}`;

    const variant = getVariant(state.decision);
    verdictPill.textContent = state.decision || "UNKNOWN";
    verdictPill.className = `verdict-pill ${variant}`;

    reasonsList.innerHTML = "";
    const reasons = Array.isArray(state.reasons) && state.reasons.length > 0
        ? state.reasons
        : ["No detailed reasons were returned."];

    reasons.forEach((reason) => {
        const item = document.createElement("li");
        item.className = "reason-item";
        item.textContent = reason;
        reasonsList.appendChild(item);
    });
}


function getVariant(decision) {
    if (decision === "ALLOW") {
        return "allow";
    }
    if (decision === "CHALLENGE") {
        return "challenge";
    }
    if (decision === "BLOCK") {
        return "block";
    }
    return "neutral";
}


function formatTime(value) {
    if (!value) {
        return "waiting";
    }

    return new Date(value).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}
