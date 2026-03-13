const API_BASE = "http://127.0.0.1:8000";

const totalEvents = document.getElementById("total-events");
const blockedCount = document.getElementById("blocked-count");
const challengedCount = document.getElementById("challenged-count");
const allowedCount = document.getElementById("allowed-count");
const averageRisk = document.getElementById("average-risk");
const decisionBars = document.getElementById("decision-bars");
const blockedList = document.getElementById("blocked-list");
const eventsTable = document.getElementById("events-table");
const liveStatus = document.getElementById("live-status");
const CACHE_KEY = "shieldx-dashboard-cache";


async function refreshDashboard() {
    try {
        const [overviewResponse, blockedResponse] = await Promise.all([
            fetch(`${API_BASE}/dashboard/overview`),
            fetch(`${API_BASE}/blocked-sites`)
        ]);

        if (!overviewResponse.ok || !blockedResponse.ok) {
            throw new Error("Dashboard API request failed");
        }

        const overview = await overviewResponse.json();
        const blocked = await blockedResponse.json();

        renderStats(overview.stats);
        renderDecisionBars(overview.decision_breakdown, overview.stats.total_events);
        renderBlocked(blocked);
        renderEvents(overview.recent_events);
        cacheDashboardSnapshot({
            overview,
            blocked,
            cachedAt: new Date().toISOString()
        });
        liveStatus.textContent = `Live data synced at ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        const cached = getCachedDashboardSnapshot();
        if (cached) {
            renderStats(cached.overview.stats);
            renderDecisionBars(cached.overview.decision_breakdown, cached.overview.stats.total_events);
            renderBlocked(cached.blocked);
            renderEvents(cached.overview.recent_events);
            liveStatus.textContent = `Backend offline. Showing cached data from ${formatTimestamp(cached.cachedAt)}`;
            return;
        }

        liveStatus.textContent = "Backend unavailable";
        decisionBars.innerHTML = `<p class="empty-state">Unable to reach the ShieldX backend and no cached dashboard snapshot is available yet.</p>`;
    }
}


function renderStats(stats) {
    totalEvents.textContent = stats.total_events ?? 0;
    blockedCount.textContent = stats.blocked ?? 0;
    challengedCount.textContent = stats.challenged ?? 0;
    allowedCount.textContent = stats.allowed ?? 0;
    averageRisk.textContent = `Avg risk ${(stats.average_risk || 0).toFixed(3)}`;
}


function renderDecisionBars(items, total) {
    if (!items.length) {
        decisionBars.innerHTML = `<p class="empty-state">No extension traffic has been logged yet.</p>`;
        return;
    }

    decisionBars.innerHTML = items.map((item) => {
        const percent = total ? Math.round((item.count / total) * 100) : 0;
        return `
            <div class="bar-row">
                <span>${item.decision}</span>
                <div class="bar-track">
                    <div class="bar-fill ${getBarClass(item.decision)}" style="width:${percent}%"></div>
                </div>
                <strong>${item.count}</strong>
            </div>
        `;
    }).join("");
}


function renderBlocked(blocked) {
    if (!blocked.length) {
        blockedList.innerHTML = `<p class="empty-state">No blocked websites yet.</p>`;
        return;
    }

    blockedList.innerHTML = blocked.slice(0, 6).map((item) => `
        <article class="stack-item">
            <h3>${escapeHtml(item.url)}</h3>
            <p>${escapeHtml(item.summary || "Blocked by ShieldX")}</p>
            <p class="event-reasons">${escapeHtml((item.reasons || []).join(" | "))}</p>
        </article>
    `).join("");
}


function renderEvents(events) {
    if (!events.length) {
        eventsTable.innerHTML = `<p class="empty-state">No telemetry events yet.</p>`;
        return;
    }

    eventsTable.innerHTML = events.map((event) => `
        <article class="event-row">
            <div class="event-header">
                <div class="event-main">${escapeHtml(event.url)}</div>
                <span class="pill ${getPillClass(event.decision)}">${event.decision}</span>
            </div>
            <div class="event-meta">Risk ${Number(event.risk_score || 0).toFixed(3)} • Severity ${event.severity ?? 0} • ${formatTimestamp(event.created_at)}</div>
            <p class="event-reasons">${escapeHtml(event.summary || "No summary")}</p>
        </article>
    `).join("");
}


function getBarClass(decision) {
    if (decision === "ALLOW") {
        return "allow";
    }
    if (decision === "CHALLENGE") {
        return "challenge";
    }
    return "block";
}


function getPillClass(decision) {
    if (decision === "ALLOW") {
        return "allow";
    }
    if (decision === "CHALLENGE") {
        return "challenge";
    }
    return "block";
}


function formatTimestamp(value) {
    if (!value) {
        return "Unknown time";
    }
    return new Date(value).toLocaleString();
}


function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
}


function cacheDashboardSnapshot(snapshot) {
    localStorage.setItem(CACHE_KEY, JSON.stringify(snapshot));
}


function getCachedDashboardSnapshot() {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) {
        return null;
    }

    try {
        return JSON.parse(raw);
    } catch (error) {
        return null;
    }
}


refreshDashboard();
setInterval(refreshDashboard, 5000);
