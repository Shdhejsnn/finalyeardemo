const API_URL = "http://127.0.0.1:8000/analyze-url";
const TAB_STATE_PREFIX = "shieldx:tab:";
const HISTORY_KEY = "shieldx:event-history";
const tabAnalysisContext = new Map();


async function analyzeTab(tabId, url, formDetected = false, pageFlags = []) {
    if (!url || !/^https?:/i.test(url)) {
        return;
    }

    const context = getOrCreateTabContext(tabId, url);
    if (context.url !== url) {
        resetTabContext(tabId, url);
    }

    const activeContext = getOrCreateTabContext(tabId, url);
    activeContext.url = url;
    activeContext.formDetected = activeContext.formDetected || formDetected;
    activeContext.pageFlags = mergePageFlags(activeContext.pageFlags, pageFlags);
    activeContext.requestId += 1;
    const requestId = activeContext.requestId;

    if (isLocalDevelopmentUrl(url)) {
        const state = {
            decision: "ALLOW",
            risk_score: 0,
            severity: 0,
            summary: "Local development traffic was allowed automatically.",
            reasons: ["ShieldX bypasses localhost and private development ports that are currently in use."],
            captcha_required: false,
            url,
            formDetected: activeContext.formDetected,
            pageFlags: activeContext.pageFlags,
            checkedAt: new Date().toISOString()
        };
        await commitTabState(tabId, state, requestId);
        return;
    }

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url,
                form_detected: activeContext.formDetected,
                source: "extension-auto",
                page_flags: activeContext.pageFlags
            })
        });

        if (!response.ok) {
            throw new Error(`ShieldX API returned ${response.status}`);
        }

        const data = await response.json();
        const state = {
            ...data,
            url,
            formDetected: activeContext.formDetected,
            pageFlags: activeContext.pageFlags,
            checkedAt: new Date().toISOString()
        };

        await commitTabState(tabId, state, requestId);
    } catch (error) {
        console.error("ShieldX error:", error);
        const state = {
            decision: "ERROR",
            risk_score: 0,
            severity: 0,
            summary: "ShieldX could not analyze this page.",
            reasons: ["The backend did not respond successfully."],
            captcha_required: false,
            url,
            pageFlags: activeContext.pageFlags,
            checkedAt: new Date().toISOString()
        };
        await commitTabState(tabId, state, requestId);
    }
}


async function persistTabState(tabId, state) {
    await chrome.storage.local.set({
        [`${TAB_STATE_PREFIX}${tabId}`]: state
    });
}


async function getTabState(tabId) {
    const key = `${TAB_STATE_PREFIX}${tabId}`;
    const stored = await chrome.storage.local.get(key);
    return stored[key] || null;
}


async function appendHistory(state) {
    const stored = await chrome.storage.local.get(HISTORY_KEY);
    const history = Array.isArray(stored[HISTORY_KEY]) ? stored[HISTORY_KEY] : [];
    history.unshift(state);
    await chrome.storage.local.set({
        [HISTORY_KEY]: history.slice(0, 250)
    });
}


async function commitTabState(tabId, state, requestId) {
    const context = tabAnalysisContext.get(tabId);
    if (!context || requestId !== context.requestId) {
        return;
    }

    await persistTabState(tabId, state);
    await appendHistory(state);
    await updateBadge(tabId, state);
    await notifyContentScript(tabId, state);
}


async function notifyContentScript(tabId, state) {
    const action = state.decision === "BLOCK"
        ? "block"
        : state.decision === "CHALLENGE"
            ? "warn"
            : "safe";

    try {
        await chrome.tabs.sendMessage(tabId, {
            action,
            payload: state
        });
    } catch (error) {
        // Ignore pages where content scripts are unavailable.
    }
}


async function updateBadge(tabId, state) {
    const badgeConfig = getBadgeConfig(state.decision);
    await chrome.action.setBadgeText({
        tabId,
        text: badgeConfig.text
    });
    await chrome.action.setBadgeBackgroundColor({
        tabId,
        color: badgeConfig.color
    });
    await chrome.action.setTitle({
        tabId,
        title: `ShieldX: ${badgeConfig.label}`
    });
}


function getBadgeConfig(decision) {
    switch (decision) {
        case "ALLOW":
            return { text: "SAFE", color: "#0f9d58", label: "Safe" };
        case "CHALLENGE":
            return { text: "WARN", color: "#f4b400", label: "Captcha required" };
        case "BLOCK":
            return { text: "BLOCK", color: "#db4437", label: "Blocked" };
        default:
            return { text: "ERR", color: "#5f6368", label: "Analysis unavailable" };
    }
}


function isLocalDevelopmentUrl(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();

        if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]") {
            return true;
        }
        if (hostname.endsWith(".local")) {
            return true;
        }
        if (hostname.startsWith("192.168.") || hostname.startsWith("10.")) {
            return true;
        }
        if (hostname.startsWith("172.")) {
            const secondOctet = Number(hostname.split(".")[1]);
            return secondOctet >= 16 && secondOctet <= 31;
        }
    } catch (error) {
        return false;
    }

    return false;
}


function getOrCreateTabContext(tabId, url = "") {
    if (!tabAnalysisContext.has(tabId)) {
        tabAnalysisContext.set(tabId, {
            url,
            requestId: 0,
            formDetected: false,
            pageFlags: []
        });
    }

    return tabAnalysisContext.get(tabId);
}


function resetTabContext(tabId, url) {
    tabAnalysisContext.set(tabId, {
        url,
        requestId: 0,
        formDetected: false,
        pageFlags: []
    });
}


function mergePageFlags(existingFlags, nextFlags) {
    return [...new Set([...(existingFlags || []), ...(nextFlags || [])])];
}


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        resetTabContext(tabId, tab.url);
        await analyzeTab(tabId, tab.url, false);
    }
});


chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    const state = await getTabState(tabId);
    if (state) {
        await updateBadge(tabId, state);
    }
});


chrome.tabs.onRemoved.addListener(async (tabId) => {
    tabAnalysisContext.delete(tabId);
    await chrome.storage.local.remove(`${TAB_STATE_PREFIX}${tabId}`);
});


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.action === "credentialFormDetected") {
        const tabId = sender.tab?.id;
        const tabUrl = sender.tab?.url || message.url;
        if (tabId === undefined || !tabUrl) {
            return;
        }

        analyzeTab(tabId, tabUrl, true, message.pageFlags || []);
        return;
    }

    if (message?.action === "pageSignalsDetected") {
        const tabId = sender.tab?.id;
        const tabUrl = sender.tab?.url || message.url;
        if (tabId === undefined || !tabUrl) {
            return;
        }

        analyzeTab(tabId, tabUrl, Boolean(message.formDetected), message.pageFlags || []);
        return;
    }

    if (message?.action === "getTabState") {
        chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
            if (!tab?.id) {
                sendResponse(null);
                return;
            }

            const state = await getTabState(tab.id);
            sendResponse(state);
        });
        return true;
    }

    if (message?.action === "getHistory") {
        chrome.storage.local.get(HISTORY_KEY).then((stored) => {
            sendResponse(stored[HISTORY_KEY] || []);
        });
        return true;
    }
});
