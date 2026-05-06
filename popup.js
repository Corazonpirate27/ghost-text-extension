const toggleSecure = document.getElementById('toggleSecure');
const blockCount = document.getElementById('blockCount');
const statusBadge = document.getElementById('statusBadge');
const logList = document.getElementById('logList');
const resetBtn = document.getElementById('resetBtn');
const clearLogsBtn = document.getElementById('clearLogsBtn');
const exportLogsBtn = document.getElementById('exportLogsBtn');
const customRuleInput = document.getElementById('customRuleInput');
const addRuleBtn = document.getElementById('addRuleBtn');
const customRulesList = document.getElementById('customRulesList');
const siteInput = document.getElementById('siteInput');
const addSiteBtn = document.getElementById('addSiteBtn');
const whitelistList = document.getElementById('whitelistList');
const tipContent = document.getElementById('tipContent');
const nextTipBtn = document.getElementById('nextTipBtn');
const analyticsDiv = document.getElementById('analytics');
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');

const STORAGE_KEYS = {
    enabled: 'enabled',
    blockedCount: 'blockedCount',
    logs: 'eventLogs',
    customRules: 'customRules',
    whitelist: 'whitelist'
};

const SECURITY_TIPS = [
    "Avoid sharing full credit card numbers—use the last 4 digits instead.",
    "Never paste API keys or tokens into chat prompts. Use environment variables.",
    "Use strong, unique passwords and consider a password manager.",
    "Be cautious with personal data like SSNs or phone numbers in AI conversations.",
    "Review logs regularly to spot patterns in your data sharing habits.",
    "Whitelist trusted sites to reduce interruptions on safe platforms.",
    "Custom rules can protect company-specific secrets or codes.",
    "GhostText works on clipboard pastes too—double protection!",
    "Enable notifications for real-time alerts on blocked threats.",
    "Export logs for compliance or personal review."
];

let currentTipIndex = 0;

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString([], { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderStatus(isEnabled) {
    statusBadge.textContent = isEnabled ? 'Active' : 'Paused';
    statusBadge.style.background = isEnabled ? 'rgba(12, 245, 157, 0.12)' : 'rgba(255, 99, 86, 0.18)';
    statusBadge.style.color = isEnabled ? '#b7f9d4' : '#ffc7c2';
    toggleSecure.checked = isEnabled;
}

function renderCount(value) {
    blockCount.textContent = value;
}

function renderLogs(logs) {
    if (!Array.isArray(logs) || logs.length === 0) {
        logList.innerHTML = '<li class="empty">No events blocked yet.</li>';
        return;
    }

    logList.innerHTML = logs.slice(0, 15).map((entry) => {
        const shortThreats = entry.threats.join(', ');
        return `
            <li class="log-item">
                <span>${formatTime(entry.timestamp)} — ${shortThreats}</span>
                <strong>${entry.redacted || 'Sensitive content blocked'}</strong>
            </li>
        `;
    }).join('');
}

function renderCustomRules(rules) {
    customRulesList.innerHTML = rules.map((rule, index) => `
        <li style="display: flex; justify-content: space-between; align-items: center; padding: 8px; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 5px;">
            <span>${rule}</span>
            <button class="button secondary" onclick="removeRule(${index})" style="padding: 4px 8px; font-size: 12px;">Remove</button>
        </li>
    `).join('');
}

function renderAnalytics(logs) {
    if (!Array.isArray(logs) || logs.length === 0) {
        analyticsDiv.innerHTML = '<div class="empty">No data yet.</div>';
        return;
    }

    const threatCounts = {};
    logs.forEach(entry => {
        entry.threats.forEach(threat => {
            threatCounts[threat] = (threatCounts[threat] || 0) + 1;
        });
    });

    const sorted = Object.entries(threatCounts).sort((a, b) => b[1] - a[1]);
    analyticsDiv.innerHTML = sorted.slice(0, 5).map(([threat, count]) => `
        <div style="display: flex; justify-content: space-between; padding: 8px; background: #f8fafc; border-radius: 8px; border: 1px solid #e5e7eb;">
            <span>${threat}</span>
            <strong>${count}</strong>
        </div>
    `).join('');
}

function showTip(index) {
    tipContent.innerHTML = `<p style="margin: 0; font-size: 0.9rem; line-height: 1.5;">${SECURITY_TIPS[index]}</p>`;
}

function nextTip() {
    currentTipIndex = (currentTipIndex + 1) % SECURITY_TIPS.length;
    showTip(currentTipIndex);
}

function loadState() {
    chrome.storage.local.get([STORAGE_KEYS.enabled, STORAGE_KEYS.blockedCount, STORAGE_KEYS.logs, STORAGE_KEYS.customRules, STORAGE_KEYS.whitelist], (data) => {
        renderStatus(data.enabled !== false);
        renderCount(data.blockedCount || 0);
        const logs = data.eventLogs || data[STORAGE_KEYS.logs] || [];
        renderLogs(logs);
        renderAnalytics(logs);
        renderCustomRules(data[STORAGE_KEYS.customRules] || []);
        renderWhitelist(data[STORAGE_KEYS.whitelist] || []);
        showTip(currentTipIndex);
    });
}

function updateEnabled(enabled) {
    chrome.storage.local.set({ [STORAGE_KEYS.enabled]: enabled });
}

function resetCount() {
    chrome.storage.local.set({ [STORAGE_KEYS.blockedCount]: 0 });
    renderCount(0);
}

function clearLogs() {
    chrome.storage.local.set({ [STORAGE_KEYS.logs]: [] });
    renderLogs([]);
}

function exportLogs() {
    chrome.storage.local.get([STORAGE_KEYS.logs], (data) => {
        const logs = data[STORAGE_KEYS.logs] || [];
        const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ghosttext-logs.json';
        a.click();
        URL.revokeObjectURL(url);
    });
}

function addCustomRule() {
    const rule = customRuleInput.value.trim();
    if (!rule) return;

    try {
        new RegExp(rule);
    } catch (e) {
        alert('Invalid regex pattern. Please check your syntax.');
        return;
    }

    chrome.storage.local.get([STORAGE_KEYS.customRules], (data) => {
        const rules = data[STORAGE_KEYS.customRules] || [];
        if (rules.includes(rule)) {
            alert('Rule already exists.');
            return;
        }
        rules.push(rule);
        chrome.storage.local.set({ [STORAGE_KEYS.customRules]: rules });
        renderCustomRules(rules);
        customRuleInput.value = '';
    });
}

function removeRule(index) {
    chrome.storage.local.get([STORAGE_KEYS.customRules], (data) => {
        const rules = data[STORAGE_KEYS.customRules] || [];
        rules.splice(index, 1);
        chrome.storage.local.set({ [STORAGE_KEYS.customRules]: rules });
        renderCustomRules(rules);
    });
}

function addSite() {
    const site = siteInput.value.trim();
    if (!site) return;
    chrome.storage.local.get([STORAGE_KEYS.whitelist], (data) => {
        const sites = data[STORAGE_KEYS.whitelist] || [];
        sites.push(site);
        chrome.storage.local.set({ [STORAGE_KEYS.whitelist]: sites });
        renderWhitelist(sites);
        siteInput.value = '';
    });
}

function removeSite(index) {
    chrome.storage.local.get([STORAGE_KEYS.whitelist], (data) => {
        const sites = data[STORAGE_KEYS.whitelist] || [];
        sites.splice(index, 1);
        chrome.storage.local.set({ [STORAGE_KEYS.whitelist]: sites });
        renderWhitelist(sites);
    });
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab).classList.add('active');
    });
});

if (toggleSecure) {
    toggleSecure.addEventListener('change', () => {
        updateEnabled(toggleSecure.checked);
        renderStatus(toggleSecure.checked);
    });
}

if (resetBtn) resetBtn.addEventListener('click', resetCount);
if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);
if (exportLogsBtn) exportLogsBtn.addEventListener('click', exportLogs);
if (addRuleBtn) addRuleBtn.addEventListener('click', addCustomRule);
if (addSiteBtn) addSiteBtn.addEventListener('click', addSite);
if (nextTipBtn) nextTipBtn.addEventListener('click', nextTip);

chrome.storage.onChanged.addListener((changes) => {
    if (changes[STORAGE_KEYS.enabled]) renderStatus(changes[STORAGE_KEYS.enabled].newValue);
    if (changes[STORAGE_KEYS.blockedCount]) renderCount(changes[STORAGE_KEYS.blockedCount].newValue || 0);
    if (changes[STORAGE_KEYS.logs]) {
        const logs = changes[STORAGE_KEYS.logs].newValue || [];
        renderLogs(logs);
        renderAnalytics(logs);
    }
    if (changes[STORAGE_KEYS.customRules]) renderCustomRules(changes[STORAGE_KEYS.customRules].newValue || []);
    if (changes[STORAGE_KEYS.whitelist]) renderWhitelist(changes[STORAGE_KEYS.whitelist].newValue || []);
});

loadState();

loadState();
