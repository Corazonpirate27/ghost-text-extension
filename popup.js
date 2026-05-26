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
const trustedSiteInput = document.getElementById('trustedSiteInput');
const addTrustedSiteBtn = document.getElementById('addTrustedSiteBtn');
const trustedSitesList = document.getElementById('trustedSitesList');
const tipContent = document.getElementById('tipContent');
const nextTipBtn = document.getElementById('nextTipBtn');
const analyticsDiv = document.getElementById('analytics');
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const toggleMonitor = document.getElementById('toggleMonitor');
const toggleRiskPopups = document.getElementById('toggleRiskPopups');
const toggleBadgeAlerts = document.getElementById('toggleBadgeAlerts');
const monitorHistoryList = document.getElementById('monitorHistoryList');
const clearMonitorHistoryBtn = document.getElementById('clearMonitorHistoryBtn');
const exportMonitorHistoryBtn = document.getElementById('exportMonitorHistoryBtn');
const adBlockPowerBtn = document.getElementById('adBlockPowerBtn');
const toggleAdBlock = document.getElementById('toggleAdBlock');
const toggleCosmeticBlock = document.getElementById('toggleCosmeticBlock');
const adBlockTotalBlocked = document.getElementById('adBlockTotalBlocked');
const adBlockTabBlocked = document.getElementById('adBlockTabBlocked');
const adBlockTotalBlockedSummary = document.getElementById('adBlockTotalBlockedSummary');
const adBlockTabBlockedSummary = document.getElementById('adBlockTabBlockedSummary');
const adBlockTopDomains = document.getElementById('adBlockTopDomains');
const resetAdBlockStatsBtn = document.getElementById('resetAdBlockStatsBtn');
const threatTextInput = document.getElementById('threatTextInput');
const threatRiskLevel = document.getElementById('threatRiskLevel');
const threatScoreText = document.getElementById('threatScoreText');
const threatFlagCount = document.getElementById('threatFlagCount');
const threatUrlList = document.getElementById('threatUrlList');
const threatRecommendation = document.getElementById('threatRecommendation');
const threatFlagList = document.getElementById('threatFlagList');
const clearThreatInputBtn = document.getElementById('clearThreatInputBtn');
const loadThreatSampleBtn = document.getElementById('loadThreatSampleBtn');
const recommendationsList = document.getElementById('recommendationsList');
const applyRecommendedBtn = document.getElementById('applyRecommendedBtn');

// Network Tab Elements
const netIp = document.getElementById('netIp');
const netLocation = document.getElementById('netLocation');
const netIsp = document.getElementById('netIsp');
const netType = document.getElementById('netType');
const netAsn = document.getElementById('netAsn');
const netTimezone = document.getElementById('netTimezone');
const netPrivacy = document.getElementById('netPrivacy');
const netCoordinates = document.getElementById('netCoordinates');
const netProvider = document.getElementById('netProvider');
const refreshNetBtn = document.getElementById('refreshNetBtn');
const liveTrafficList = document.getElementById('liveTrafficList');

// Scanner & Panic Elements
const scannerDomain = document.getElementById('scannerDomain');
const scannerStatus = document.getElementById('scannerStatus');
const trustScoreCircle = document.getElementById('trustScoreCircle');
const trackerCount = document.getElementById('trackerCount');
const trackerList = document.getElementById('trackerList');
const scannerInput = document.getElementById('scannerInput');
const scanBtn = document.getElementById('scanBtn');
const scannerDetails = document.getElementById('scannerDetails');
const trustScannedSiteBtn = document.getElementById('trustScannedSiteBtn');
const panicBtn = document.getElementById('panicBtn');
const themeToggle = document.getElementById('themeToggle');

const STORAGE_KEYS = {
    enabled: 'enabled',
    blockedCount: 'blockedCount',
    logs: 'eventLogs',
    customRules: 'customRules',
    whitelist: 'whitelist',
    trustedSites: 'trustedSites',
    monitorSettings: 'monitorSettings',
    monitorHistory: 'monitorHistory',
    adBlockSettings: 'adBlockSettings'
};

const DEFAULT_MONITOR_SETTINGS = {
    continuous: true,
    popups: true,
    badges: true
};

const DEFAULT_AD_BLOCK_SETTINGS = {
    enabled: true,
    cosmetic: true
};

const KNOWN_TRUSTED_SCAN_DOMAINS = [
    'google.com',
    'gmail.com',
    'accounts.google.com',
    'mail.google.com',
    'microsoft.com',
    'live.com',
    'office.com',
    'apple.com',
    'paypal.com',
    'facebook.com',
    'instagram.com',
    'linkedin.com',
    'amazon.com',
    'netflix.com'
];

const SECURITY_TIPS = [
    "Avoid sharing full credit card numbers—use the last 4 digits instead.",
    "Never paste API keys or tokens into chat prompts. Use environment variables.",
    "Use strong, unique passwords and consider a password manager.",
    "Be cautious with personal data like SSNs or phone numbers in AI conversations.",
    "Review logs regularly to spot patterns in your data sharing habits.",
    "Whitelist trusted sites to reduce interruptions on safe platforms.",
    "Custom rules can protect company-specific secrets or codes.",
    "Ghost Guard checks clipboard pastes too.",
    "Enable notifications for real-time alerts on blocked threats.",
    "Export logs for compliance or personal review."
];

let currentTipIndex = 0;
let currentDashboardState = {};
const THREAT_SAMPLE_INPUT = `Your account suspended notice requires you to verify now.
Login required: http://paypa1.com/secure/account/update
Backup link: https://bit.ly/reset-paypal`;

function applyTheme(theme) {
    const selectedTheme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = selectedTheme;
    localStorage.setItem('ghostGuardTheme', selectedTheme);
    if (themeToggle) {
        themeToggle.textContent = selectedTheme === 'dark' ? 'Light' : 'Dark';
        themeToggle.setAttribute('aria-label', `Switch to ${themeToggle.textContent} mode`);
    }
}

function toggleTheme() {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString([], { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderStatus(isEnabled) {
    statusBadge.textContent = isEnabled ? 'Active' : 'Paused';
    statusBadge.className = `status-pill ${isEnabled ? 'is-active' : 'is-paused'}`;
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

function renderWhitelist(sites) {
    whitelistList.innerHTML = sites.map((site, index) => `
        <li style="display: flex; justify-content: space-between; align-items: center; padding: 8px; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 5px;">
            <span>${site}</span>
            <button class="button secondary" onclick="removeSite(${index})" style="padding: 4px 8px; font-size: 12px;">Remove</button>
        </li>
    `).join('');
}

function renderTrustedSites(sites) {
    trustedSitesList.innerHTML = sites.map((site, index) => `
        <li style="display: flex; justify-content: space-between; align-items: center; padding: 8px; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 5px;">
            <span>${escapeHtml(site)}</span>
            <button class="button secondary" onclick="removeTrustedSite(${index})" style="padding: 4px 8px; font-size: 12px;">Remove</button>
        </li>
    `).join('');
}

function renderMonitorSettings(settings = {}) {
    const merged = { ...DEFAULT_MONITOR_SETTINGS, ...settings };
    if (toggleMonitor) toggleMonitor.checked = merged.continuous !== false;
    if (toggleRiskPopups) toggleRiskPopups.checked = merged.popups !== false;
    if (toggleBadgeAlerts) toggleBadgeAlerts.checked = merged.badges !== false;
}

function renderAdBlockSettings(settings = {}) {
    const merged = { ...DEFAULT_AD_BLOCK_SETTINGS, ...settings };
    if (toggleAdBlock) toggleAdBlock.checked = merged.enabled !== false;
    if (toggleCosmeticBlock) toggleCosmeticBlock.checked = merged.cosmetic !== false;
    if (adBlockPowerBtn) {
        const isFullyOn = merged.enabled !== false && merged.cosmetic !== false;
        adBlockPowerBtn.textContent = isFullyOn ? 'Ad Block On' : 'Ad Block Off';
        adBlockPowerBtn.className = `button ${isFullyOn ? 'primary' : 'secondary'}`;
        adBlockPowerBtn.setAttribute('aria-pressed', String(isFullyOn));
    }
}

function renderMonitorHistory(history = []) {
    if (!monitorHistoryList) return;
    if (!Array.isArray(history) || history.length === 0) {
        monitorHistoryList.innerHTML = '<li class="empty">No monitored sites yet.</li>';
        return;
    }

    monitorHistoryList.innerHTML = history.slice(0, 60).map((entry) => {
        const level = entry.riskLevel || 'safe';
        const color = level === 'danger' ? '#ef4444' : level === 'warning' ? '#f59e0b' : '#10b981';
        const score = Math.round(Number(entry.score || 0));
        const issues = (entry.issues || []).slice(0, 2).join(' - ') || entry.verdict || 'No issues';
        return `
            <li class="history-item">
                <span class="history-score" style="border-color: ${color}; color: ${color};">${score}</span>
                <span class="history-meta">
                    <strong>${escapeHtml(entry.domain || 'Unknown')}</strong>
                    <span>${escapeHtml(formatTime(entry.timestamp))} - ${escapeHtml(issues)}</span>
                </span>
                <span class="status-chip" style="background: ${color}1f; color: ${color};">${escapeHtml(level)}</span>
            </li>
        `;
    }).join('');
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

function getDashboardState(data = {}) {
    return {
        enabled: data[STORAGE_KEYS.enabled] !== false,
        logs: data.eventLogs || data[STORAGE_KEYS.logs] || [],
        customRules: data[STORAGE_KEYS.customRules] || [],
        whitelist: data[STORAGE_KEYS.whitelist] || [],
        trustedSites: data[STORAGE_KEYS.trustedSites] || [],
        monitorSettings: { ...DEFAULT_MONITOR_SETTINGS, ...(data[STORAGE_KEYS.monitorSettings] || {}) },
        monitorHistory: data[STORAGE_KEYS.monitorHistory] || [],
        adBlockSettings: { ...DEFAULT_AD_BLOCK_SETTINGS, ...(data[STORAGE_KEYS.adBlockSettings] || {}) }
    };
}

function renderRecommendations(state = currentDashboardState) {
    if (!recommendationsList) return;

    const items = [];
    const logs = Array.isArray(state.logs) ? state.logs : [];
    const history = Array.isArray(state.monitorHistory) ? state.monitorHistory : [];
    const rules = Array.isArray(state.customRules) ? state.customRules : [];
    const monitor = { ...DEFAULT_MONITOR_SETTINGS, ...(state.monitorSettings || {}) };
    const adBlock = { ...DEFAULT_AD_BLOCK_SETTINGS, ...(state.adBlockSettings || {}) };
    const recentRisk = history.find((entry) => ['danger', 'warning'].includes(entry.riskLevel));

    if (!state.enabled) {
        items.push({
            level: 'danger',
            title: 'Turn defense back on',
            detail: 'Private text checks are paused, so sensitive data can pass through without warning.'
        });
    }

    if (!monitor.continuous || !monitor.popups || !monitor.badges) {
        items.push({
            level: 'warning',
            title: 'Use full monitor coverage',
            detail: 'Enable continuous scans, risk popups, and badge alerts for faster page-level warnings.'
        });
    }

    if (!adBlock.enabled || !adBlock.cosmetic) {
        items.push({
            level: 'warning',
            title: 'Enable both ad-block layers',
            detail: 'Network blocking stops common ad requests; cosmetic hiding cleans up sponsored page slots.'
        });
    }

    if (rules.length === 0) {
        items.push({
            level: 'safe',
            title: 'Add one personal secret rule',
            detail: 'Create a custom regex for project codes, internal IDs, private keywords, or token formats you use.'
        });
    }

    if (recentRisk) {
        items.push({
            level: recentRisk.riskLevel === 'danger' ? 'danger' : 'warning',
            title: `Review ${recentRisk.domain || 'recent risky site'}`,
            detail: `${recentRisk.verdict || 'A monitored page raised a warning'}. Open Monitor History before trusting it.`
        });
    }

    if (logs.length >= 10) {
        items.push({
            level: 'safe',
            title: 'Export or clear older logs',
            detail: 'You have a useful local audit trail now. Export it if needed, then clear stale records.'
        });
    }

    if (items.length === 0) {
        items.push({
            level: 'safe',
            title: 'Protection setup looks strong',
            detail: 'Core defense, monitoring, alerts, and ad-block settings are all active.'
        });
    }

    recommendationsList.innerHTML = items.slice(0, 5).map((item) => `
        <li class="recommendation-item ${escapeHtml(item.level)}">
            <span class="recommendation-dot"></span>
            <span>
                <strong>${escapeHtml(item.title)}</strong>
                <span>${escapeHtml(item.detail)}</span>
            </span>
        </li>
    `).join('');
}

function renderThreatAnalysis(text) {
    if (!threatRiskLevel || !window.GhostTextThreatAnalyzer) return;

    const result = window.GhostTextThreatAnalyzer.analyzeThreatText(text || '');
    const suspiciousUrls = window.GhostTextThreatAnalyzer.extractUrls(text || '').filter((entry) => {
        return window.GhostTextThreatAnalyzer.analyzeUrl(entry).length > 0;
    });

    threatRiskLevel.textContent = result.riskLevel;
    threatRiskLevel.className = `threat-risk ${result.riskLevel}`;
    threatScoreText.textContent = `Score ${result.score}`;
    threatFlagCount.textContent = result.flags.length;
    threatRecommendation.textContent = result.recommendation;

    threatUrlList.innerHTML = suspiciousUrls.length
        ? suspiciousUrls.map((entry) => `<li>${escapeHtml(entry.url)}</li>`).join('')
        : '<li>No suspicious URLs detected.</li>';

    threatFlagList.innerHTML = result.flags.length
        ? result.flags.slice(0, 12).map((flag) => `
            <li>
                <strong>${escapeHtml(flag.type.replace(/_/g, ' '))}</strong><br>
                ${escapeHtml(flag.message)}<br>
                <span style="color: #6b7280;">${escapeHtml(flag.value)}</span>
            </li>
        `).join('')
        : '<li>No red flags detected.</li>';
}

function showTip(index) {
    tipContent.innerHTML = `<p style="margin: 0; font-size: 0.9rem; line-height: 1.5;">${SECURITY_TIPS[index]}</p>`;
}

function nextTip() {
    currentTipIndex = (currentTipIndex + 1) % SECURITY_TIPS.length;
    showTip(currentTipIndex);
}

function loadState() {
    chrome.storage.local.get([
        STORAGE_KEYS.enabled,
        STORAGE_KEYS.blockedCount,
        STORAGE_KEYS.logs,
        STORAGE_KEYS.customRules,
        STORAGE_KEYS.whitelist,
        STORAGE_KEYS.trustedSites,
        STORAGE_KEYS.monitorSettings,
        STORAGE_KEYS.monitorHistory,
        STORAGE_KEYS.adBlockSettings
    ], (data) => {
        currentDashboardState = getDashboardState(data);
        renderStatus(data.enabled !== false);
        renderCount(data.blockedCount || 0);
        const logs = data.eventLogs || data[STORAGE_KEYS.logs] || [];
        renderLogs(logs);
        renderAnalytics(logs);
        renderCustomRules(data[STORAGE_KEYS.customRules] || []);
        renderWhitelist(data[STORAGE_KEYS.whitelist] || []);
        renderTrustedSites(data[STORAGE_KEYS.trustedSites] || []);
        renderMonitorSettings(data[STORAGE_KEYS.monitorSettings]);
        renderMonitorHistory(data[STORAGE_KEYS.monitorHistory] || []);
        renderAdBlockSettings(data[STORAGE_KEYS.adBlockSettings]);
        renderRecommendations(currentDashboardState);
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
        a.download = 'ghost-guard-logs.json';
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

function normalizeDomain(value) {
    const input = String(value || '').trim().toLowerCase();
    if (!input) return '';

    try {
        const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`);
        return url.hostname.replace(/^www\./, '');
    } catch (error) {
        return input.replace(/^www\./, '').split('/')[0];
    }
}

function addTrustedSite(domainValue) {
    const site = normalizeDomain(domainValue || (trustedSiteInput && trustedSiteInput.value));
    if (!site) return;

    chrome.storage.local.get([STORAGE_KEYS.trustedSites], (data) => {
        const sites = data[STORAGE_KEYS.trustedSites] || [];
        if (!sites.includes(site)) sites.push(site);
        chrome.storage.local.set({ [STORAGE_KEYS.trustedSites]: sites });
        renderTrustedSites(sites);
        if (trustedSiteInput) trustedSiteInput.value = '';
    });
}

function removeTrustedSite(index) {
    chrome.storage.local.get([STORAGE_KEYS.trustedSites], (data) => {
        const sites = data[STORAGE_KEYS.trustedSites] || [];
        sites.splice(index, 1);
        chrome.storage.local.set({ [STORAGE_KEYS.trustedSites]: sites });
        renderTrustedSites(sites);
    });
}

function updateMonitorSetting(key, value) {
    chrome.storage.local.get([STORAGE_KEYS.monitorSettings], (data) => {
        const settings = { ...DEFAULT_MONITOR_SETTINGS, ...(data[STORAGE_KEYS.monitorSettings] || {}) };
        settings[key] = value;
        chrome.storage.local.set({ [STORAGE_KEYS.monitorSettings]: settings });
        renderMonitorSettings(settings);
    });
}

function loadMonitorHistory() {
    chrome.runtime.sendMessage({ type: 'GET_MONITOR_HISTORY' }, (response) => {
        if (chrome.runtime.lastError) return;
        renderMonitorHistory((response && response.history) || []);
    });
}

function clearMonitorHistory() {
    chrome.runtime.sendMessage({ type: 'CLEAR_MONITOR_HISTORY' }, (response) => {
        renderMonitorHistory((response && response.history) || []);
    });
}

function exportMonitorHistory() {
    chrome.storage.local.get([STORAGE_KEYS.monitorHistory], (data) => {
        const history = data[STORAGE_KEYS.monitorHistory] || [];
        const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ghost-guard-monitor-history.json';
        a.click();
        URL.revokeObjectURL(url);
    });
}

function loadAdBlockSettings() {
    chrome.runtime.sendMessage({ type: 'GET_AD_BLOCK_SETTINGS' }, (response) => {
        if (chrome.runtime.lastError) return;
        renderAdBlockSettings(response && response.settings);
    });
    refreshAdBlockStats();
}

function updateAdBlockSetting(key, value) {
    chrome.storage.local.get([STORAGE_KEYS.adBlockSettings], (data) => {
        const settings = { ...DEFAULT_AD_BLOCK_SETTINGS, ...(data[STORAGE_KEYS.adBlockSettings] || {}) };
        settings[key] = value;
        chrome.runtime.sendMessage({ type: 'UPDATE_AD_BLOCK_SETTINGS', settings }, (response) => {
            if (chrome.runtime.lastError) {
                chrome.storage.local.set({ [STORAGE_KEYS.adBlockSettings]: settings });
                renderAdBlockSettings(settings);
                return;
            }
            renderAdBlockSettings((response && response.settings) || settings);
        });
    });
}

function setAdBlockSettings(settings) {
    const nextSettings = { ...DEFAULT_AD_BLOCK_SETTINGS, ...settings };
    chrome.runtime.sendMessage({ type: 'UPDATE_AD_BLOCK_SETTINGS', settings: nextSettings }, (response) => {
        if (chrome.runtime.lastError) {
            chrome.storage.local.set({ [STORAGE_KEYS.adBlockSettings]: nextSettings });
            renderAdBlockSettings(nextSettings);
            return;
        }
        renderAdBlockSettings((response && response.settings) || nextSettings);
    });
}

function toggleAdBlockPower() {
    chrome.storage.local.get([STORAGE_KEYS.adBlockSettings], (data) => {
        const settings = { ...DEFAULT_AD_BLOCK_SETTINGS, ...(data[STORAGE_KEYS.adBlockSettings] || {}) };
        const isFullyOn = settings.enabled !== false && settings.cosmetic !== false;
        setAdBlockSettings({
            enabled: !isFullyOn,
            cosmetic: !isFullyOn
        });
    });
}

function applyRecommendedSettings() {
    const recommendedMonitorSettings = { ...DEFAULT_MONITOR_SETTINGS };
    const recommendedAdBlockSettings = { ...DEFAULT_AD_BLOCK_SETTINGS };
    const updates = {
        [STORAGE_KEYS.enabled]: true,
        [STORAGE_KEYS.monitorSettings]: recommendedMonitorSettings,
        [STORAGE_KEYS.adBlockSettings]: recommendedAdBlockSettings
    };

    chrome.storage.local.set(updates, () => {
        renderStatus(true);
        renderMonitorSettings(recommendedMonitorSettings);
        renderAdBlockSettings(recommendedAdBlockSettings);
        currentDashboardState = {
            ...currentDashboardState,
            enabled: true,
            monitorSettings: recommendedMonitorSettings,
            adBlockSettings: recommendedAdBlockSettings
        };
        renderRecommendations(currentDashboardState);
    });

    chrome.runtime.sendMessage({
        type: 'UPDATE_AD_BLOCK_SETTINGS',
        settings: recommendedAdBlockSettings
    }, () => {
        // The storage write above keeps the UI responsive if the background worker is sleeping.
    });
}

function getActiveTabId() {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const tab = tabs[0];
            if (!tab || typeof tab.id !== 'number' || !/^https?:\/\//i.test(tab.url || '')) {
                resolve(null);
                return;
            }
            resolve(tab.id);
        });
    });
}

async function refreshAdBlockStats() {
    const tabId = await getActiveTabId();
    chrome.runtime.sendMessage({ type: 'GET_AD_BLOCK_STATS', tabId }, (response) => {
        if (chrome.runtime.lastError) return;
        renderAdBlockStats(response && response.stats);
    });
}

async function resetAdBlockStats() {
    const tabId = await getActiveTabId();
    chrome.runtime.sendMessage({ type: 'RESET_AD_BLOCK_STATS', tabId }, (response) => {
        if (chrome.runtime.lastError) return;
        renderAdBlockStats(response && response.stats);
    });
}

function renderAdBlockStats(stats = {}) {
    if (adBlockTotalBlocked) adBlockTotalBlocked.textContent = Number(stats.total || 0);
    if (adBlockTabBlocked) adBlockTabBlocked.textContent = Number(stats.tab || 0);
    if (adBlockTotalBlockedSummary) adBlockTotalBlockedSummary.textContent = Number(stats.total || 0);
    if (adBlockTabBlockedSummary) adBlockTabBlockedSummary.textContent = Number(stats.tab || 0);
    if (!adBlockTopDomains) return;

    const domains = Array.isArray(stats.topDomains) ? stats.topDomains : [];
    adBlockTopDomains.innerHTML = domains.length
        ? domains.map((entry) => `
            <li style="display: flex; justify-content: space-between; gap: 12px;">
                <span>${escapeHtml(entry.domain)}</span>
                <strong>${Number(entry.count || 0)}</strong>
            </li>
        `).join('')
        : '<li>No ad requests blocked yet.</li>';
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        const tabId = tab.dataset.tab;
        document.getElementById(tabId).classList.add('active');

        if (tabId === 'protection') {
            runScanner();
        }
        if (tabId === 'activity') {
            loadMonitorHistory();
            refreshAdBlockStats();
            if (netIp.textContent !== 'Fetching...') {
                fetchNetworkInfo();
            }
        }
        if (tabId === 'settings') {
            loadAdBlockSettings();
        }
    });
});

if (toggleSecure) {
    toggleSecure.addEventListener('change', () => {
        updateEnabled(toggleSecure.checked);
        renderStatus(toggleSecure.checked);
    });
}

async function fetchNetworkInfo() {
    if (!netIp) return;
    setNetworkLoading();

    const providers = [
        fetchIpWhoIs,
        fetchFreeIpApi,
        fetchIpApiCo
    ];
    const errors = [];

    for (const provider of providers) {
        try {
            const intel = await provider();
            if (intel && intel.ip) {
                renderNetworkIntel(intel);
                return;
            }
        } catch (error) {
            errors.push(`${provider.name}: ${error.message}`);
        }
    }

    renderNetworkError();
    console.warn('Ghost Guard network intel failed:', errors.join(' | '));
}

function setNetworkText(element, value) {
    if (element) element.textContent = value || 'Unknown';
}

function setNetworkLoading() {
    [
        netIp,
        netLocation,
        netIsp,
        netType,
        netAsn,
        netTimezone,
        netPrivacy,
        netCoordinates,
        netProvider
    ].forEach((element) => setNetworkText(element, 'Fetching...'));
}

function renderNetworkError() {
    setNetworkText(netIp, 'Lookup failed');
    setNetworkText(netLocation, 'All providers unavailable');
    setNetworkText(netIsp, 'Try refresh');
    setNetworkText(netType, 'Unknown');
    setNetworkText(netAsn, 'Unknown');
    setNetworkText(netTimezone, 'Unknown');
    setNetworkText(netPrivacy, 'Unknown');
    setNetworkText(netCoordinates, 'Unknown');
    setNetworkText(netProvider, 'ipwho.is, freeipapi.com, ipapi.co');
}

function renderNetworkIntel(intel) {
    setNetworkText(netIp, intel.ip);
    setNetworkText(netLocation, [intel.city, intel.region, intel.country].filter(Boolean).join(', '));
    setNetworkText(netIsp, intel.isp || intel.org);
    setNetworkText(netType, intel.type);
    setNetworkText(netAsn, intel.asn ? `AS${String(intel.asn).replace(/^AS/i, '')}` : 'Unknown');
    setNetworkText(netTimezone, intel.timezone);
    setNetworkText(netPrivacy, intel.privacy);
    setNetworkText(netCoordinates, formatCoordinates(intel.latitude, intel.longitude));
    setNetworkText(netProvider, intel.provider);
}

function formatCoordinates(latitude, longitude) {
    if (latitude === undefined || longitude === undefined || latitude === null || longitude === null) {
        return 'Unknown';
    }
    return `${Number(latitude).toFixed(4)}, ${Number(longitude).toFixed(4)}`;
}

async function fetchJson(url) {
    const response = await fetch(url, {
        cache: 'no-store',
        headers: { Accept: 'application/json' }
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
        throw new Error('Non-JSON response');
    }

    return response.json();
}

async function fetchIpWhoIs() {
    const data = await fetchJson('https://ipwho.is/');
    if (data.success === false) {
        throw new Error(data.message || 'Provider rejected request');
    }

    return {
        provider: 'ipwho.is',
        ip: data.ip,
        type: data.type,
        city: data.city,
        region: data.region,
        country: data.country,
        latitude: data.latitude,
        longitude: data.longitude,
        timezone: data.timezone && data.timezone.id,
        asn: data.connection && data.connection.asn,
        isp: data.connection && (data.connection.isp || data.connection.org),
        org: data.connection && data.connection.org,
        privacy: 'Not reported'
    };
}

async function fetchFreeIpApi() {
    const data = await fetchJson('https://freeipapi.com/api/json/');

    return {
        provider: 'freeipapi.com',
        ip: data.ipAddress,
        type: data.ipVersion ? `IPv${data.ipVersion}` : 'Unknown',
        city: data.cityName,
        region: data.regionName,
        country: data.countryName,
        latitude: data.latitude,
        longitude: data.longitude,
        timezone: Array.isArray(data.timeZones) ? data.timeZones[0] : data.timeZones,
        asn: data.asn,
        isp: data.asnOrganization,
        org: data.asnOrganization,
        privacy: data.isProxy === true ? 'Proxy/VPN detected' : 'No proxy reported'
    };
}

async function fetchIpApiCo() {
    const data = await fetchJson('https://ipapi.co/json/');
    if (data.error) {
        throw new Error(data.reason || 'Provider returned error');
    }

    return {
        provider: 'ipapi.co',
        ip: data.ip,
        type: data.version || 'Unknown',
        city: data.city,
        region: data.region,
        country: data.country_name,
        latitude: data.latitude,
        longitude: data.longitude,
        timezone: data.timezone,
        asn: data.asn,
        isp: data.org,
        org: data.org,
        privacy: 'Not reported'
    };
}

function renderRequest(req) {
    let color = '#94a3b8'; // default grey for images/scripts
    if (req.method === 'POST' || req.method === 'PUT') color = '#ef4444'; // Red for data sending
    if (req.type === 'xmlhttprequest' || req.type === 'fetch') color = '#10b981'; // Green for APIs
    if (req.type === 'main_frame' || req.type === 'sub_frame') color = '#3b82f6'; // Blue for pages

    let shortUrl = req.url;
    try {
        const urlObj = new URL(req.url);
        shortUrl = urlObj.hostname + urlObj.pathname;
        if (shortUrl.length > 38) {
            shortUrl = shortUrl.substring(0, 35) + '...';
        }
    } catch(e) {}

    const typeStr = (req.type || 'other').padEnd(6, ' ').substring(0, 6);

    return `
        <li style="display: flex; gap: 10px; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 4px 0;">
            <span style="color: ${color}; font-weight: bold; width: 35px; flex-shrink: 0;">${req.method}</span>
            <span style="color: #64748b; width: 45px; flex-shrink: 0; text-transform: uppercase; font-size: 0.65rem; margin-top: 2px;">${typeStr}</span>
            <span style="color: #cbd5e1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;" title="${req.url}">${shortUrl}</span>
        </li>
    `;
}

function updateLiveTraffic(requests) {
    if (!liveTrafficList) return;
    if (requests.length === 0) {
        liveTrafficList.innerHTML = `<li style="color: #64748b; text-align: center; padding: 10px;">Waiting for network activity...</li>`;
        return;
    }
    liveTrafficList.innerHTML = requests.map(renderRequest).join('');
}

// Fetch initial traffic list
chrome.runtime.sendMessage({ type: 'GET_REQUESTS' }, (response) => {
    if (response && response.requests) {
        updateLiveTraffic(response.requests);
    }
});

// Listen for real-time traffic updates
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'NEW_REQUEST') {
        chrome.runtime.sendMessage({ type: 'GET_REQUESTS' }, (response) => {
            if (response && response.requests) {
                updateLiveTraffic(response.requests);
            }
        });
    } else if (message.type === 'AD_BLOCK_STATS_UPDATED') {
        renderAdBlockStats(message.stats);
    }
});

if (panicBtn) {
    panicBtn.addEventListener('click', () => {
        if (confirm('☢️ WARNING: This will instantly wipe your browsing history, cache, and cookies from the past hour, and close the current tab. Proceed?')) {
            const oneHourAgo = (new Date()).getTime() - (1000 * 60 * 60);
            chrome.browsingData.remove({
                "since": oneHourAgo
            }, {
                "appcache": true,
                "cache": true,
                "cookies": true,
                "downloads": true,
                "history": true,
                "passwords": false
            }, () => {
                chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                    if (tabs[0]) chrome.tabs.remove(tabs[0].id);
                });
            });
        }
    });
}

async function runScanner(targetUrl) {
    if (!scannerDomain) return;
    scannerDomain.textContent = 'Scanning...';
    scannerStatus.textContent = 'Checking live threat intel and local risk signals...';
    renderScanScore(0, 'loading');
    renderScannerDetails(['Contacting scanner...']);

    const url = targetUrl || await getActiveTabUrl();
    if (!url) {
        scannerDomain.textContent = 'Unknown';
        scannerStatus.textContent = 'Cannot analyze this page.';
        renderScannerDetails(['Open an http/https page or enter a website URL.']);
        return;
    }

    if (scannerInput) scannerInput.value = url;

    try {
        const result = await requestWebsiteScan(url);
        if (result) {
            scannerDomain.textContent = result.domain || url;
            scannerStatus.textContent = `${result.verdict} • ${result.provider || 'Local scanner'}`;
            renderScanScore(result.score, result.riskLevel);
            renderScannerDetails(result.issues || []);
        } else {
            scannerDomain.textContent = 'Scan failed';
            scannerStatus.textContent = 'No scanner response.';
            renderScanScore(50, 'warning');
            renderScannerDetails(['Scanner did not return a verdict.']);
        }
    } catch (error) {
        scannerDomain.textContent = 'Scan failed';
        scannerStatus.textContent = error.message;
        renderScanScore(50, 'warning');
        renderScannerDetails(['Scanner failed locally and in the background.']);
    }

    refreshTrackerRadar();
}

async function requestWebsiteScan(url) {
    const backgroundResult = await requestBackgroundScan(url);
    if (backgroundResult) return backgroundResult;
    return scanUrlInPopup(url);
}

function requestBackgroundScan(url) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'SCAN_URL', url }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn('Background scanner unavailable:', chrome.runtime.lastError.message);
                resolve(null);
                return;
            }
            resolve(response && response.result);
        });
    });
}

function getActiveTabUrl() {
    return new Promise((resolve) => {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const activeUrl = tabs[0] && tabs[0].url;
            if (activeUrl && /^https?:\/\//i.test(activeUrl)) {
                resolve(activeUrl);
                return;
            }

            chrome.runtime.sendMessage({ type: 'GET_LAST_SCANNABLE_URL' }, (response) => {
                resolve(response && response.url);
            });
        });
    });
}

function renderScanScore(score, level) {
    const numeric = Math.max(0, Math.min(100, Number(score) || 0));
    const displayScore = level === 'safe' ? 100 - numeric : numeric;
    let color = '#10b981';
    if (level === 'warning') color = '#f59e0b';
    if (level === 'danger') color = '#ef4444';
    if (level === 'loading') color = '#64748b';

    trustScoreCircle.textContent = Math.round(displayScore);
    trustScoreCircle.style.borderColor = color;
    trustScoreCircle.style.color = color;
}

function renderScannerDetails(issues) {
    const details = issues.length ? issues : ['No high-risk signals found.'];
    scannerDetails.innerHTML = details.slice(0, 8).map((issue) => `<li>${escapeHtml(issue)}</li>`).join('');
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function scanUrlInPopup(url) {
    const normalized = normalizePopupScanUrl(url);
    if (isKnownTrustedPopupScanUrl(normalized)) {
        return buildKnownTrustedPopupScanResult(normalized);
    }

    const local = analyzePopupUrl(normalized);
    const provider = await fetchPopupPhishDestroy(normalized.hostname);
    return buildPopupScanResult(normalized, local, provider);
}

function normalizePopupScanUrl(url) {
    const value = String(url || '').trim();
    const withProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
    const parsed = new URL(withProtocol);
    parsed.hash = '';
    return parsed;
}

function isKnownTrustedPopupScanUrl(urlObj) {
    if (!urlObj || urlObj.protocol !== 'https:') return false;
    const host = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    return KNOWN_TRUSTED_SCAN_DOMAINS.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function buildKnownTrustedPopupScanResult(urlObj) {
    return {
        url: urlObj.href,
        domain: urlObj.hostname,
        score: 0,
        riskLevel: 'safe',
        verdict: 'Known trusted domain',
        issues: ['Official trusted domain; message contents are checked separately by Threat Analysis.'],
        provider: 'Ghost Guard Local Trust'
    };
}

function analyzePopupUrl(urlObj) {
    const host = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    const path = `${urlObj.pathname}${urlObj.search}`;
    const labels = host.split('.').filter(Boolean);
    const issues = [];
    let score = 0;

    if (urlObj.protocol !== 'https:') {
        score += 18;
        issues.push('Connection is not HTTPS');
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        score += 35;
        issues.push('Uses raw IP address instead of a domain');
    }

    if (host.includes('xn--')) {
        score += 28;
        issues.push('Punycode domain can hide lookalike characters');
    }

    if (labels.length >= 4) {
        score += 10;
        issues.push('Deep subdomain chain');
    }

    if (host.length > 45) {
        score += 10;
        issues.push('Unusually long domain');
    }

    if (/[0-9]{3,}/.test(host) || (host.match(/-/g) || []).length >= 3) {
        score += 12;
        issues.push('Heavy digits or hyphen use in domain');
    }

    const riskyTlds = ['zip', 'mov', 'click', 'top', 'work', 'quest', 'support', 'live', 'buzz'];
    const tld = labels[labels.length - 1];
    if (riskyTlds.includes(tld)) {
        score += 10;
        issues.push(`Higher-risk TLD .${tld}`);
    }

    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rebrand.ly'];
    if (shorteners.includes(host)) {
        score += 25;
        issues.push('URL shortener hides the final destination');
    }

    const protectedBrands = [
        { brand: 'openai', official: ['openai.com', 'chatgpt.com'] },
        { brand: 'chatgpt', official: ['chatgpt.com', 'openai.com'] },
        { brand: 'google', official: ['google.com'] },
        { brand: 'microsoft', official: ['microsoft.com', 'live.com', 'office.com'] },
        { brand: 'apple', official: ['apple.com'] },
        { brand: 'paypal', official: ['paypal.com'] },
        { brand: 'github', official: ['github.com'] },
        { brand: 'metamask', official: ['metamask.io'] },
        { brand: 'coinbase', official: ['coinbase.com'] },
        { brand: 'binance', official: ['binance.com'] },
        { brand: 'facebook', official: ['facebook.com', 'meta.com'] },
        { brand: 'instagram', official: ['instagram.com'] }
    ];

    protectedBrands.forEach(({ brand, official }) => {
        if (host.includes(brand) && !official.some(domain => host === domain || host.endsWith(`.${domain}`))) {
            score += 32;
            issues.push(`Possible ${brand} impersonation`);
        }
    });

    if (/(login|verify|wallet|seed|recovery|airdrop|claim|bonus|gift|security|account)/i.test(path)) {
        score += 10;
        issues.push('Sensitive action words in URL path');
    }

    return { score, issues };
}

async function fetchPopupPhishDestroy(domain) {
    try {
        const data = await fetchJson(`https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}`);
        return {
            provider: 'PhishDestroy',
            available: true,
            threat: data.threat === true,
            score: Number(data.risk_score || 0),
            severity: data.severity,
            message: data.message,
            sources: Array.isArray(data.sources) ? data.sources : []
        };
    } catch (error) {
        return {
            provider: 'PhishDestroy',
            available: false,
            threat: false,
            score: 0,
            message: error.message,
            sources: []
        };
    }
}

function buildPopupScanResult(urlObj, local, provider) {
    const providerScore = provider.threat ? Math.max(85, provider.score || 0) : provider.score || 0;
    const score = Math.min(100, Math.max(local.score, providerScore) + (provider.threat ? 0 : Math.min(15, local.score)));
    const issues = [...local.issues];

    if (provider.threat) {
        issues.unshift(`Listed by ${provider.provider}${provider.severity ? ` as ${provider.severity}` : ''}`);
    } else if (provider.available) {
        issues.push(`${provider.provider}: ${provider.message || 'Not found in blocklist'}`);
    } else {
        issues.push(`${provider.provider}: unavailable`);
    }

    const riskLevel = score >= 70 ? 'danger' : score >= 35 ? 'warning' : 'safe';
    const verdict = riskLevel === 'danger'
        ? 'Risky website detected'
        : riskLevel === 'warning'
            ? 'Suspicious website'
            : 'No known high-risk signals';

    return {
        url: urlObj.href,
        domain: urlObj.hostname,
        score,
        riskLevel,
        verdict,
        issues,
        provider: provider.available ? provider.provider : 'Local scanner'
    };
}

function refreshTrackerRadar() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs[0]) return;
        chrome.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: tabs[0].id }, (response) => {
            if (response && response.trackers) {
                trackerCount.textContent = response.trackers.length;
                if (response.trackers.length > 0) {
                    trackerList.innerHTML = response.trackers.map(t => `<li style="padding:4px 0; border-bottom: 1px solid #e5e7eb;">${t}</li>`).join('');
                } else {
                    trackerList.innerHTML = `<li style="color:#10b981;">No known trackers detected on this page.</li>`;
                }
            }
        });
    });
}

if (resetBtn) resetBtn.addEventListener('click', resetCount);
if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);
if (exportLogsBtn) exportLogsBtn.addEventListener('click', exportLogs);
if (addRuleBtn) addRuleBtn.addEventListener('click', addCustomRule);
if (addSiteBtn) addSiteBtn.addEventListener('click', addSite);
if (addTrustedSiteBtn) addTrustedSiteBtn.addEventListener('click', () => addTrustedSite());
if (nextTipBtn) nextTipBtn.addEventListener('click', nextTip);
if (refreshNetBtn) refreshNetBtn.addEventListener('click', fetchNetworkInfo);
if (scanBtn) scanBtn.addEventListener('click', () => runScanner(scannerInput.value.trim()));
if (trustScannedSiteBtn) trustScannedSiteBtn.addEventListener('click', () => addTrustedSite(scannerDomain.textContent));
if (toggleMonitor) toggleMonitor.addEventListener('change', () => updateMonitorSetting('continuous', toggleMonitor.checked));
if (toggleRiskPopups) toggleRiskPopups.addEventListener('change', () => updateMonitorSetting('popups', toggleRiskPopups.checked));
if (toggleBadgeAlerts) toggleBadgeAlerts.addEventListener('change', () => updateMonitorSetting('badges', toggleBadgeAlerts.checked));
if (clearMonitorHistoryBtn) clearMonitorHistoryBtn.addEventListener('click', clearMonitorHistory);
if (exportMonitorHistoryBtn) exportMonitorHistoryBtn.addEventListener('click', exportMonitorHistory);
if (toggleAdBlock) toggleAdBlock.addEventListener('change', () => updateAdBlockSetting('enabled', toggleAdBlock.checked));
if (toggleCosmeticBlock) toggleCosmeticBlock.addEventListener('change', () => updateAdBlockSetting('cosmetic', toggleCosmeticBlock.checked));
if (adBlockPowerBtn) adBlockPowerBtn.addEventListener('click', toggleAdBlockPower);
if (resetAdBlockStatsBtn) resetAdBlockStatsBtn.addEventListener('click', resetAdBlockStats);
if (themeToggle) themeToggle.addEventListener('click', toggleTheme);
if (applyRecommendedBtn) applyRecommendedBtn.addEventListener('click', applyRecommendedSettings);
if (threatTextInput) threatTextInput.addEventListener('input', () => renderThreatAnalysis(threatTextInput.value));
if (clearThreatInputBtn) {
    clearThreatInputBtn.addEventListener('click', () => {
        threatTextInput.value = '';
        renderThreatAnalysis('');
    });
}
if (loadThreatSampleBtn) {
    loadThreatSampleBtn.addEventListener('click', () => {
        threatTextInput.value = THREAT_SAMPLE_INPUT;
        renderThreatAnalysis(THREAT_SAMPLE_INPUT);
    });
}
if (scannerInput) {
    scannerInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            runScanner(scannerInput.value.trim());
        }
    });
}

chrome.storage.onChanged.addListener((changes) => {
    if (changes[STORAGE_KEYS.enabled]) currentDashboardState.enabled = changes[STORAGE_KEYS.enabled].newValue !== false;
    if (changes[STORAGE_KEYS.logs]) currentDashboardState.logs = changes[STORAGE_KEYS.logs].newValue || [];
    if (changes[STORAGE_KEYS.customRules]) currentDashboardState.customRules = changes[STORAGE_KEYS.customRules].newValue || [];
    if (changes[STORAGE_KEYS.whitelist]) currentDashboardState.whitelist = changes[STORAGE_KEYS.whitelist].newValue || [];
    if (changes[STORAGE_KEYS.trustedSites]) currentDashboardState.trustedSites = changes[STORAGE_KEYS.trustedSites].newValue || [];
    if (changes[STORAGE_KEYS.monitorSettings]) currentDashboardState.monitorSettings = { ...DEFAULT_MONITOR_SETTINGS, ...(changes[STORAGE_KEYS.monitorSettings].newValue || {}) };
    if (changes[STORAGE_KEYS.monitorHistory]) currentDashboardState.monitorHistory = changes[STORAGE_KEYS.monitorHistory].newValue || [];
    if (changes[STORAGE_KEYS.adBlockSettings]) currentDashboardState.adBlockSettings = { ...DEFAULT_AD_BLOCK_SETTINGS, ...(changes[STORAGE_KEYS.adBlockSettings].newValue || {}) };

    if (changes[STORAGE_KEYS.enabled]) renderStatus(changes[STORAGE_KEYS.enabled].newValue);
    if (changes[STORAGE_KEYS.blockedCount]) renderCount(changes[STORAGE_KEYS.blockedCount].newValue || 0);
    if (changes[STORAGE_KEYS.logs]) {
        const logs = changes[STORAGE_KEYS.logs].newValue || [];
        renderLogs(logs);
        renderAnalytics(logs);
    }
    if (changes[STORAGE_KEYS.customRules]) renderCustomRules(changes[STORAGE_KEYS.customRules].newValue || []);
    if (changes[STORAGE_KEYS.whitelist]) renderWhitelist(changes[STORAGE_KEYS.whitelist].newValue || []);
    if (changes[STORAGE_KEYS.trustedSites]) renderTrustedSites(changes[STORAGE_KEYS.trustedSites].newValue || []);
    if (changes[STORAGE_KEYS.monitorSettings]) renderMonitorSettings(changes[STORAGE_KEYS.monitorSettings].newValue || {});
    if (changes[STORAGE_KEYS.monitorHistory]) renderMonitorHistory(changes[STORAGE_KEYS.monitorHistory].newValue || []);
    if (changes[STORAGE_KEYS.adBlockSettings]) renderAdBlockSettings(changes[STORAGE_KEYS.adBlockSettings].newValue || {});
    renderRecommendations(currentDashboardState);
});

applyTheme(localStorage.getItem('ghostGuardTheme') || document.documentElement.dataset.theme || 'dark');
loadState();
refreshAdBlockStats();
renderThreatAnalysis('');
