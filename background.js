const MAX_REQUESTS = 50;
let recentRequests = [];
const SCAN_CACHE_TTL = 1000 * 60 * 10;
const scanCache = new Map();
let lastScannableUrl = '';
let lastScannableTabId = null;
const tabScanResults = {};
const adBlockStats = {
    total: 0,
    byTab: {},
    byDomain: {}
};

const STORAGE_KEYS = {
    trustedSites: 'trustedSites',
    monitorSettings: 'monitorSettings',
    monitorHistory: 'monitorHistory',
    adBlockSettings: 'adBlockSettings',
    adBlockStats: 'adBlockStats'
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

const TRACKER_DOMAINS = [
    'google-analytics.com', 'doubleclick.net', 'facebook.com/tr', 'pixel.facebook.com',
    'hotjar.com', 'clarity.ms', 'mixpanel.com', 'segment.com', 'scorecardresearch.com',
    'quantserve.com', 'googletagmanager.com', 'analytics.twitter.com', 'googlesyndication.com',
    'googleadservices.com', 'adnxs.com', 'amazon-adsystem.com', 'taboola.com', 'outbrain.com',
    'rubiconproject.com', 'openx.net', 'pubmatic.com', 'criteo.com', 'criteo.net', 'moatads.com'
];
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
let tabTrackers = {}; // { tabId: Set<domain> }

chrome.runtime.onInstalled.addListener(() => {
    syncAdBlockRules();
});

chrome.runtime.onStartup.addListener(() => {
    syncAdBlockRules();
});

syncAdBlockRules();

chrome.action.onClicked.addListener(() => {
    chrome.tabs.create({
        url: chrome.runtime.getURL('panel.html')
    });
});

chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabTrackers[tabId];
    delete tabScanResults[tabId];
    delete adBlockStats.byTab[tabId];
});

if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        recordAdBlockMatch(info);
    });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete' || !tab.url || !isScannableUrl(tab.url)) return;
    lastScannableTabId = tabId;
    runContinuousScan(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
    chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab || !isScannableUrl(tab.url)) return;
        lastScannableTabId = tabId;
        runContinuousScan(tabId, tab.url);
    });
});

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        // Ignore the extension's own requests
        if (details.url.startsWith('chrome-extension://')) return;

        const requestInfo = {
            id: details.requestId,
            url: details.url,
            method: details.method,
            type: details.type,
            timestamp: Date.now()
        };

        recentRequests.unshift(requestInfo);
        if (recentRequests.length > MAX_REQUESTS) {
            recentRequests.pop();
        }

        // Tracker Radar
        if (details.tabId >= 0) {
            try {
                const urlObj = new URL(details.url);
                const isTracker = TRACKER_DOMAINS.some(domain => urlObj.hostname.includes(domain));
                if (isTracker) {
                    if (!tabTrackers[details.tabId]) tabTrackers[details.tabId] = new Set();
                    tabTrackers[details.tabId].add(urlObj.hostname);
                }
            } catch(e) {}
        }

        // Broadcast to popup if open
        chrome.runtime.sendMessage({ type: 'NEW_REQUEST', request: requestInfo }).catch(() => {
            // Ignore error when popup is not open
        });
    },
    { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_REQUESTS') {
        sendResponse({ requests: recentRequests });
    } else if (message.type === 'GET_TAB_DATA') {
        const trackers = tabTrackers[message.tabId] ? Array.from(tabTrackers[message.tabId]) : [];
        sendResponse({ trackers: trackers });
    } else if (message.type === 'GET_LAST_SCANNABLE_URL') {
        sendResponse({ url: lastScannableUrl });
    } else if (message.type === 'GET_TAB_SCAN_RESULT') {
        sendResponse({ result: tabScanResults[message.tabId] || null });
    } else if (message.type === 'GET_MONITOR_HISTORY') {
        getStorage([STORAGE_KEYS.monitorHistory]).then((data) => {
            sendResponse({ history: data[STORAGE_KEYS.monitorHistory] || [] });
        });
        return true;
    } else if (message.type === 'CLEAR_MONITOR_HISTORY') {
        setStorage({ [STORAGE_KEYS.monitorHistory]: [] }).then(() => {
            sendResponse({ history: [] });
        });
        return true;
    } else if (message.type === 'GET_AD_BLOCK_SETTINGS') {
        getAdBlockSettings().then((settings) => {
            sendResponse({ settings });
        });
        return true;
    } else if (message.type === 'GET_AD_BLOCK_STATS') {
        sendResponse({ stats: getAdBlockStats(message.tabId) });
    } else if (message.type === 'RESET_AD_BLOCK_STATS') {
        resetAdBlockStats();
        sendResponse({ stats: getAdBlockStats(message.tabId) });
    } else if (message.type === 'UPDATE_AD_BLOCK_SETTINGS') {
        const settings = { ...DEFAULT_AD_BLOCK_SETTINGS, ...(message.settings || {}) };
        setStorage({ [STORAGE_KEYS.adBlockSettings]: settings }).then(() => syncAdBlockRules(settings)).then(() => {
            sendResponse({ settings });
        });
        return true;
    } else if (message.type === 'TRUST_SITE') {
        trustSite(message.domain || message.url).then((sites) => {
            sendResponse({ sites });
        });
        return true;
    } else if (message.type === 'PAGE_READY_SCAN') {
        const tabId = sender.tab && sender.tab.id;
        const url = message.url || (sender.tab && sender.tab.url);
        if (typeof tabId !== 'number' || !isScannableUrl(url)) {
            sendResponse({ result: null });
            return;
        }

        runContinuousScan(tabId, url).then((result) => {
            sendResponse({ result });
        });
        return true;
    } else if (message.type === 'SCAN_URL') {
        scanUrl(message.url).then((result) => {
            sendResponse({ result });
        }).catch((error) => {
            sendResponse({
                result: {
                    url: message.url,
                    score: 50,
                    riskLevel: 'warning',
                    verdict: 'Scan unavailable',
                    issues: ['Scanner provider unavailable'],
                    provider: 'Local scanner',
                    error: error.message
                }
            });
        });
        return true;
    }
});

async function runContinuousScan(tabId, url) {
    lastScannableUrl = url;
    const settings = await getMonitorSettings();
    if (!settings.continuous) {
        clearScanBadge(tabId);
        return null;
    }

    if (await isTrustedUrl(url)) {
        tabScanResults[tabId] = {
            url,
            score: 0,
            riskLevel: 'safe',
            verdict: 'Trusted site',
            issues: ['Trusted by user'],
            provider: 'Ghost Guard Trust List'
        };
        tabScanResults[tabId].suppressPopup = true;
        saveMonitorHistory(tabScanResults[tabId]);
        if (settings.badges) {
            setScanBadge(tabId, 'TRST', '#2563eb');
        } else {
            clearScanBadge(tabId);
        }
        return tabScanResults[tabId];
    }

    if (settings.badges) {
        setScanBadge(tabId, '...', '#64748b');
    }

    try {
        const result = await scanUrl(url);
        result.suppressPopup = !settings.popups;
        tabScanResults[tabId] = result;
        saveMonitorHistory(result);
        if (settings.badges) {
            updateTabBadge(tabId, result);
        } else {
            clearScanBadge(tabId);
        }
        if (settings.popups) {
            notifyRiskyTab(tabId, result);
        }
        return result;
    } catch (error) {
        const result = {
            url,
            score: 50,
            riskLevel: 'warning',
            verdict: 'Scan unavailable',
            issues: ['Continuous scanner unavailable'],
            provider: 'Local scanner',
            error: error.message
        };
        result.suppressPopup = !settings.popups;
        tabScanResults[tabId] = result;
        saveMonitorHistory(result);
        if (settings.badges) {
            setScanBadge(tabId, 'ERR', '#f59e0b');
        } else {
            clearScanBadge(tabId);
        }
        return result;
    }
}

chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes[STORAGE_KEYS.adBlockSettings]) {
        syncAdBlockRules(changes[STORAGE_KEYS.adBlockSettings].newValue);
    }
});

function updateTabBadge(tabId, result) {
    if (result.riskLevel === 'danger') {
        setScanBadge(tabId, 'BAD', '#dc2626');
    } else if (result.riskLevel === 'warning') {
        setScanBadge(tabId, 'WARN', '#f59e0b');
    } else {
        setScanBadge(tabId, 'OK', '#10b981');
    }
}

function setScanBadge(tabId, text, color) {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function clearScanBadge(tabId) {
    chrome.action.setBadgeText({ tabId, text: '' });
}

function notifyRiskyTab(tabId, result) {
    if (result.riskLevel !== 'danger' && result.riskLevel !== 'warning') return;

    chrome.tabs.sendMessage(tabId, {
        type: 'GHOST_SITE_RISK',
        result
    }).catch(() => {
        // Content scripts are not available on browser/system pages.
    });
}

function isScannableUrl(url) {
    return /^https?:\/\//i.test(url || '');
}

function getStorage(keys) {
    return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function setStorage(values) {
    return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

async function getMonitorSettings() {
    const data = await getStorage([STORAGE_KEYS.monitorSettings]);
    return { ...DEFAULT_MONITOR_SETTINGS, ...(data[STORAGE_KEYS.monitorSettings] || {}) };
}

async function getAdBlockSettings() {
    const data = await getStorage([STORAGE_KEYS.adBlockSettings]);
    return { ...DEFAULT_AD_BLOCK_SETTINGS, ...(data[STORAGE_KEYS.adBlockSettings] || {}) };
}

async function syncAdBlockRules(settings) {
    if (!chrome.declarativeNetRequest) return;
    const resolved = settings ? { ...DEFAULT_AD_BLOCK_SETTINGS, ...settings } : await getAdBlockSettings();
    const options = resolved.enabled
        ? { enableRulesetIds: ['ghost_adblock'], disableRulesetIds: [] }
        : { enableRulesetIds: [], disableRulesetIds: ['ghost_adblock'] };

    chrome.declarativeNetRequest.updateEnabledRulesets(options).catch((error) => {
        console.warn('Ghost Guard ad blocker rule sync failed:', error.message);
    });
}

function recordAdBlockMatch(info) {
    if (!info || info.rulesetId !== 'ghost_adblock') return;

    const tabId = info.request && typeof info.request.tabId === 'number' ? info.request.tabId : -1;
    const domain = getRequestDomain(info.request && info.request.url);
    adBlockStats.total += 1;

    if (tabId >= 0) {
        adBlockStats.byTab[tabId] = (adBlockStats.byTab[tabId] || 0) + 1;
    }

    if (domain) {
        adBlockStats.byDomain[domain] = (adBlockStats.byDomain[domain] || 0) + 1;
    }

    if (tabId >= 0) {
        chrome.runtime.sendMessage({
            type: 'AD_BLOCK_STATS_UPDATED',
            stats: getAdBlockStats(tabId)
        }).catch(() => {
            // Panel may be closed.
        });
    }
}

function getAdBlockStats(tabId) {
    const targetTabId = typeof tabId === 'number' && tabId >= 0 ? tabId : lastScannableTabId;
    const topDomains = Object.entries(adBlockStats.byDomain)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([domain, count]) => ({ domain, count }));

    return {
        total: adBlockStats.total,
        tab: typeof targetTabId === 'number' ? adBlockStats.byTab[targetTabId] || 0 : 0,
        topDomains
    };
}

function resetAdBlockStats() {
    adBlockStats.total = 0;
    adBlockStats.byTab = {};
    adBlockStats.byDomain = {};
}

function getRequestDomain(url) {
    try {
        return new URL(url).hostname.replace(/^www\./, '');
    } catch (error) {
        return '';
    }
}

async function saveMonitorHistory(result) {
    if (!result || !result.domain) return;

    const entry = {
        timestamp: new Date().toISOString(),
        domain: result.domain,
        url: result.url,
        score: result.score,
        riskLevel: result.riskLevel,
        verdict: result.verdict,
        provider: result.provider,
        issues: (result.issues || []).slice(0, 5)
    };

    const data = await getStorage([STORAGE_KEYS.monitorHistory]);
    const history = data[STORAGE_KEYS.monitorHistory] || [];
    const deduped = history.filter(item => item.domain !== entry.domain || item.url !== entry.url);
    deduped.unshift(entry);
    if (deduped.length > 100) deduped.length = 100;
    await setStorage({ [STORAGE_KEYS.monitorHistory]: deduped });
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

async function isTrustedUrl(url) {
    const domain = normalizeDomain(url);
    if (!domain) return false;

    const data = await getStorage([STORAGE_KEYS.trustedSites]);
    const sites = data[STORAGE_KEYS.trustedSites] || [];
    return sites.some(site => domain === site || domain.endsWith(`.${site}`));
}

async function trustSite(value) {
    const domain = normalizeDomain(value);
    if (!domain) return [];

    const data = await getStorage([STORAGE_KEYS.trustedSites]);
    const sites = data[STORAGE_KEYS.trustedSites] || [];
    if (!sites.includes(domain)) sites.push(domain);
    await setStorage({ [STORAGE_KEYS.trustedSites]: sites });
    return sites;
}

async function scanUrl(url) {
    const normalized = normalizeScanUrl(url);
    const cached = scanCache.get(normalized.href);
    if (cached && Date.now() - cached.cachedAt < SCAN_CACHE_TTL) {
        return cached.result;
    }

    if (isKnownTrustedScanUrl(normalized)) {
        const result = buildKnownTrustedScanResult(normalized);
        scanCache.set(normalized.href, { result, cachedAt: Date.now() });
        return result;
    }

    const local = analyzeUrlLocally(normalized);
    const provider = await fetchPhishDestroy(normalized.hostname);
    const result = buildScanResult(normalized, local, provider);
    scanCache.set(normalized.href, { result, cachedAt: Date.now() });
    return result;
}

function normalizeScanUrl(url) {
    const value = String(url || '').trim();
    const withProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
    const parsed = new URL(withProtocol);
    parsed.hash = '';
    return parsed;
}

function isKnownTrustedScanUrl(urlObj) {
    if (!urlObj || urlObj.protocol !== 'https:') return false;
    const host = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    return KNOWN_TRUSTED_SCAN_DOMAINS.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function buildKnownTrustedScanResult(urlObj) {
    return {
        url: urlObj.href,
        domain: urlObj.hostname,
        score: 0,
        riskLevel: 'safe',
        verdict: 'Known trusted domain',
        issues: ['Official trusted domain; message contents are checked separately by Threat Analysis.'],
        provider: 'Ghost Guard Local Trust',
        providerAvailable: false,
        providerSources: [],
        checkedAt: new Date().toISOString()
    };
}

function analyzeUrlLocally(urlObj) {
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

async function fetchPhishDestroy(domain) {
    try {
        const response = await fetch(`https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}`, {
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        return {
            provider: 'PhishDestroy',
            available: true,
            threat: data.threat === true,
            score: Number(data.risk_score || 0),
            severity: data.severity,
            message: data.message,
            sources: Array.isArray(data.sources) ? data.sources : [],
            checkedAt: data.checked_at
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

function buildScanResult(urlObj, local, provider) {
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
        provider: provider.provider,
        providerAvailable: provider.available,
        providerSources: provider.sources,
        checkedAt: new Date().toISOString()
    };
}
