// content.js - Ghost Guard page protection

console.log("Ghost Guard: local protection active");

let isEnabled = true;
const STORAGE_KEYS = {
    enabled: 'enabled',
    blockedCount: 'blockedCount',
    logs: 'eventLogs',
    customRules: 'customRules',
    whitelist: 'whitelist',
    adBlockSettings: 'adBlockSettings'
};
const DEFAULT_AD_BLOCK_SETTINGS = {
    enabled: true,
    cosmetic: true
};
const MAX_LOGS = 25;
let customPatterns = {};
let whitelist = [];

// Load custom rules and whitelist
chrome.storage.local.get([STORAGE_KEYS.customRules, STORAGE_KEYS.whitelist], (data) => {
    customPatterns = {};
    (data[STORAGE_KEYS.customRules] || []).forEach((rule, index) => {
        try {
            customPatterns[`custom${index}`] = { regex: new RegExp(rule, 'g'), replacement: '[CUSTOM_REDACTED]', label: `Custom Rule ${index + 1}` };
        } catch (e) {
            console.warn('Invalid custom regex:', rule);
        }
    });
    whitelist = data[STORAGE_KEYS.whitelist] || [];
});

// Listen for updates
chrome.storage.onChanged.addListener((changes) => {
    if (changes[STORAGE_KEYS.customRules]) {
        customPatterns = {};
        (changes[STORAGE_KEYS.customRules].newValue || []).forEach((rule, index) => {
            try {
                customPatterns[`custom${index}`] = { regex: new RegExp(rule, 'g'), replacement: '[CUSTOM_REDACTED]', label: `Custom Rule ${index + 1}` };
            } catch (e) {
                console.warn('Invalid custom regex:', rule);
            }
        });
    }
    if (changes[STORAGE_KEYS.whitelist]) {
        whitelist = changes[STORAGE_KEYS.whitelist].newValue || [];
    }
    if (changes[STORAGE_KEYS.adBlockSettings]) {
        updateCosmeticAdBlock(changes[STORAGE_KEYS.adBlockSettings].newValue || {});
    }
});

// 1. Connect to Chrome Storage (Popup Communication)
if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get([STORAGE_KEYS.enabled], (data) => {
        isEnabled = data.enabled !== false;
        console.log(`[Ghost Guard] System startup: ${isEnabled ? 'ARMED' : 'DISARMED'}`);
    });

    chrome.storage.onChanged.addListener((changes) => {
        if (changes[STORAGE_KEYS.enabled]) {
            isEnabled = changes[STORAGE_KEYS.enabled].newValue;
            console.log(`[Ghost Guard] System status changed: ${isEnabled ? 'ARMED' : 'DISARMED'}`);
            const threatPanel = document.getElementById('ghost-threat-analysis');
            if (!isEnabled && threatPanel) threatPanel.hidden = true;
            const gmailPanel = document.getElementById('ghost-gmail-checkup');
            if (!isEnabled && gmailPanel) gmailPanel.hidden = true;
            if (isEnabled && gmailPanel) gmailPanel.hidden = false;
            if (isEnabled) initGmailSecurityCheckup();
        }
    });
}

function saveLogEntry(entry) {
    if (typeof chrome === 'undefined' || !chrome.storage) return;
    chrome.storage.local.get([STORAGE_KEYS.logs], (data) => {
        const logs = Array.isArray(data[STORAGE_KEYS.logs]) ? data[STORAGE_KEYS.logs] : [];
        logs.unshift(entry);
        if (logs.length > MAX_LOGS) logs.length = MAX_LOGS;
        chrome.storage.local.set({ [STORAGE_KEYS.logs]: logs });
    });
}

function incrementStats(eventData) {
    if (typeof chrome === 'undefined' || !chrome.storage) return;

    chrome.storage.local.get([STORAGE_KEYS.blockedCount], (data) => {
        const current = Number(data[STORAGE_KEYS.blockedCount] || 0) + 1;
        chrome.storage.local.set({ [STORAGE_KEYS.blockedCount]: current }, () => {
            if (eventData) {
                saveLogEntry(eventData);
            }
        });
    });
}

// 2. The Threat Library (Regex Patterns)
const PATTERNS = {
    email: { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[EMAIL_REDACTED]', label: 'Email Address' },
    phone: { regex: /(?:(?:\b|(?<=\s))\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, replacement: '[PHONE_REDACTED]', label: 'Phone Number' },
    ssn: { regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[SSN_REDACTED]', label: 'Social Security Number' },

    creditCard: { regex: /\b(?:\d[ -]*?){13,16}\b/g, replacement: '[CC_REDACTED]', label: 'Credit Card Number' },
    cryptoWallet: { regex: /\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b/g, replacement: '[CRYPTO_WALLET_REDACTED]', label: 'Crypto Wallet Address' },
    stripeKey: { regex: /(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}/g, replacement: '[STRIPE_KEY_REDACTED]', label: 'Stripe API Key' },
    jwtToken: { regex: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g, replacement: '[JWT_REDACTED]', label: 'JWT Token' },

    ipv4: { regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, replacement: '[IPV4_REDACTED]', label: 'IPv4 Address' },
    ipv6: { regex: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g, replacement: '[IPV6_REDACTED]', label: 'IPv6 Address' },
    macAddress: { regex: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g, replacement: '[MAC_ADDR_REDACTED]', label: 'MAC Address' },

    awsAccessKey: { regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, replacement: '[AWS_KEY_REDACTED]', label: 'AWS Access Key' },
    googleApiKey: { regex: /AIza[0-9A-Za-z\-_]{35}/g, replacement: '[GOOGLE_API_KEY_REDACTED]', label: 'Google/Gemini API Key' },
    slackToken: { regex: /xox[baprs]-[a-zA-Z0-9-]{10,48}/g, replacement: '[SLACK_TOKEN_REDACTED]', label: 'Slack Token' },
    githubToken: { regex: /(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}/g, replacement: '[GITHUB_TOKEN_REDACTED]', label: 'GitHub Token' },
    privateKey: { regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g, replacement: '[PRIVATE_KEY_BLOCK_REDACTED]', label: 'Private Key Block' },
    openaiKey: { regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, replacement: '[OPENAI_KEY_REDACTED]', label: 'OpenAI API Key' },
    anthropicKey: { regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, replacement: '[ANTHROPIC_KEY_REDACTED]', label: 'Anthropic API Key' },
    huggingFaceToken: { regex: /\bhf_[A-Za-z0-9]{30,}\b/g, replacement: '[HUGGINGFACE_TOKEN_REDACTED]', label: 'Hugging Face Token' },
    npmToken: { regex: /\bnpm_[A-Za-z0-9]{36,}\b/g, replacement: '[NPM_TOKEN_REDACTED]', label: 'NPM Token' },
    vercelToken: { regex: /\bvercel_[A-Za-z0-9]{20,}\b/g, replacement: '[VERCEL_TOKEN_REDACTED]', label: 'Vercel Token' },
    supabaseUrl: { regex: /\bhttps:\/\/[a-zA-Z0-9-]+\.supabase\.co\b/g, replacement: '[SUPABASE_URL_REDACTED]', label: 'Supabase Project URL' },
    databaseUrl: { regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]+/gi, replacement: '[DATABASE_URL_REDACTED]', label: 'Database Connection URL' },
    bearerToken: { regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/g, replacement: '[BEARER_TOKEN_REDACTED]', label: 'Bearer Token' },
    webhookUrl: { regex: /\bhttps:\/\/hooks\.(?:slack|zapier)\.com\/[^\s'"]+/gi, replacement: '[WEBHOOK_URL_REDACTED]', label: 'Webhook URL' },

    passwordSentence: { regex: /\b(?:my|the|your)\b\s+(?:password|passphrase|pin)\s*(?:is|:|=)?\s*[^\n]{4,80}/gi, replacement: '[PASSWORD_REDACTED]', label: 'Password Sentence' },
    apiKeySentence: { regex: /\b(?:my|the|your)\b\s+(?:api key|access key|secret key|token|stripe key|aws key|google api key)\s*(?:is|:|=)?\s*[A-Za-z0-9\-_]{16,}/gi, replacement: '[API_KEY_REDACTED]', label: 'API Key Sentence' },
    ccSentence: { regex: /\b(?:my|the|your)\b\s+(?:credit card|card number)\s*(?:is|:|=)?\s*(?:\d[ -]*){13,16}\b/gi, replacement: '[CC_REDACTED]', label: 'Credit Card Sentence' },
    ssnSentence: { regex: /\b(?:my|the|your)\b\s+(?:social security number|ssn)\s*(?:is|:|=)?\s*\d{3}-\d{2}-\d{4}/gi, replacement: '[SSN_REDACTED]', label: 'SSN Sentence' },
    privateKeySentence: { regex: /\b(?:my|the|your)\b\s+private key\s*(?:is|:|=)?\s*-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/gi, replacement: '[PRIVATE_KEY_BLOCK_REDACTED]', label: 'Private Key Sentence' },
    promptInjection: { regex: /\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions\b[\s\S]{0,160}/gi, replacement: '[PROMPT_INJECTION_REDACTED]', label: 'Prompt Injection Attempt' },
    systemPromptLeak: { regex: /\b(?:reveal|show|print|dump|exfiltrate)\s+(?:your\s+)?(?:system prompt|hidden prompt|developer message|tool output|chain of thought)\b[\s\S]{0,160}/gi, replacement: '[AI_POLICY_LEAK_ATTEMPT_REDACTED]', label: 'AI System Prompt Leak Attempt' }
};

function sanitizeText(text) {
    let cleanText = text;
    const allPatterns = { ...PATTERNS, ...customPatterns };
    for (const type in allPatterns) {
        allPatterns[type].regex.lastIndex = 0;
        if (allPatterns[type].regex.test(cleanText)) {
            console.log(`[Ghost Guard] Redacting ${type}`);
            cleanText = cleanText.replace(allPatterns[type].regex, allPatterns[type].replacement);
        }
    }
    return cleanText;
}

// --- Warning Modal Logic ---
function createWarningModal() {
    if (document.getElementById('ghost-modal-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'ghost-modal-overlay';
    overlay.className = 'ghost-modal-overlay';
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            closeWarningModal();
        }
    });

    const modal = document.createElement('div');
    modal.className = 'ghost-modal-content';

    const header = document.createElement('div');
    header.className = 'ghost-modal-header';
    header.innerText = 'Security Alert';

    const body = document.createElement('div');
    body.className = 'ghost-modal-body';
    body.innerHTML = `
        <p>Ghost Guard blocked sensitive text before it left the page.</p>
        <p>Detected items:</p>
        <span id="ghost-threat-list" class="ghost-threat-list"></span>
        <p>The risky parts were redacted automatically.</p>
    `;

    const footer = document.createElement('div');
    footer.className = 'ghost-modal-footer';

    const btn = document.createElement('button');
    btn.className = 'ghost-modal-btn';
    btn.innerText = 'Done';
    btn.addEventListener('click', closeWarningModal);

    footer.appendChild(btn);
    modal.appendChild(header);
    modal.appendChild(body);
    modal.appendChild(footer);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
}

function showWarning(threats) {
    createWarningModal();
    const listElement = document.getElementById('ghost-threat-list');
    const overlay = document.getElementById('ghost-modal-overlay');
    if (listElement && overlay) {
        const uniqueThreats = [...new Set(threats)];
        listElement.innerText = uniqueThreats.map(t => `• ${t}`).join('\n');
        overlay.style.display = 'flex';
    }
}

function closeWarningModal() {
    const overlay = document.getElementById('ghost-modal-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function getEditableText(target) {
    if (!target) return '';
    if (target.isContentEditable) return target.innerText || target.textContent || '';
    if ('value' in target) return target.value || '';
    return '';
}

function isTextInputTarget(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;
    const tagName = (target.tagName || '').toLowerCase();
    if (tagName === 'textarea') return true;
    if (tagName !== 'input') return false;
    return !target.type || ['email', 'search', 'text', 'url'].includes(target.type);
}

function escapeHtmlForPanel(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function ensureThreatAnalysisPanel() {
    let panel = document.getElementById('ghost-threat-analysis');
    if (panel) return panel;

    panel = document.createElement('aside');
    panel.id = 'ghost-threat-analysis';
    panel.className = 'ghost-threat-analysis';
    panel.hidden = true;
    panel.innerHTML = `
        <div class="ghost-threat-header">
            <span class="ghost-threat-title">Threat Analysis</span>
            <span id="ghost-threat-risk" class="ghost-threat-risk low">Low</span>
        </div>
        <div class="ghost-threat-body">
            <div class="ghost-threat-metrics">
                <div class="ghost-threat-metric">
                    <span>Score</span>
                    <strong id="ghost-threat-score">0</strong>
                </div>
                <div class="ghost-threat-metric">
                    <span>Red Flags</span>
                    <strong id="ghost-threat-count">0</strong>
                </div>
            </div>
            <div>
                <span class="ghost-threat-section-label">Suspicious URLs</span>
                <ul id="ghost-threat-urls" class="ghost-threat-urls">
                    <li>None detected.</li>
                </ul>
            </div>
            <div id="ghost-threat-recommendation" class="ghost-threat-recommendation">
                No obvious phishing indicators found in this text.
            </div>
        </div>
    `;
    document.documentElement.appendChild(panel);
    return panel;
}

function updateThreatAnalysisPanel(text) {
    if (!window.GhostTextThreatAnalyzer) return;

    const panel = ensureThreatAnalysisPanel();
    const result = window.GhostTextThreatAnalyzer.analyzeThreatText(text || '');
    const suspiciousUrls = window.GhostTextThreatAnalyzer.extractUrls(text || '').filter((entry) => {
        return window.GhostTextThreatAnalyzer.analyzeUrl(entry).length > 0;
    });
    const risk = panel.querySelector('#ghost-threat-risk');
    const score = panel.querySelector('#ghost-threat-score');
    const count = panel.querySelector('#ghost-threat-count');
    const urls = panel.querySelector('#ghost-threat-urls');
    const recommendation = panel.querySelector('#ghost-threat-recommendation');

    panel.hidden = !String(text || '').trim();
    risk.textContent = result.riskLevel;
    risk.className = `ghost-threat-risk ${result.riskLevel}`;
    score.textContent = String(result.score);
    count.textContent = String(result.flags.length);
    recommendation.textContent = result.recommendation;
    urls.innerHTML = suspiciousUrls.length
        ? suspiciousUrls.slice(0, 5).map((entry) => `<li>${escapeHtmlForPanel(entry.url)}</li>`).join('')
        : '<li>None detected.</li>';
}

function getThreatRecommendation(riskLevel, flags) {
    if (riskLevel === 'high') {
        return 'Real warning signs found. Do not click links or share credentials until you verify the sender another way.';
    }
    if (riskLevel === 'medium') {
        return 'Some suspicious signs found. Review the flagged links before you trust this email.';
    }
    if (flags.length > 0) {
        return 'Minor warning signs found. The email is probably okay only if you expected it and trust the sender.';
    }
    return 'No clear phishing signs found in the visible Gmail content.';
}

function isGmailPage() {
    return location.hostname === 'mail.google.com';
}

function unwrapGmailRedirectUrl(href) {
    try {
        const parsed = new URL(href);
        const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
        if (host === 'google.com' && parsed.pathname === '/url') {
            return parsed.searchParams.get('q') || parsed.searchParams.get('url') || href;
        }
    } catch (error) {
        return href;
    }
    return href;
}

function ensureGmailSecurityCheckup() {
    let panel = document.getElementById('ghost-gmail-checkup');
    if (panel) return panel;

    panel = document.createElement('aside');
    panel.id = 'ghost-gmail-checkup';
    panel.className = 'ghost-gmail-checkup';
    panel.innerHTML = `
        <div class="ghost-gmail-header">
            <span>
                <strong>Gmail Security Checkup</strong>
                <small id="ghost-gmail-status">Ready to inspect visible email content.</small>
            </span>
            <button id="ghost-gmail-scan-btn" type="button">Scan</button>
        </div>
        <div class="ghost-gmail-progress" aria-hidden="true">
            <span id="ghost-gmail-progress-bar"></span>
        </div>
        <div class="ghost-gmail-body">
            <div class="ghost-gmail-verdict safe" id="ghost-gmail-verdict">Not scanned yet</div>
            <div class="ghost-gmail-stats">
                <span><strong id="ghost-gmail-score">0</strong> Score</span>
                <span><strong id="ghost-gmail-flags">0</strong> Flags</span>
                <span><strong id="ghost-gmail-links">0</strong> Links</span>
            </div>
            <div id="ghost-gmail-recommendation" class="ghost-gmail-recommendation">
                Open an email and run a scan.
            </div>
            <ul id="ghost-gmail-findings" class="ghost-gmail-findings">
                <li>No inspection results yet.</li>
            </ul>
        </div>
    `;

    document.documentElement.appendChild(panel);
    panel.querySelector('#ghost-gmail-scan-btn').addEventListener('click', runGmailSecurityCheckup);
    return panel;
}

function getVisibleGmailAnchors() {
    return Array.from(document.querySelectorAll('a[href]'))
        .filter((link) => {
            const href = link.getAttribute('href') || '';
            const rect = link.getBoundingClientRect();
            return /^https?:\/\//i.test(href) && rect.width > 0 && rect.height > 0;
        })
        .slice(0, 80)
        .map((link) => ({
            url: unwrapGmailRedirectUrl(link.href),
            visibleText: (link.innerText || link.textContent || '').trim().slice(0, 160)
        }));
}

function inspectVisibleGmailContent() {
    const analyzer = window.GhostTextThreatAnalyzer;
    if (!analyzer) {
        return {
            riskLevel: 'low',
            score: 0,
            flags: [],
            recommendation: 'Threat analyzer is not available yet.',
            linkCount: 0
        };
    }

    const pageText = (document.body && document.body.innerText || '').slice(0, 30000);
    const textResult = analyzer.analyzeThreatText(pageText);
    const linkEntries = getVisibleGmailAnchors();
    const hrefFlags = linkEntries.flatMap((entry) => analyzer.analyzeUrl(entry));
    const flagKeys = new Set();
    const flags = [...textResult.flags, ...hrefFlags].filter((flag) => {
        const key = `${flag.type}|${flag.message}|${flag.value}`;
        if (flagKeys.has(key)) return false;
        flagKeys.add(key);
        return true;
    });
    const score = analyzer.calculateThreatScore(flags);
    const riskLevel = score >= 60 ? 'high' : score >= 25 ? 'medium' : 'low';

    return {
        riskLevel,
        score,
        flags,
        recommendation: getThreatRecommendation(riskLevel, flags),
        linkCount: linkEntries.length
    };
}

function renderGmailSecurityResult(result) {
    const panel = ensureGmailSecurityCheckup();
    const verdict = panel.querySelector('#ghost-gmail-verdict');
    const score = panel.querySelector('#ghost-gmail-score');
    const flags = panel.querySelector('#ghost-gmail-flags');
    const links = panel.querySelector('#ghost-gmail-links');
    const recommendation = panel.querySelector('#ghost-gmail-recommendation');
    const findings = panel.querySelector('#ghost-gmail-findings');

    const label = result.riskLevel === 'high'
        ? 'High risk signals found'
        : result.riskLevel === 'medium'
            ? 'Suspicious signals found'
            : 'No clear threat found';

    verdict.textContent = label;
    verdict.className = `ghost-gmail-verdict ${result.riskLevel}`;
    score.textContent = String(result.score);
    flags.textContent = String(result.flags.length);
    links.textContent = String(result.linkCount || 0);
    recommendation.textContent = result.recommendation;
    findings.innerHTML = result.flags.length
        ? result.flags.slice(0, 6).map((flag) => `
            <li>
                <strong>${escapeHtmlForPanel(flag.type.replace(/_/g, ' '))}</strong>
                <span>${escapeHtmlForPanel(flag.message)}</span>
                <em>${escapeHtmlForPanel(flag.value)}</em>
            </li>
        `).join('')
        : '<li>No urgent language, suspicious links, lookalike domains, or link mismatches found.</li>';
}

function runGmailSecurityCheckup() {
    if (!isGmailPage()) return;
    const panel = ensureGmailSecurityCheckup();
    const scanBtn = panel.querySelector('#ghost-gmail-scan-btn');
    const status = panel.querySelector('#ghost-gmail-status');
    const progress = panel.querySelector('#ghost-gmail-progress-bar');
    const steps = [
        'Reading visible Gmail message text...',
        'Checking urgent language...',
        'Inspecting links and hidden destinations...',
        'Checking lookalike domains...',
        'Building verdict...'
    ];

    scanBtn.disabled = true;
    panel.classList.add('scanning');
    progress.style.width = '0%';

    steps.forEach((step, index) => {
        setTimeout(() => {
            status.textContent = step;
            progress.style.width = `${Math.round(((index + 1) / steps.length) * 100)}%`;
        }, index * 450);
    });

    setTimeout(() => {
        const result = inspectVisibleGmailContent();
        renderGmailSecurityResult(result);
        status.textContent = `Inspection complete: ${result.riskLevel} risk.`;
        panel.classList.remove('scanning');
        scanBtn.disabled = false;
    }, steps.length * 450 + 120);
}

function initGmailSecurityCheckup() {
    if (!isGmailPage() || !isEnabled) return;
    ensureGmailSecurityCheckup();
    setTimeout(runGmailSecurityCheckup, 1800);
}

const updateThreatAnalysisPanelDebounced = debounce((target) => {
    if (!isEnabled || !isTextInputTarget(target)) return;
    updateThreatAnalysisPanel(getEditableText(target));
}, 220);

function showSiteRiskWarning(result) {
    if (!result || document.getElementById('ghost-site-risk-overlay')) return;
    const warningKey = `ghost-dismissed-${result.domain || location.hostname}-${result.riskLevel}`;
    if (sessionStorage.getItem(warningKey) === '1') return;

    const overlay = document.createElement('div');
    overlay.id = 'ghost-site-risk-overlay';
    overlay.style.cssText = [
        'position: fixed',
        'inset: 0',
        'z-index: 2147483647',
        'background: rgba(15, 23, 42, 0.82)',
        'display: flex',
        'align-items: center',
        'justify-content: center',
        'padding: 24px',
        'font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    ].join(';');

    const panel = document.createElement('div');
    panel.style.cssText = [
        'width: min(560px, 94vw)',
        'background: #ffffff',
        'border: 1px solid #fecaca',
        'border-radius: 10px',
        'box-shadow: 0 28px 70px rgba(0, 0, 0, 0.35)',
        'padding: 24px',
        'color: #111827'
    ].join(';');

    const title = document.createElement('div');
    title.textContent = result.riskLevel === 'danger' ? 'Risky Website Blocked' : 'Suspicious Website Warning';
    title.style.cssText = 'font-size: 24px; font-weight: 900; color: #991b1b; margin-bottom: 8px;';

    const subtitle = document.createElement('div');
    subtitle.textContent = `${result.domain || location.hostname} scored ${result.score}/100`;
    subtitle.style.cssText = 'font-size: 15px; color: #4b5563; margin-bottom: 16px;';

    const list = document.createElement('ul');
    list.style.cssText = 'margin: 0 0 18px; padding-left: 20px; color: #374151; line-height: 1.5;';
    (result.issues || []).slice(0, 6).forEach((issue) => {
        const item = document.createElement('li');
        item.textContent = issue;
        list.appendChild(item);
    });

    const actions = document.createElement('div');
    actions.style.cssText = 'display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap;';

    const leaveBtn = document.createElement('button');
    leaveBtn.textContent = 'Leave Site';
    leaveBtn.style.cssText = 'border: none; border-radius: 8px; padding: 11px 16px; background: #dc2626; color: #ffffff; font-weight: 800; cursor: pointer;';
    leaveBtn.addEventListener('click', () => {
        window.location.href = 'about:blank';
    });

    const continueBtn = document.createElement('button');
    continueBtn.textContent = 'Continue Anyway';
    continueBtn.style.cssText = 'border: 1px solid #d1d5db; border-radius: 8px; padding: 11px 16px; background: #ffffff; color: #111827; font-weight: 800; cursor: pointer;';
    continueBtn.addEventListener('click', () => {
        sessionStorage.setItem(warningKey, '1');
        overlay.remove();
    });

    const trustBtn = document.createElement('button');
    trustBtn.textContent = 'Trust Site';
    trustBtn.style.cssText = 'border: 1px solid #2563eb; border-radius: 8px; padding: 11px 16px; background: #eff6ff; color: #1d4ed8; font-weight: 800; cursor: pointer;';
    trustBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({
            type: 'TRUST_SITE',
            domain: result.domain || location.hostname
        }, () => {
            sessionStorage.setItem(warningKey, '1');
            overlay.remove();
        });
    });

    actions.appendChild(continueBtn);
    actions.appendChild(trustBtn);
    actions.appendChild(leaveBtn);
    panel.appendChild(title);
    panel.appendChild(subtitle);
    panel.appendChild(list);
    panel.appendChild(actions);
    overlay.appendChild(panel);
    document.documentElement.appendChild(overlay);
}

chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'GHOST_SITE_RISK') {
        showSiteRiskWarning(message.result);
    }
});

let lastMonitoredUrl = location.href;

function requestContinuousScan() {
    if (!/^https?:\/\//i.test(location.href)) return;

    chrome.runtime.sendMessage({
        type: 'PAGE_READY_SCAN',
        url: location.href
    }, (response) => {
        if (chrome.runtime.lastError) return;
        const result = response && response.result;
        if (result && !result.suppressPopup && (result.riskLevel === 'danger' || result.riskLevel === 'warning')) {
            showSiteRiskWarning(result);
        }
    });
}

requestContinuousScan();

chrome.storage.local.get([STORAGE_KEYS.adBlockSettings], (data) => {
    updateCosmeticAdBlock(data[STORAGE_KEYS.adBlockSettings] || {});
});

setInterval(() => {
    if (location.href === lastMonitoredUrl) return;
    lastMonitoredUrl = location.href;
    requestContinuousScan();
    if (isGmailPage() && isEnabled) {
        setTimeout(runGmailSecurityCheckup, 1200);
    }
}, 3000);

function updateCosmeticAdBlock(settings = {}) {
    const merged = { ...DEFAULT_AD_BLOCK_SETTINGS, ...settings };
    const existing = document.getElementById('ghost-cosmetic-adblock');

    if (existing) existing.remove();
    if (merged.enabled === false || merged.cosmetic === false) return;

    const style = document.createElement('style');
    style.id = 'ghost-cosmetic-adblock';
    style.textContent = `
        iframe[src*="doubleclick.net"],
        iframe[src*="googlesyndication.com"],
        iframe[src*="googleadservices.com"],
        iframe[src*="googletagservices.com"],
        iframe[src*="adnxs.com"],
        iframe[src*="amazon-adsystem.com"],
        iframe[src*="taboola.com"],
        iframe[src*="outbrain.com"],
        iframe[src*="rubiconproject.com"],
        iframe[src*="openx.net"],
        iframe[src*="pubmatic.com"],
        iframe[src*="criteo.com"],
        [id^="google_ads_"],
        [id*="google_ads_iframe"],
        [id*="div-gpt-ad"],
        [id*="ad-slot" i],
        [id*="ad_unit" i],
        [id*="ad-wrapper" i],
        [class*="ad-slot" i],
        [class*="ad-unit" i],
        [class*="ad-wrapper" i],
        [class*="ad-container"],
        [class*="ads-container"],
        [class*="advertisement"],
        [class*="sponsored" i],
        [class*="promoted" i],
        [class*="native-ad" i],
        [class*="taboola" i],
        [class*="outbrain" i],
        [class*="ad_banner" i],
        [class*="ad-banner" i],
        [class*="adsbygoogle" i],
        [data-testid*="placementTracking" i],
        [aria-label*="advertisement" i],
        [aria-label*="sponsored" i],
        [data-ad],
        [data-ad-slot],
        [data-ad-client],
        [data-ad-format],
        [data-google-query-id],
        ins.adsbygoogle,
        [data-testid*="ad" i] {
            display: none !important;
            visibility: hidden !important;
            min-height: 0 !important;
            height: 0 !important;
        }
    `;
    document.documentElement.appendChild(style);
}


// 3. The Active Interceptor
window.addEventListener('keydown', (e) => {
    if (!isEnabled) return;
    if (e.key !== 'Enter' || e.shiftKey) return;

    // Check whitelist
    const currentHost = window.location.hostname;
    if (whitelist.includes(currentHost)) return;

    const target = e.target;
    const text = target.value || target.innerText || '';
    let detectedThreats = [];

    const allPatterns = { ...PATTERNS, ...customPatterns };
    for (const type in allPatterns) {
        allPatterns[type].regex.lastIndex = 0;
        if (allPatterns[type].regex.test(text)) {
            detectedThreats.push(allPatterns[type].label || type);
        }
    }

    if (detectedThreats.length === 0) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const clean = sanitizeText(text);
    try {
        if (target.isContentEditable) {
            target.focus();
            document.execCommand('selectAll', false, null);
            document.execCommand('insertText', false, clean);
        } else {
            target.value = clean;
            target.dispatchEvent(new Event('input', { bubbles: true }));
        }
    } catch (err) {
        console.error('Ghost Guard: Failed to insert redacted text.', err);
    }

    target.classList.add('ghost-flash');
    showWarning(detectedThreats);
    console.log('Ghost Guard: Threat neutralized. Data redacted.');

    // Browser notification
    if (chrome && chrome.notifications) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icon128.png'),
            title: 'Ghost Guard Alert',
            message: `Blocked ${detectedThreats.length} threat(s): ${detectedThreats.slice(0, 3).join(', ')}`
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.warn('Notification failed:', chrome.runtime.lastError);
            }
        });
    }

    incrementStats({
        timestamp: new Date().toISOString(),
        threats: detectedThreats,
        original: text.slice(0, 300),
        redacted: clean.slice(0, 300)
    });

    setTimeout(() => target.classList.remove('ghost-flash'), 1500);
}, { capture: true });

// Debounce utility
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

document.addEventListener('focusin', (event) => {
    if (!isEnabled || !isTextInputTarget(event.target)) return;
    updateThreatAnalysisPanel(getEditableText(event.target));
});

document.addEventListener('input', (event) => {
    updateThreatAnalysisPanelDebounced(event.target);
}, { capture: true });

document.addEventListener('paste', (event) => {
    if (!isEnabled || !isTextInputTarget(event.target)) return;
    setTimeout(() => updateThreatAnalysisPanel(getEditableText(event.target)), 0);
}, { capture: true });

initGmailSecurityCheckup();

// Clipboard monitoring
document.addEventListener('paste', debounce((e) => {
    if (!isEnabled) return;

    const currentHost = window.location.hostname;
    if (whitelist.includes(currentHost)) return;

    const pastedText = e.clipboardData.getData('text');
    let detectedThreats = [];

    const allPatterns = { ...PATTERNS, ...customPatterns };
    for (const type in allPatterns) {
        allPatterns[type].regex.lastIndex = 0;
        if (allPatterns[type].regex.test(pastedText)) {
            detectedThreats.push(allPatterns[type].label || type);
        }
    }

    if (detectedThreats.length === 0) return;

    e.preventDefault();
    const clean = sanitizeText(pastedText);
    e.clipboardData.setData('text', clean);

    showWarning(detectedThreats);
    console.log('Ghost Guard: Clipboard threat neutralized.');

    if (chrome && chrome.notifications) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icon128.png'),
            title: 'Ghost Guard Clipboard Alert',
            message: `Blocked paste with ${detectedThreats.length} threat(s): ${detectedThreats.slice(0, 3).join(', ')}`
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.warn('Clipboard notification failed:', chrome.runtime.lastError);
            }
        });
    }

    incrementStats({
        timestamp: new Date().toISOString(),
        threats: detectedThreats,
        original: pastedText.slice(0, 300),
        redacted: clean.slice(0, 300),
        source: 'clipboard'
    });
}, 300)); // 300ms debounce
