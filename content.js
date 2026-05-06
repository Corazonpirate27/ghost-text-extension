// content.js - GhostText v4 (Logs + Simple UI + Advanced protection)

console.log("GhostText v4: Active defense with local logging enabled 🛡️");

let isEnabled = true;
const STORAGE_KEYS = {
    enabled: 'enabled',
    blockedCount: 'blockedCount',
    logs: 'eventLogs',
    customRules: 'customRules',
    whitelist: 'whitelist'
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
});

// 1. Connect to Chrome Storage (Popup Communication)
if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get([STORAGE_KEYS.enabled], (data) => {
        isEnabled = data.enabled !== false;
        console.log(`[GhostText] System startup: ${isEnabled ? 'ARMED' : 'DISARMED'}`);
    });

    chrome.storage.onChanged.addListener((changes) => {
        if (changes[STORAGE_KEYS.enabled]) {
            isEnabled = changes[STORAGE_KEYS.enabled].newValue;
            console.log(`[GhostText] System status changed: ${isEnabled ? 'ARMED' : 'DISARMED'}`);
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
    googleApiKey: { regex: /AIza[0-9A-Za-z\-_]{35}/g, replacement: '[GOOGLE_API_KEY_REDACTED]', label: 'Google API Key' },
    slackToken: { regex: /xox[baprs]-[a-zA-Z0-9-]{10,48}/g, replacement: '[SLACK_TOKEN_REDACTED]', label: 'Slack Token' },
    githubToken: { regex: /(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}/g, replacement: '[GITHUB_TOKEN_REDACTED]', label: 'GitHub Token' },
    privateKey: { regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g, replacement: '[PRIVATE_KEY_BLOCK_REDACTED]', label: 'Private Key Block' },

    passwordSentence: { regex: /\b(?:my|the|your)\b\s+(?:password|passphrase|pin)\s*(?:is|:|=)?\s*[^\n]{4,80}/gi, replacement: '[PASSWORD_REDACTED]', label: 'Password Sentence' },
    apiKeySentence: { regex: /\b(?:my|the|your)\b\s+(?:api key|access key|secret key|token|stripe key|aws key|google api key)\s*(?:is|:|=)?\s*[A-Za-z0-9\-_]{16,}/gi, replacement: '[API_KEY_REDACTED]', label: 'API Key Sentence' },
    ccSentence: { regex: /\b(?:my|the|your)\b\s+(?:credit card|card number)\s*(?:is|:|=)?\s*(?:\d[ -]*){13,16}\b/gi, replacement: '[CC_REDACTED]', label: 'Credit Card Sentence' },
    ssnSentence: { regex: /\b(?:my|the|your)\b\s+(?:social security number|ssn)\s*(?:is|:|=)?\s*\d{3}-\d{2}-\d{4}/gi, replacement: '[SSN_REDACTED]', label: 'SSN Sentence' },
    privateKeySentence: { regex: /\b(?:my|the|your)\b\s+private key\s*(?:is|:|=)?\s*-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/gi, replacement: '[PRIVATE_KEY_BLOCK_REDACTED]', label: 'Private Key Sentence' }
};

function sanitizeText(text) {
    let cleanText = text;
    const allPatterns = { ...PATTERNS, ...customPatterns };
    for (const type in allPatterns) {
        allPatterns[type].regex.lastIndex = 0;
        if (allPatterns[type].regex.test(cleanText)) {
            console.log(`[GhostText] Redacting ${type}`);
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
    header.innerText = '⚠️ SECURITY ALERT ⚠️';

    const body = document.createElement('div');
    body.className = 'ghost-modal-body';
    body.innerHTML = `
        <p>GhostText intercepted a potential data leak.</p>
        <p>This content is considered <strong>RISKY</strong> because it contains:</p>
        <span id="ghost-threat-list" class="ghost-threat-list"></span>
        <p>The sensitive content has been automatically redacted.</p>
    `;

    const footer = document.createElement('div');
    footer.className = 'ghost-modal-footer';

    const btn = document.createElement('button');
    btn.className = 'ghost-modal-btn';
    btn.innerText = 'ACKNOWLEDGE';
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
        console.error('GhostText: Failed to insert redacted text.', err);
    }

    target.classList.add('ghost-flash');
    showWarning(detectedThreats);
    console.log('GhostText: Threat neutralized. Data redacted.');

    // Browser notification
    if (chrome && chrome.notifications) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('logo.svg'),
            title: 'GhostText Alert',
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
    console.log('GhostText: Clipboard threat neutralized.');

    if (chrome && chrome.notifications) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('logo.svg'),
            title: 'GhostText Clipboard Alert',
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
