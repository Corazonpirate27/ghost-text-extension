// content.js - PRO VERSION 2.0

const PATTERNS = {
    email: { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[EMAIL_REDACTED]' },
    phone: { regex: /(\+\d{1,2}\s?)?1?\-?\.?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, replacement: '[PHONE_REDACTED]' },
    // NEW: Credit Cards (Matches 13-16 digits with spaces/dashes)
    creditCard: { regex: /\b(?:\d[ -]*?){13,16}\b/g, replacement: '[CREDIT_CARD_REDACTED]' },
    // NEW: IP Addresses (IPv4)
    ip: { regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, replacement: '[IP_REDACTED]' }
};

// Global State
let isEnabled = true;

// 1. Initialize State
chrome.storage.local.get(['enabled'], (data) => {
    isEnabled = data.enabled !== false;
});

// 2. Listen for Toggle Changes
chrome.storage.onChanged.addListener((changes) => {
    if (changes.enabled) isEnabled = changes.enabled.newValue;
});

function incrementCounter() {
    chrome.storage.local.get(['blockedCount'], (data) => {
        const newCount = (data.blockedCount || 0) + 1;
        chrome.storage.local.set({ blockedCount: newCount });
    });
}

function checkRisk(text) {
    for (const type in PATTERNS) {
        if (PATTERNS[type].regex.test(text)) return true;
    }
    return false;
}

function sanitizeText(text) {
    let cleanText = text;
    for (const type in PATTERNS) {
        cleanText = cleanText.replace(PATTERNS[type].regex, PATTERNS[type].replacement);
    }
    return cleanText;
}

// 3. The Nuclear Interceptor
window.addEventListener('keydown', (e) => {
    if (!isEnabled) return; // Exit if turned off

    if (e.key === 'Enter' && !e.shiftKey) {
        const target = e.target;
        if (target.isContentEditable || target.tagName === 'TEXTAREA' || target.tagName === 'INPUT') {
            const text = target.value || target.innerText;

            if (checkRisk(text)) {
                console.log("[GhostText] 🛑 BLOCKED");
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();

                const clean = sanitizeText(text);

                // Update UI
                if (target.isContentEditable) {
                    document.execCommand('selectAll', false, null);
                    document.execCommand('insertText', false, clean);
                } else {
                    target.value = clean;
                    target.dispatchEvent(new Event('input', { bubbles: true }));
                }

                // Increment Stats
                incrementCounter();

                // Visual Feedback
                target.style.setProperty("border", "5px solid #00cc00", "important");
                setTimeout(() => target.style.removeProperty("border"), 1000);
            }
        }
    }
}, { capture: true });
