// content.js - Ultimate "Paranoid" Edition (Developer Defense)

console.log("GhostText: Ultimate Defense Protocol Engaged 🛡️");

let isEnabled = true; // Default to ON

// 1. Connect to Chrome Storage (Popup Communication)
if (typeof chrome !== 'undefined' && chrome.storage) {
    // Load initial state
    chrome.storage.local.get(['enabled'], (data) => {
        isEnabled = data.enabled !== false;
    });

    // Listen for changes from the popup
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.enabled) {
            isEnabled = changes.enabled.newValue;
            console.log(`[GhostText] System status changed: ${isEnabled ? 'ARMED' : 'DISARMED'}`);
        }
    });
}

// Function to update the "Threats Blocked" counter
function incrementStats() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['blockedCount'], (data) => {
            const current = data.blockedCount || 0;
            chrome.storage.local.set({ blockedCount: current + 1 });
        });
    }
}

// 2. The Threat Library (Regex Patterns)
const PATTERNS = {
    // --- Personal Identity ---
    email: { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[EMAIL_REDACTED]' },
    // Uses lookbehind for space or boundary for start of number to avoid consuming preceding words
    phone: { regex: /(?:(?:\b|(?<=\s))\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, replacement: '[PHONE_REDACTED]' },
    ssn: { regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[SSN_REDACTED]' },

    // --- Financial ---
    creditCard: { regex: /\b(?:\d[ -]*?){13,16}\b/g, replacement: '[CC_REDACTED]' },
    cryptoWallet: { regex: /\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b/g, replacement: '[CRYPTO_WALLET_REDACTED]' },
    stripeKey: { regex: /(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}/g, replacement: '[STRIPE_KEY_REDACTED]' },

    // --- Network/Infra ---
    // Improved IPv4 regex to check range 0-255
    ipv4: { regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, replacement: '[IPV4_REDACTED]' },
    macAddress: { regex: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g, replacement: '[MAC_ADDR_REDACTED]' },

    // --- Developer Keys ---
    awsAccessKey: { regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, replacement: '[AWS_KEY_REDACTED]' },
    googleApiKey: { regex: /AIza[0-9A-Za-z\-_]{35}/g, replacement: '[GOOGLE_API_KEY_REDACTED]' },
    slackToken: { regex: /xox[baprs]-[a-zA-Z0-9-]{10,48}/g, replacement: '[SLACK_TOKEN_REDACTED]' },
    githubToken: { regex: /(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}/g, replacement: '[GITHUB_TOKEN_REDACTED]' },
    privateKey: { regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g, replacement: '[PRIVATE_KEY_BLOCK_REDACTED]' }
};

function sanitizeText(text) {
    let cleanText = text;
    for (const type in PATTERNS) {
        if (PATTERNS[type].regex.test(cleanText)) {
            console.log(`[GhostText] Redacting ${type}`);
            cleanText = cleanText.replace(PATTERNS[type].regex, PATTERNS[type].replacement);
        }
    }
    return cleanText;
}

// 3. The Active Interceptor
window.addEventListener('keydown', (e) => {
    // Exit if disabled
    if (!isEnabled) return;

    // Only intercept the "Enter" key
    if (e.key === 'Enter' && !e.shiftKey) {
        
        const target = e.target;
        const text = target.value || target.innerText || "";

        // Check if any threat exists
        let hasThreat = false;
        for (const type in PATTERNS) {
            // Reset lastIndex for global regexes to ensure correct testing
            PATTERNS[type].regex.lastIndex = 0;
            if (PATTERNS[type].regex.test(text)) {
                hasThreat = true;
                break;
            }
        }

        if (hasThreat) {
            // A. STOP the send
            e.preventDefault();
            e.stopImmediatePropagation();
            e.stopPropagation();

            // B. Clean the data
            const clean = sanitizeText(text);

            // C. Insert clean text
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
                console.error("GhostText: Failed to insert redacted text.", err);
            }

            // D. Visual Success Indicator
            target.classList.add('ghost-flash');
            
            console.log("GhostText: Threat neutralized. Data redacted.");
            incrementStats();

            setTimeout(() => {
                target.classList.remove('ghost-flash');
            }, 1500);
        }
    }
}, { capture: true });
