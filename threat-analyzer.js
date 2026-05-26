(function (root) {
    const URGENCY_TERMS = [
        'verify now',
        'account suspended',
        'password expired',
        'urgent',
        'immediately',
        'limited time',
        'login required',
        'payment failed'
    ];

    const TRUSTED_DOMAINS = [
        'paypal.com',
        'google.com',
        'microsoft.com',
        'apple.com',
        'facebook.com',
        'instagram.com',
        'linkedin.com',
        'amazon.com',
        'netflix.com'
    ];

    const SHORTENED_DOMAINS = [
        'bit.ly',
        'tinyurl.com',
        't.co',
        'goo.gl',
        'ow.ly',
        'is.gd',
        'cutt.ly',
        'rebrand.ly'
    ];

    const UNSAFE_URL_WORDS = [
        'login',
        'verify',
        'reset',
        'password',
        'secure',
        'account',
        'update'
    ];

    function escapeRegExp(value) {
        return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function normalizeUrl(value) {
        const raw = String(value || '').trim().replace(/[.,;:!?]+$/g, '');
        if (!raw) return null;

        try {
            return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
        } catch (error) {
            return null;
        }
    }

    function normalizeDomain(domain) {
        return String(domain || '').toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
    }

    function getRegistrableDomain(hostname) {
        const domain = normalizeDomain(hostname);
        const labels = domain.split('.').filter(Boolean);
        if (labels.length <= 2 || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) return domain;
        return labels.slice(-2).join('.');
    }

    function addUrlCandidate(items, seen, url, visibleText) {
        const parsed = normalizeUrl(url);
        if (!parsed) return;

        const normalizedHref = parsed.href;
        const key = `${normalizedHref}|${visibleText || ''}`;
        if (seen.has(key)) return;
        seen.add(key);

        items.push({
            url: normalizedHref,
            raw: String(url).trim(),
            visibleText: visibleText ? String(visibleText).replace(/<[^>]*>/g, '').trim() : ''
        });
    }

    function extractUrls(text) {
        const value = String(text || '');
        const urls = [];
        const seen = new Set();

        value.replace(/\[([^\]]{1,120})\]\((https?:\/\/[^)\s]+|www\.[^)\s]+)\)/gi, (match, visibleText, href) => {
            addUrlCandidate(urls, seen, href, visibleText);
            return match;
        });

        value.replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, (match, href, visibleText) => {
            addUrlCandidate(urls, seen, href, visibleText);
            return match;
        });

        value.replace(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi, (match) => {
            addUrlCandidate(urls, seen, match, '');
            return match;
        });

        return urls;
    }

    function detectUrgency(text) {
        const value = String(text || '').toLowerCase();
        return URGENCY_TERMS
            .filter((term) => new RegExp(`\\b${escapeRegExp(term)}\\b`, 'i').test(value))
            .map((term) => ({
                type: 'urgency',
                message: `Urgent or alarming phrase detected: "${term}"`,
                value: term
            }));
    }

    function leetNormalize(value, oneAs) {
        return String(value || '')
            .toLowerCase()
            .replace(/0/g, 'o')
            .replace(/1/g, oneAs)
            .replace(/3/g, 'e')
            .replace(/@/g, 'a')
            .replace(/\$/g, 's');
    }

    function levenshteinDistance(a, b) {
        const left = String(a || '');
        const right = String(b || '');
        const rows = Array.from({ length: left.length + 1 }, (_, index) => [index]);

        for (let col = 1; col <= right.length; col += 1) {
            rows[0][col] = col;
        }

        for (let row = 1; row <= left.length; row += 1) {
            for (let col = 1; col <= right.length; col += 1) {
                const cost = left[row - 1] === right[col - 1] ? 0 : 1;
                rows[row][col] = Math.min(
                    rows[row - 1][col] + 1,
                    rows[row][col - 1] + 1,
                    rows[row - 1][col - 1] + cost
                );
            }
        }

        return rows[left.length][right.length];
    }

    function detectLookalikeDomain(domain) {
        const host = normalizeDomain(domain);
        const registrableDomain = getRegistrableDomain(host);
        if (!registrableDomain || TRUSTED_DOMAINS.includes(registrableDomain)) return null;

        const candidateName = registrableDomain.split('.')[0] || '';
        const candidateTld = registrableDomain.split('.').slice(1).join('.');

        for (const trustedDomain of TRUSTED_DOMAINS) {
            const trustedParts = trustedDomain.split('.');
            const trustedName = trustedParts[0];
            const trustedTld = trustedParts.slice(1).join('.');
            const normalizedNames = [
                leetNormalize(candidateName, 'l'),
                leetNormalize(candidateName, 'i')
            ];
            const exactLeetMatch = normalizedNames.includes(trustedName) && candidateName !== trustedName;
            const nearMatch = candidateTld === trustedTld && levenshteinDistance(candidateName, trustedName) === 1;

            if (exactLeetMatch || nearMatch) {
                return {
                    type: 'lookalike_domain',
                    message: `Possible lookalike for ${trustedDomain}`,
                    value: registrableDomain,
                    trustedDomain
                };
            }
        }

        return null;
    }

    function visibleTextLooksLikeUrl(value) {
        return /^(?:https?:\/\/|www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:\/.*)?$/i.test(String(value || '').trim());
    }

    function analyzeUrl(urlEntry) {
        const entry = typeof urlEntry === 'string' ? { url: urlEntry, visibleText: '' } : (urlEntry || {});
        const parsed = normalizeUrl(entry.url || entry.raw);
        if (!parsed) return [];

        const flags = [];
        const host = normalizeDomain(parsed.hostname);
        const registrableDomain = getRegistrableDomain(host);
        const labels = host.split('.').filter(Boolean);
        const pathAndQuery = `${parsed.pathname}${parsed.search}`;

        if (parsed.protocol === 'http:') {
            flags.push({
                type: 'suspicious_url',
                message: 'HTTP link is not encrypted',
                value: parsed.href
            });
        }

        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
            flags.push({
                type: 'suspicious_url',
                message: 'URL uses an IP address instead of a domain',
                value: host
            });
        }

        if (labels.length >= 4) {
            flags.push({
                type: 'suspicious_url',
                message: 'URL has many subdomains',
                value: host
            });
        }

        if (/%[0-9a-f]{2}/i.test(parsed.href) || /[{}[\]^`\\|]/.test(parsed.href) || parsed.href.includes('@')) {
            flags.push({
                type: 'suspicious_url',
                message: 'URL contains unusual characters',
                value: parsed.href
            });
        }

        if (host.includes('xn--')) {
            flags.push({
                type: 'suspicious_url',
                message: 'Punycode domain can hide lookalike characters',
                value: host
            });
        }

        if (SHORTENED_DOMAINS.includes(registrableDomain)) {
            flags.push({
                type: 'suspicious_url',
                message: 'Shortened URL hides the final destination',
                value: registrableDomain
            });
        }

        const lookalike = detectLookalikeDomain(host);
        if (lookalike) flags.push(lookalike);

        const unsafeWords = UNSAFE_URL_WORDS.filter((word) => new RegExp(`\\b${word}\\b`, 'i').test(pathAndQuery));
        if (unsafeWords.length > 0 && flags.some((flag) => flag.type === 'suspicious_url' || flag.type === 'lookalike_domain')) {
            flags.push({
                type: 'unsafe_pattern',
                message: `Sensitive action words in suspicious URL: ${unsafeWords.join(', ')}`,
                value: parsed.href
            });
        }

        if (entry.visibleText && visibleTextLooksLikeUrl(entry.visibleText)) {
            const visibleUrl = normalizeUrl(entry.visibleText);
            if (visibleUrl && getRegistrableDomain(visibleUrl.hostname) !== registrableDomain) {
                flags.push({
                    type: 'unsafe_pattern',
                    message: 'Visible link text does not match the actual URL',
                    value: `${entry.visibleText} -> ${parsed.href}`
                });
            }
        }

        return flags;
    }

    function calculateThreatScore(flags) {
        const weights = {
            urgency: 12,
            suspicious_url: 20,
            lookalike_domain: 35,
            unsafe_pattern: 18
        };

        const score = (flags || []).reduce((total, flag) => total + (weights[flag.type] || 10), 0);
        return Math.min(100, score);
    }

    function getRecommendation(riskLevel, flags) {
        if (riskLevel === 'high') {
            return 'Do not open links or share credentials. Verify the sender through a trusted channel.';
        }

        if (riskLevel === 'medium') {
            return 'Review the flagged links and language before sending or acting on this text.';
        }

        if (flags.length > 0) {
            return 'Only minor signals found. Double-check links before trusting the message.';
        }

        return 'No obvious phishing indicators found in this text.';
    }

    function analyzeThreatText(text) {
        const flags = [
            ...detectUrgency(text),
            ...extractUrls(text).flatMap(analyzeUrl)
        ];
        const score = calculateThreatScore(flags);
        const riskLevel = score >= 60 ? 'high' : score >= 25 ? 'medium' : 'low';

        return {
            riskLevel,
            score,
            flags,
            recommendation: getRecommendation(riskLevel, flags)
        };
    }

    const api = {
        extractUrls,
        detectUrgency,
        analyzeUrl,
        detectLookalikeDomain,
        calculateThreatScore,
        analyzeThreatText
    };

    root.GhostTextThreatAnalyzer = api;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : window);
