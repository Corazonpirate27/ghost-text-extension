🛡️ GhostText: Cyber Defense (v4.0)

GhostText is an advanced browser-based Data Loss Prevention (DLP) firewall designed for the AI era. It acts as an active interceptor between your keyboard and AI chatbots (like ChatGPT, Claude, Gemini), automatically detecting and redacting sensitive data before it leaves your browser.

"Stop data leaks before they happen."

🚀 Features

🔒 Active Interception

GhostText hooks into the browser's event loop at the Capture Phase, intercepting the Enter key milliseconds before the data is submitted. If a threat is detected, the submission is blocked, the data is redacted, and the safe version is inserted back into the input field.

🕵️‍♂️ Comprehensive Threat Detection

We don't just stop emails. GhostText detects over 20 types of sensitive data with high precision:

Personal Identity (PII): Emails, Phone Numbers (Context-aware detection), SSNs.

Financial Data: Credit Cards (13-16 digits), Crypto Wallet Addresses (ETH/BTC), Stripe Live Keys.

Developer Secrets: AWS Access Keys, Google Cloud API Keys, Slack Tokens, GitHub Tokens, SSH Private Keys, JWTs.

Network Infrastructure: IPv4 Addresses (Validates 0-255 range), IPv6 Addresses, MAC Addresses.

Sentence Detection: Catches full sentences like "My password is xyz" or "The API key is abc".

Custom Rules: Add your own regex patterns for unique threats.

🛡️ Site Whitelisting

Whitelist trusted domains to skip protection on internal tools or known safe sites.

📊 Local Logs & Export

View blocked events in the popup and keep a recent history of threats handled. Export logs as JSON for review or compliance.

🔔 Browser Notifications

Get instant alerts when threats are blocked, even if you're not looking at the popup.

📋 Clipboard Monitoring

Scans pasted content for sensitive data before it enters input fields. Optimized with debouncing for better performance.

🎛️ Control Panel

Kill Switch: Toggle the active defense system On/Off instantly via the popup menu.

Live Stats: Track the number of data leaks prevented in real-time with a persistent counter.

Threat Analytics: See a breakdown of the most common threats blocked.

Educational Tips: Learn security best practices with rotating tips in the popup.

Local Logs: View blocked events in the popup and keep a recent history of threats handled.

Sentence Detection: GhostText now catches full prompt sentences that include passwords, API keys, credit cards, SSNs and other sensitive disclosures.

Visual Feedback: Input fields flash blue when a threat is successfully neutralized.

Custom Rules: Add your own regex patterns to protect company-specific secrets.

Site Whitelist: Bypass protection on trusted domains like internal tools.

Reset Counter: Clear the blocked events count when needed.

Clear Logs: Remove all stored logs to free up space.

📦 Installation (Developer Mode)

Since this is a specialized security tool, you can install it directly from the source:

Download/Clone this repository to your computer.

Open Google Chrome (or Edge/Brave) and navigate to chrome://extensions/.

Toggle Developer mode in the top-right corner.

Click Load unpacked in the top-left corner.

Select the folder containing the manifest.json file.

The GhostText shield icon should appear in your toolbar.

🎮 How to Test

Open the extension popup and ensure the system is ARMED.

Go to ChatGPT or any text input field.

Type a fake credit card number: 4532 1234 5678 9012.

Press Enter.

Result: The send will be blocked, the text will change to [CC_REDACTED], and the box will flash green.

🛡️ Privacy Policy

Effective Date: January 2026

No Data Collection: GhostText does NOT collect, store, or transmit any keystrokes, input data, or browsing history.

Local Processing: All Regular Expression (Regex) matching occurs 100% locally within your browser sandbox.

Permissions: The storage permission is used solely to save your On/Off preference and local stats counter.

⚠️ Disclaimer

This tool is a defensive Proof of Concept (PoC) for Endpoint Security. While it effectively prevents accidental data leakage, no client-side tool is a replacement for comprehensive enterprise security policies. Always handle sensitive data with care.

Built with ❤️ for the Cyber Security Community.
