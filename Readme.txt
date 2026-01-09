🛡️ GhostText: Cyber Defense (v3.0)

GhostText is an advanced browser-based Data Loss Prevention (DLP) firewall designed for the AI era. It acts as an active interceptor between your keyboard and AI chatbots (like ChatGPT, Claude, Gemini), automatically detecting and redacting sensitive data before it leaves your browser.

"Stop data leaks before they happen."

🚀 Features

🔒 Active Interception

GhostText hooks into the browser's event loop at the Capture Phase, intercepting the Enter key milliseconds before the data is submitted. If a threat is detected, the submission is blocked, the data is redacted, and the safe version is inserted back into the input field.

🕵️‍♂️ Comprehensive Threat Detection

We don't just stop emails. GhostText detects over 15 types of sensitive data:

Personal Identity (PII): Emails, Phone Numbers, SSNs.

Financial Data: Credit Cards (13-16 digits), Crypto Wallet Addresses (ETH/BTC), Stripe Live Keys.

Developer Secrets: AWS Access Keys, Google Cloud API Keys, Slack Tokens, GitHub Tokens, SSH Private Keys, JWTs.

Network Infrastructure: IPv4 Addresses, IPv6 Addresses, MAC Addresses.

🎛️ Cyberpunk Control Panel

Kill Switch: Toggle the active defense system On/Off instantly via the popup menu.

Live Stats: Track the number of data leaks prevented in real-time with a persistent counter.

Visual Feedback: Input fields flash Hacker Green when a threat is successfully neutralized.

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
