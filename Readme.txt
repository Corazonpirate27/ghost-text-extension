# 🛡️ GhostText: AI Privacy Firewall (DLP)

**GhostText** is a browser-based Data Loss Prevention (DLP) agent designed to prevent accidental leakage of PII (Personally Identifiable Information) into Large Language Models (LLMs) like ChatGPT, Claude, and Gemini.

Unlike standard ad-blockers, GhostText acts as an **Active Defense** layer, using a "man-in-the-browser" approach to intercept, sanitize, and redact sensitive data *before* it leaves the user's device.

![Version](https://img.shields.io/badge/version-2.0-blue) ![Security](https://img.shields.io/badge/Security-Active%20Defense-green) ![Platform](https://img.shields.io/badge/Platform-Chrome%20Extension%20(MV3)-orange)

## 🚀 Key Features

* **🔒 Real-Time Redaction:** Instantly detects and blocks sensitive data patterns (Emails, Phone Numbers, IPv4 Addresses, Credit Cards).
* **⚡ Active Interception:** Hooks into the DOM's `keydown` events (Capture Phase) to stop data submission at the network boundary.
* **⚛️ React/SPA Compatible:** Uses advanced DOM manipulation to force updates on shadow-DOM inputs used by modern AI interfaces (ChatGPT/Gemini).
* **🎛️ Kill Switch:** Integrated popup control panel to toggle protections On/Off dynamically.
* **📊 Threat Counter:** Local storage tracking of prevented data leaks for audit purposes.

## 🛠️ Technical Architecture

GhostText operates as a **Manifest V3** Chrome Extension with zero external dependencies.

* **Detection Engine:** Custom Regex-based pattern matching running purely client-side (Privacy by Design).
* **Event Handling:** Utilization of `e.stopImmediatePropagation()` to override default browser submit actions.
* **State Management:** `chrome.storage.local` for persisting user preferences and threat statistics.

## 📦 Installation (Developer Mode)

Since this is a security tool in active development, it is installed via "Unpacked" mode:

1.  Clone or download this repository.
2.  Open Chrome and navigate to `chrome://extensions/`.
3.  Toggle **Developer mode** (top right corner).
4.  Click **Load unpacked**.
5.  Select the `ghost-text-extension` folder.

## 🛡️ Security Logic

The tool monitors for the following PII patterns:

| Risk Type | Detection Method | Action |
| :--- | :--- | :--- |
| **Email Addresses** | Regex (Standard RFC 5322) | Redact to `[EMAIL_REDACTED]` |
| **Phone Numbers** | Regex (International Formats) | Redact to `[PHONE_REDACTED]` |
| **IPv4 Addresses** | Regex (0.0.0.0 - 255.255.255.255) | Redact to `[IP_REDACTED]` |
| **Credit Cards** | Regex (13-16 digit strings) | Redact to `[CC_REDACTED]` |

## ⚠️ Disclaimer

This tool is a Proof of Concept (PoC) for **Endpoint Security Engineering**. It is designed for educational and defensive purposes. While it effectively blocks common data leaks, no client-side tool is 100% impenetrable. Always practice safe data handling.

---
*Built by [corazonpirate27] as part of an Advanced AI Security Portfolio.*
