// popup.js
document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('toggleSecure');
    const countDisplay = document.getElementById('blockCount');

    // 1. Load saved settings
    chrome.storage.local.get(['enabled', 'blockedCount'], (data) => {
        toggle.checked = data.enabled !== false; // Default to TRUE
        countDisplay.innerText = data.blockedCount || 0;
    });

    // 2. Listen for toggle changes
    toggle.addEventListener('change', () => {
        chrome.storage.local.set({ enabled: toggle.checked });
    });

    // 3. Listen for updates from content script (Real-time counter update)
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.blockedCount) {
            countDisplay.innerText = changes.blockedCount.newValue;
        }
    });
});
