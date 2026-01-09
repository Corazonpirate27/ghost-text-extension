document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('toggleSecure');
    const countDisplay = document.getElementById('blockCount');
    const statusLabel = document.querySelector('.toggle-label');

    // 1. Load Saved Settings
    chrome.storage.local.get(['enabled', 'blockedCount'], (data) => {
        // Toggle State
        const isEnabled = data.enabled !== false; // Default to true
        toggle.checked = isEnabled;
        updateStatusText(isEnabled);

        // Counter State
        countDisplay.innerText = data.blockedCount || 0;
    });

    // 2. Handle Toggle Clicks
    toggle.addEventListener('change', () => {
        const isEnabled = toggle.checked;
        chrome.storage.local.set({ enabled: isEnabled });
        updateStatusText(isEnabled);
    });

    // 3. Live Counter Updates (Listen for content script)
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.blockedCount) {
            // Animate the number change
            countDisplay.style.transform = "scale(1.2)";
            countDisplay.style.color = "#fff";
            setTimeout(() => {
                countDisplay.innerText = changes.blockedCount.newValue;
                countDisplay.style.transform = "scale(1)";
                countDisplay.style.color = "#00ff41";
            }, 100);
        }
    });

    function updateStatusText(enabled) {
        if (enabled) {
            statusLabel.innerText = "SYSTEM ARMED";
            statusLabel.style.color = "#00ff41";
        } else {
            statusLabel.innerText = "SYSTEM DISARMED";
            statusLabel.style.color = "#555";
        }
    }
});
