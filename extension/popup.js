// ==============================================================================
// VERTEX BROWSER EXTENSION - POPUP CONTROLLER
// ==============================================================================

document.addEventListener("DOMContentLoaded", async () => {
  const urlInput = document.getElementById("url-input");
  const btnCheck = document.getElementById("btn-check");
  const resultBox = document.getElementById("result-box");
  const resultTier = document.getElementById("result-tier");
  const resultDesc = document.getElementById("result-desc");
  const openBenchBtn = document.getElementById("open-bench-btn");

  // Open Test Bench
  if (openBenchBtn) {
    openBenchBtn.onclick = () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("test_page.html") });
    };
  }

  // Pre-fill active tab URL if available
  if (chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http")) {
        urlInput.value = tabs[0].url;
      }
    });
  }

  // Manual URL Scan
  btnCheck.onclick = () => {
    const url = urlInput.value.trim();
    if (!url) return;

    btnCheck.innerText = "...";
    chrome.runtime.sendMessage({ type: "SCAN_URL", url: url }, (data) => {
      btnCheck.innerText = "Scan";
      if (!data) {
        resultBox.style.display = "block";
        resultTier.innerText = "Scan Failed";
        resultDesc.innerText = "Unable to inspect URL.";
        return;
      }

      resultBox.style.display = "block";
      const isRisk = data.risk_tier === "High" || data.risk_tier === "Critical";
      resultTier.style.color = isRisk ? "#dc2626" : "#16a34a";
      resultTier.innerText = `Verdict: ${data.risk_tier} Risk (${(data.risk_score * 100).toFixed(0)}%)`;
      resultDesc.innerText = data.xai_explanation || "Link inspected and validated by Vertex autonomous model engine.";
    });
  };
});
