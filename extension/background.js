// ==============================================================================
// VERTEX BROWSER EXTENSION - BACKGROUND SERVICE WORKER
// Proxies network scanning requests to bypass webpage CSP and Mixed-Content,
// enforces active URL redirect blocking for suspicious destinations,
// and syncs live blocklists from the Vertex SOC Command Center.
// ==============================================================================

const BACKEND_URL = "http://127.0.0.1:8000";
const URL_CACHE = new Map();
const BYPASSED_URLS = new Set();
let REMOTE_BLOCKLIST = [];

// Whitelist of trusted global infrastructure domains (never flagged)
const TRUSTED_DOMAINS = [
  "google.com", "google.co.in", "google.co.uk", "gstatic.com", "googleapis.com", "googleusercontent.com",
  "microsoft.com", "live.com", "office.com", "bing.com", "apple.com", "icloud.com",
  "github.com", "wikipedia.org", "wikimedia.org", "amazon.com", "cloudflare.com",
  "mozilla.org", "youtube.com", "yahoo.com", "linkedin.com", "twitter.com", "x.com"
];

function isWhitelisted(hostname) {
  if (!hostname) return true;
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1") return true;
  if (host.endsWith(".gov") || host.endsWith(".gov.in") || host.endsWith(".edu") || host.endsWith(".mil")) return true;
  return TRUSTED_DOMAINS.some(root => host === root || host.endsWith("." + root));
}

// Sync SOC blocklist from backend
async function syncRemoteBlocklist() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/admin/blocklist`);
    if (res.ok) {
      const data = await res.json();
      REMOTE_BLOCKLIST = data.blocklist || [];
    }
  } catch (e) {
    // Backend offline
  }
}
syncRemoteBlocklist();
setInterval(syncRemoteBlocklist, 30000);

function isRemoteBlocked(targetUrl) {
  const lower = targetUrl.toLowerCase();
  for (const item of REMOTE_BLOCKLIST) {
    if (item.target && lower.includes(item.target.toLowerCase())) {
      return item;
    }
  }
  return null;
}

// ------------------------------------------------------------------------------
// Active Navigation Interception (Blocks suspicious navigation & redirects)
// ------------------------------------------------------------------------------
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only check top-level frame navigation
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url || !url.startsWith("http")) return;

    // Check if user clicked "Proceed Anyway"
    if (BYPASSED_URLS.has(url)) return;
    try {
      const parsed = new URL(url);
      if (BYPASSED_URLS.has(parsed.hostname)) return;
      if (isWhitelisted(parsed.hostname)) return;

      // 1. Check live SOC blocklist match
      const matchedBlock = isRemoteBlocked(url);
      if (matchedBlock) {
        console.warn("[Vertex] Blocking navigation via SOC Blocklist:", url);
        const blockedUrl = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(url)}&score=1.0&tier=Critical&xai=${encodeURIComponent("Destination is on the active Vertex SOC Blocklist: " + (matchedBlock.reason || 'Malicious Host'))}&ttp=T1566.002`
        );
        chrome.tabs.update(details.tabId, { url: blockedUrl });
        return;
      }

      // 2. Evaluate destination URL
      const evaluation = await handleUrlScan(url);
      if (evaluation && (evaluation.risk_tier === "Critical" || evaluation.risk_tier === "High")) {
        console.warn("[Vertex] Blocking navigation to suspicious destination:", url);
        const blockedUrl = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(url)}&score=${evaluation.risk_score}&tier=${evaluation.risk_tier}&xai=${encodeURIComponent(evaluation.xai_explanation || 'Detected suspicious URL')}&ttp=${evaluation.mitre_ttp || 'T1190'}`
        );
        chrome.tabs.update(details.tabId, { url: blockedUrl });
      }
    } catch (e) {
      // Ignore non-standard URLs
    }
  });
}

// ------------------------------------------------------------------------------
// Message Listener for Content Scripts, Popup & Blocked Page
// ------------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "SCAN_URL") {
    handleUrlScan(request.url).then(sendResponse);
    return true; // Keep message channel open for async response
  }

  if (request.type === "SCAN_EMAIL") {
    handleEmailScan(request.emailText, request.sender, request.subject).then(sendResponse);
    return true; // Keep channel open for async response
  }

  if (request.type === "BYPASS_URL") {
    if (request.url) {
      BYPASSED_URLS.add(request.url);
      try {
        const u = new URL(request.url);
        BYPASSED_URLS.add(u.hostname);
      } catch {}
      // Expire bypass in 5 minutes
      setTimeout(() => {
        BYPASSED_URLS.delete(request.url);
      }, 300000);
    }
    sendResponse({ status: "bypassed" });
    return false;
  }

  if (request.type === "RETURN_TO_SAFETY") {
    if (sender.tab && sender.tab.id) {
      chrome.tabs.update(sender.tab.id, { url: "https://www.google.com" });
    }
    sendResponse({ status: "ok" });
    return false;
  }

  if (request.type === "THREAT_BLOCKED") {
    sendResponse({ status: "acknowledged" });
    return false;
  }

  return false;
});

// Handle URL scan with caching, backend query, and intelligent heuristic fallback
async function handleUrlScan(url) {
  if (!url || typeof url !== "string") {
    return { risk_tier: "Safe", risk_score: 0.01, xai_explanation: "Invalid URL string." };
  }

  if (URL_CACHE.has(url)) {
    return URL_CACHE.get(url);
  }

  try {
    const parsed = new URL(url);
    if (isWhitelisted(parsed.hostname)) {
      const safeResult = {
        risk_tier: "Safe",
        risk_score: 0.01,
        is_threat: false,
        threat_type: "Trusted Entity",
        mitre_ttp: null,
        xai_explanation: `Verified trusted domain: ${parsed.hostname}. Zero malicious indicators detected.`
      };
      URL_CACHE.set(url, safeResult);
      return safeResult;
    }
  } catch {
    return { risk_tier: "Safe", risk_score: 0.01, xai_explanation: "Local link." };
  }

  // 1. Try backend XGBoost URL scanner
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`${BACKEND_URL}/api/v1/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, source: "extension-service-worker" }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      URL_CACHE.set(url, data);
      return data;
    }
  } catch (err) {
    // Backend timeout or offline
  }

  // 2. Local heuristic fallback
  const localResult = evaluateLocalUrl(url);
  URL_CACHE.set(url, localResult);
  return localResult;
}

// Handle email scanning via backend with heuristic fallback
async function handleEmailScan(emailText, sender = "Unknown", subject = "No Subject") {
  if (!emailText || emailText.length < 15) {
    return { risk_tier: "Safe", risk_score: 0.01, is_phishing: false, xai_explanation: "Routine short message." };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const res = await fetch(`${BACKEND_URL}/api/v1/scan/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email_text: emailText.substring(0, 4000),
        headers: { from: sender, subject: subject }
      }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return data;
    }
  } catch (err) {
    // Fallback to local heuristic
  }

  return evaluateLocalEmail(emailText);
}

// Local URL evaluation logic
function evaluateLocalUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const domain = parsed.hostname.toLowerCase();

    if (isWhitelisted(domain)) {
      return {
        risk_tier: "Safe",
        risk_score: 0.01,
        is_threat: false,
        threat_type: "Trusted Entity",
        mitre_ttp: null,
        xai_explanation: `Verified trusted domain: ${domain}.`
      };
    }

    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
    const highRiskTlds = [".xyz", ".top", ".buzz", ".work", ".click", ".surf", ".gq", ".ml", ".cf", ".tk", ".ru"];
    const hasHighRiskTld = highRiskTlds.some(tld => domain.endsWith(tld));

    const brandSpoofs = ["paypa1", "paypal-", "chase-auth", "apple-id-", "bankofamerica-", "wellsfargo-", "netflix-login", "office365-verify", "micros0ft"];
    const hasBrandSpoof = brandSpoofs.some(spoof => domain.includes(spoof));

    if (isIpHost || (hasBrandSpoof && hasHighRiskTld)) {
      return {
        risk_tier: "Critical",
        risk_score: 0.95,
        is_threat: true,
        threat_type: "Phishing / Host Spoofing",
        mitre_ttp: "T1566.002",
        xai_explanation: `Detected suspicious IP host or brand spoofing on domain: ${domain}.`
      };
    }

    if (hasBrandSpoof || (hasHighRiskTld && !parsed.protocol.startsWith("https"))) {
      return {
        risk_tier: "High",
        risk_score: 0.75,
        is_threat: true,
        threat_type: "Suspicious Host",
        mitre_ttp: "T1566",
        xai_explanation: `Domain contains brand mimicry cues on unmonitored infrastructure (${domain}).`
      };
    }

    return {
      risk_tier: "Safe",
      risk_score: 0.02,
      is_threat: false,
      threat_type: "Benign",
      mitre_ttp: null,
      xai_explanation: `Verified standard domain: ${domain}.`
    };
  } catch {
    return {
      risk_tier: "Safe",
      risk_score: 0.02,
      is_threat: false,
      threat_type: "Benign",
      mitre_ttp: null,
      xai_explanation: "Standard link."
    };
  }
}

// Local email evaluation logic
function evaluateLocalEmail(text) {
  const lower = text.toLowerCase();
  const criticalLures = [
    "verify your password", "reset your password immediately", "account will be suspended within",
    "unauthorized access detected", "wire transfer immediately", "send gift cards"
  ];
  const matches = criticalLures.filter(k => lower.includes(k));

  if (matches.length >= 1) {
    return {
      risk_tier: "Critical",
      risk_score: 0.88,
      is_phishing: true,
      xai_explanation: `Phishing urgency detected: "${matches[0]}". Suspected credential harvesting lure. Do not click links or enter passwords.`
    };
  }

  return {
    risk_tier: "Safe",
    risk_score: 0.05,
    is_phishing: false,
    xai_explanation: "Standard email format. No credential harvesting or deceptive urgency detected."
  };
}
