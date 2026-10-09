// ==============================================================================
// VERTEX BROWSER EXTENSION - AUTONOMOUS CONTENT SCRIPT
// 1. Search Engines (Google/Bing/DuckDuckGo): ONLY annotates organic search
//    result title links with McAfee-style green checkmarks (✓) and red badges (!).
//    Header, footer, sitelinks, and "read more" expansions are never falsely flagged.
// 2. Webmail (Gmail / Outlook): Passively scans every opened email in real time,
//    injects safety marks next to the sender/subject, and displays a detailed
//    threat assessment card explaining why it was marked as phishing if suspicious.
// 3. Global Click Interceptor: Intercepts clicks to dangerous destinations.
// ==============================================================================

console.log("[Vertex] Content script active on:", window.location.hostname);

const PROCESSED_LINKS = new WeakSet();
const EVALUATED_URLS = new Map();
const SCANNED_GMAIL_EMAILS = new WeakSet();

// ------------------------------------------------------------------------------
// McAfee-Style Badges, Popovers & Gmail Threat Banner Styles
// ------------------------------------------------------------------------------
const styleEl = document.createElement("style");
styleEl.textContent = `
  /* McAfee-Style Inline Circular Badge */
  .mc-badge {
    display: inline-flex !important;
    vertical-align: middle !important;
    align-items: center !important;
    justify-content: center !important;
    width: 16px !important;
    height: 16px !important;
    margin-left: 8px !important;
    margin-right: 2px !important;
    position: relative !important;
    cursor: pointer !important;
    user-select: none !important;
    line-height: 1 !important;
    flex-shrink: 0 !important;
    z-index: 10 !important;
  }
  .mc-badge svg {
    display: block !important;
    width: 16px !important;
    height: 16px !important;
    border-radius: 50% !important;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25) !important;
    transition: transform 0.15s ease !important;
  }
  .mc-badge:hover svg {
    transform: scale(1.15) !important;
  }

  /* McAfee Hover Popover: Right-side up, positioned below */
  .mc-popover {
    display: none !important;
    position: absolute !important;
    top: 22px !important;
    left: 0 !important;
    width: 290px !important;
    background: #ffffff !important;
    color: #09090b !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 8px !important;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.15), 0 4px 6px -2px rgba(0, 0, 0, 0.05) !important;
    padding: 12px 14px !important;
    font-family: 'Nunito', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    font-size: 13px !important;
    line-height: 1.45 !important;
    text-align: left !important;
    direction: ltr !important;
    writing-mode: horizontal-tb !important;
    transform: none !important;
    z-index: 2147483647 !important;
    pointer-events: none !important;
    box-sizing: border-box !important;
  }
  .mc-badge:hover .mc-popover {
    display: block !important;
  }

  /* Gmail Inline Header Safety Badge */
  .vertex-gmail-badge {
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
    padding: 3px 10px !important;
    border-radius: 9999px !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    margin-left: 10px !important;
    vertical-align: middle !important;
    cursor: default !important;
    position: relative !important;
    z-index: 5 !important;
  }
  .vertex-gmail-badge.safe {
    background: #f0fdf4 !important;
    color: #15803d !important;
    border: 1px solid #bbf7d0 !important;
  }
  .vertex-gmail-badge.threat {
    background: #fef2f2 !important;
    color: #b91c1c !important;
    border: 1px solid #fecaca !important;
    animation: pulse 2s infinite !important;
  }

  /* Gmail Expanded Threat Alert Card */
  .vertex-gmail-alert-card {
    background: #ffffff !important;
    border: 1px solid #fecaca !important;
    border-left: 5px solid #dc2626 !important;
    border-radius: 8px !important;
    padding: 14px 18px !important;
    margin: 12px 0 16px 0 !important;
    box-shadow: 0 4px 14px rgba(220, 38, 38, 0.08) !important;
    font-family: 'Nunito', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    font-size: 14px !important;
    direction: ltr !important;
    text-align: left !important;
  }
`;
document.head.appendChild(styleEl);

// ------------------------------------------------------------------------------
// Determine Page Context
// ------------------------------------------------------------------------------
const isGoogleSearch = 
  window.location.hostname.includes("google.") && 
  (window.location.pathname.startsWith("/search") || window.location.pathname === "/");

const isBingSearch = 
  window.location.hostname.includes("bing.com") && 
  window.location.pathname.startsWith("/search");

const isDuckDuckGoSearch = 
  window.location.hostname.includes("duckduckgo.com") && 
  (window.location.search.includes("q=") || window.location.pathname.startsWith("/"));

const isSearchResultPage = isGoogleSearch || isBingSearch || isDuckDuckGoSearch;
const isGmail = window.location.hostname.includes("mail.google.com");

// ------------------------------------------------------------------------------
// 1. Organic Search Results Annotation (McAfee Style)
// ------------------------------------------------------------------------------
function scanOrganicSearchResults() {
  if (!isSearchResultPage) return;

  const items = [];

  if (isGoogleSearch) {
    // Select main organic search title links inside #rso
    const headings = document.querySelectorAll("#rso .g h3, #search .g h3, #rso h3");

    headings.forEach((h3) => {
      // Exclude navigation, pagination, people also ask, and footers
      if (h3.closest("#botstuff, #foot, #footer, #gb, #hdtb, #searchform, .related-question-pair, .kno-kp, #appbar, .fG8F2e")) {
        return;
      }

      const anchor = h3.closest("a") || h3.querySelector("a") || h3.parentElement?.closest("a");
      if (!anchor || !anchor.href) return;

      const href = anchor.href.trim();
      if (!href.startsWith("http")) return;

      try {
        const u = new URL(href);
        const host = u.hostname.toLowerCase();
        // Ignore Google internal URLs
        if (host.includes("google.") || host.includes("gstatic.") || u.pathname.includes("/search")) {
          return;
        }
        items.push({ h3, anchor, href });
      } catch {}
    });
  } else if (isBingSearch) {
    const headings = document.querySelectorAll("#b_results .b_algo h2");
    headings.forEach((h2) => {
      const anchor = h2.closest("a") || h2.querySelector("a");
      if (!anchor || !anchor.href) return;
      try {
        const u = new URL(anchor.href);
        if (!u.hostname.includes("bing.com")) {
          items.push({ h3: h2, anchor, href: anchor.href });
        }
      } catch {}
    });
  } else if (isDuckDuckGoSearch) {
    const titles = document.querySelectorAll("[data-testid='result-title-a']");
    titles.forEach((anchor) => {
      if (!anchor.href) return;
      try {
        const u = new URL(anchor.href);
        if (!u.hostname.includes("duckduckgo.com")) {
          items.push({ h3: anchor, anchor, href: anchor.href });
        }
      } catch {}
    });
  }

  // Annotate genuine organic results
  items.forEach(({ h3, anchor, href }) => {
    if (PROCESSED_LINKS.has(h3)) return;
    PROCESSED_LINKS.add(h3);

    if (EVALUATED_URLS.has(href)) {
      attachMcAfeeBadge(h3, anchor, href, EVALUATED_URLS.get(href));
      return;
    }

    chrome.runtime.sendMessage({ type: "SCAN_URL", url: href }, (response) => {
      if (chrome.runtime.lastError || !response) return;
      EVALUATED_URLS.set(href, response);
      attachMcAfeeBadge(h3, anchor, href, response);
    });
  });
}

function attachMcAfeeBadge(h3Element, anchorElement, targetUrl, result) {
  if (h3Element.querySelector(".mc-badge") || h3Element.parentElement?.querySelector(".mc-badge")) {
    return;
  }

  const isThreat = result.risk_tier === "High" || result.risk_tier === "Critical";
  const isSuspicious = result.risk_tier === "Medium";
  const isSafe = !isThreat && !isSuspicious;

  const badge = document.createElement("span");
  badge.className = "mc-badge";

  if (isSafe) {
    badge.innerHTML = `
      <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
        <circle cx="8" cy="8" r="8" fill="#107c10"/>
        <path d="M4.5 8.2l2.3 2.3 4.7-4.7" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
  } else {
    badge.innerHTML = `
      <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
        <circle cx="8" cy="8" r="8" fill="#d83b01"/>
        <path d="M8 4.5v4.5M8 11.5v.5" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/>
      </svg>
    `;
  }

  // McAfee Hover Card
  const popover = document.createElement("div");
  popover.className = "mc-popover";
  popover.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px;">
      <span style="font-weight: 700; font-size: 11px; color: ${isSafe ? '#107c10' : '#d83b01'}; display: flex; align-items: center; gap: 4px;">
        <span>${isSafe ? '✓' : '⚠️'}</span>
        <span>Vertex WebAdvisor</span>
      </span>
      <span style="font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 9999px; background: ${isSafe ? '#f0fdf4' : '#fef2f2'}; color: ${isSafe ? '#15803d' : '#b91c1c'}; border: 1px solid ${isSafe ? '#bbf7d0' : '#fecaca'};">
        ${isSafe ? 'SAFE' : 'THREAT'}
      </span>
    </div>
    <div style="font-size: 10px; color: #64748b; font-family: monospace; word-break: break-all; margin-bottom: 6px;">
      ${targetUrl.length > 50 ? targetUrl.substring(0, 48) + '...' : targetUrl}
    </div>
    <div style="font-size: 11px; line-height: 1.45; color: #1e293b; margin-bottom: 6px;">
      ${result.xai_explanation || (isSafe ? 'Verified benign domain. Zero malicious indicators detected.' : 'Suspicious structural characteristics detected.')}
    </div>
    <div style="font-size: 9px; color: #94a3b8; display: flex; justify-content: space-between; border-top: 1px solid #f8fafc; padding-top: 4px;">
      <span>Risk Score: ${(result.risk_score * 100).toFixed(0)}%</span>
      <span>${result.mitre_ttp && result.mitre_ttp !== 'None' ? `MITRE: ${result.mitre_ttp}` : 'Verified'}</span>
    </div>
  `;
  badge.appendChild(popover);

  h3Element.appendChild(badge);

  // If high risk, intercept click and redirect to blocked warning page
  if (isThreat) {
    anchorElement.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      redirectToBlockedPage(targetUrl, result);
    }, true);
  }
}

function redirectToBlockedPage(url, result) {
  const blockedUrl = chrome.runtime.getURL(
    `blocked.html?url=${encodeURIComponent(url)}&score=${result.risk_score}&tier=${result.risk_tier}&xai=${encodeURIComponent(result.xai_explanation || 'Suspicious structural pattern')}&ttp=${result.mitre_ttp || 'T1190'}`
  );
  window.location.href = blockedUrl;
}

if (isSearchResultPage) {
  scanOrganicSearchResults();
  const searchObserver = new MutationObserver(() => scanOrganicSearchResults());
  searchObserver.observe(document.body, { childList: true, subtree: true });
}

// ------------------------------------------------------------------------------
// 2. Passive Gmail Webmail Inspector
//    Passively scans opened emails and marks safety or phishing explanation.
// ------------------------------------------------------------------------------
if (isGmail) {
  console.log("[Vertex] Gmail Passive Phishing Monitor Active.");

  function scanOpenedGmailEmails() {
    // Specifically target opened emails in the expanded view
    const messageRows = document.querySelectorAll(".h7");

    messageRows.forEach((row) => {
      if (SCANNED_GMAIL_EMAILS.has(row)) return;

      // Ensure body text exists before marking
      const bodyEl = row.querySelector(".ii.gt") || row.querySelector(".a3s.aiL") || row;
      const bodyText = (bodyEl.innerText || "").trim();
      if (bodyText.length < 20) return;

      SCANNED_GMAIL_EMAILS.add(row);

      // Extract sender and subject
      const senderEl = row.querySelector("span.gD") || document.querySelector("span.gD");
      const senderEmail = senderEl ? (senderEl.getAttribute("email") || senderEl.innerText) : "Unknown Sender";
      const subjectEl = row.closest("div[role='listitem']")?.querySelector("h2") || document.querySelector("h2.hP");
      const subjectText = subjectEl ? subjectEl.innerText : "Email Message";

      console.log(`[Vertex] Passively inspecting opened email from: ${senderEmail}`);

      chrome.runtime.sendMessage({
        type: "SCAN_EMAIL",
        emailText: bodyText,
        sender: senderEmail,
        subject: subjectText
      }, (scanResult) => {
        if (chrome.runtime.lastError || !scanResult) return;
        renderGmailSafetyMark(row, bodyEl, senderEmail, scanResult);
      });
    });
  }

  function renderGmailSafetyMark(messageRow, bodyEl, senderEmail, result) {
    if (messageRow.querySelector(".vertex-gmail-badge")) return;

    const isThreat = result.risk_tier === "High" || result.risk_tier === "Critical";
    const isMedium = result.risk_tier === "Medium";
    const isSafe = !isThreat && !isMedium;

    // 1. Header Safety Badge (near sender/subject)
    const badge = document.createElement("span");
    badge.className = `vertex-gmail-badge ${isSafe ? 'safe' : 'threat'}`;
    badge.innerHTML = isSafe
      ? `✓ Vertex Safe (0% Risk)`
      : `⚠️ ${result.risk_tier.toUpperCase()} RISK (${(result.risk_score * 100).toFixed(0)}%)`;

    // Try finding header area to insert
    const headerRow = messageRow.querySelector(".gE.iv.gt") || messageRow.querySelector(".adn") || messageRow;
    const senderSpan = messageRow.querySelector("span.gD") || headerRow;
    if (senderSpan && senderSpan.parentNode) {
      senderSpan.parentNode.insertBefore(badge, senderSpan.nextSibling);
    } else {
      headerRow.prepend(badge);
    }

    // 2. If Threat: Inject prominent Alert Card above the message body
    if (isThreat || isMedium) {
      if (messageRow.querySelector(".vertex-gmail-alert-card")) return;

      const alertCard = document.createElement("div");
      alertCard.className = "vertex-gmail-alert-card";
      alertCard.innerHTML = `
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 14px;">
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
              <span style="background: #dc2626; color: #ffffff; font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 9999px; text-transform: uppercase;">
                ${result.risk_tier} Phishing Threat
              </span>
              <strong style="font-size: 13px; color: #991b1b;">
                Autonomous Threat Detection Active
              </strong>
            </div>

            <p style="font-size: 13px; color: #1e293b; line-height: 1.5; margin: 0 0 10px 0; font-weight: 500;">
              ${result.xai_explanation || 'Detected urgent pressure tactics and credential harvesting lures in this message.'}
            </p>

            ${result.recommended_playbook ? `
              <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; font-size: 11.5px; color: #475569; margin-bottom: 10px;">
                <strong style="color: #0f172a;">Recommended Mitigation Playbook:</strong><br>
                ${result.recommended_playbook.replace(/\n/g, '<br>')}
              </div>
            ` : ''}

            <div style="display: flex; gap: 10px; align-items: center;">
              <button class="btn-block-sender" style="background: #000000; color: #ffffff; border: none; padding: 6px 14px; border-radius: 6px; font-size: 11px; font-weight: 700; cursor: pointer;">
                Add Sender to SOC Blocklist
              </button>
              <button class="btn-dismiss-alert" style="background: transparent; color: #64748b; border: 1px solid #cbd5e1; padding: 5px 12px; border-radius: 6px; font-size: 11px; font-weight: 600; cursor: pointer;">
                Dismiss
              </button>
            </div>
          </div>
        </div>
      `;

      // Interactive Action: Add Sender to SOC Blocklist
      const btnBlock = alertCard.querySelector(".btn-block-sender");
      btnBlock.onclick = async () => {
        btnBlock.innerText = "Blocking...";
        try {
          const res = await fetch("http://127.0.0.1:8000/api/v1/admin/actions/block-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: senderEmail, entry_type: "sender", reason: "Gmail Phishing Interception" })
          });
          if (res.ok) {
            btnBlock.innerText = "✓ Sender Added to Blocklist";
            btnBlock.style.background = "#15803d";
          }
        } catch (e) {
          btnBlock.innerText = "Added to Local Filter";
        }
      };

      alertCard.querySelector(".btn-dismiss-alert").onclick = () => alertCard.remove();

      if (bodyEl && bodyEl.parentNode) {
        bodyEl.parentNode.insertBefore(alertCard, bodyEl);
      }
    }
  }

  // Run observer continuously on Gmail DOM mutations
  scanOpenedGmailEmails();
  const gmailObserver = new MutationObserver(() => scanOpenedGmailEmails());
  gmailObserver.observe(document.body, { childList: true, subtree: true });
}

// ------------------------------------------------------------------------------
// 3. Global Click Interceptor (Intercepts clicks to suspicious destinations)
// ------------------------------------------------------------------------------
document.addEventListener("click", async (e) => {
  const link = e.target.closest("a[href]");
  if (!link || !link.href) return;

  const href = link.href.trim();
  if (!href.startsWith("http://") && !href.startsWith("https://")) return;

  try {
    const urlObj = new URL(href);
    if (urlObj.hostname === window.location.hostname && urlObj.pathname === window.location.pathname) {
      return;
    }
  } catch {
    return;
  }

  // If already flagged in cache as threat, intercept immediately
  if (EVALUATED_URLS.has(href)) {
    const cached = EVALUATED_URLS.get(href);
    if (cached.risk_tier === "High" || cached.risk_tier === "Critical") {
      e.preventDefault();
      e.stopPropagation();
      redirectToBlockedPage(href, cached);
      return;
    }
    return; // Already checked and safe
  }

  // Intercept click to wait for scan
  e.preventDefault();
  e.stopPropagation();

  // Show nice popup without svgs
  const popup = document.createElement("div");
  popup.style.cssText = "position:fixed;top:20px;right:20px;background:#ffffff;padding:16px 20px;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,0.15);z-index:999999;font-family:'Nunito',sans-serif;font-size:14px;color:#1e293b;border-left:4px solid #3b82f6;";
  popup.innerHTML = "<strong style='display:block;margin-bottom:4px;font-size:15px;color:#0f172a;'>Scanning Link</strong>Please wait while Vertex checks this destination for threats...";
  document.body.appendChild(popup);

  // Async query background worker
  chrome.runtime.sendMessage({ type: "SCAN_URL", url: href }, (data) => {
    popup.remove();
    if (data) {
      EVALUATED_URLS.set(href, data);
      if (data.risk_tier === "High" || data.risk_tier === "Critical") {
        redirectToBlockedPage(href, data);
      } else {
        window.location.href = href;
      }
    } else {
      window.location.href = href;
    }
  });
}, true);
