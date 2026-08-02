let map, marker;
/** Full multi-family domain result; used when switching A ↔ AAAA focus. */
let lastDomainBundle = null;

const $ = (sel) => document.querySelector(sel);

/**
 * Extra geo sources.
 * - browser: fetched from the visitor's machine (CORS)
 * - server: proxied via our API (e.g. ip-api HTTP-only free tier)
 */
const EXTRA_SOURCES = [
  {
    id: "ip_api",
    label: "ip-api",
    mode: "server",
    // Server proxies to http://ip-api.com and sends X-Forwarded-For = visitor IP
    buildUrl: (ip) => `/api/providers/ip-api?ip=${encodeURIComponent(ip)}`,
    map: (d, ip) => ({
      provider_id: "ip_api",
      ip: d.ip || ip,
      country: d.country,
      country_code: d.country_code,
      region: d.region,
      city: d.city,
      postal: d.postal,
      latitude: d.latitude,
      longitude: d.longitude,
      timezone: d.timezone,
      asn: d.asn,
      as_name: d.as_name,
      isp: d.isp,
      org: d.org,
      is_proxy: d.is_proxy,
      is_hosting: d.is_hosting,
      is_mobile: d.is_mobile,
      error: d.error || null,
    }),
  },
  {
    id: "ipinfo_lite",
    label: "IPinfo Lite",
    mode: "server",
    // Server proxies to api.ipinfo.io/lite with our token (country + ASN only)
    buildUrl: (ip) => `/api/providers/ipinfo-lite?ip=${encodeURIComponent(ip)}`,
    map: (d, ip) => ({
      provider_id: "ipinfo_lite",
      ip: d.ip || ip,
      country: d.country,
      country_code: d.country_code,
      region: null,
      city: null,
      postal: null,
      latitude: null,
      longitude: null,
      timezone: null,
      asn: d.asn,
      as_name: d.as_name,
      isp: d.isp,
      org: d.org,
      is_proxy: null,
      is_hosting: null,
      is_mobile: null,
      error: d.error || null,
    }),
  },
  {
    id: "ipwhois",
    label: "ipwho.is",
    mode: "browser",
    buildUrl: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}`,
    map: (d, ip) => {
      if (d.success === false) throw new Error(d.message || "fail");
      const conn = d.connection || {};
      const tz = d.timezone;
      return {
        provider_id: "ipwhois",
        ip,
        country: d.country,
        country_code: d.country_code,
        region: d.region,
        city: d.city,
        postal: d.postal,
        latitude: d.latitude,
        longitude: d.longitude,
        timezone: typeof tz === "object" && tz ? tz.id : tz,
        asn: conn.asn != null ? `AS${conn.asn}` : null,
        as_name: conn.org || conn.isp || null,
        isp: conn.isp,
        org: conn.org,
        is_proxy: null,
        is_hosting: null,
        is_mobile: null,
        error: null,
      };
    },
  },
  {
    id: "ipinfo",
    label: "IPinfo",
    mode: "browser",
    buildUrl: (ip) => `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
    map: (d, ip) => {
      const [lat, lon] = (d.loc || ",").split(",").map((x) => parseFloat(x));
      const org = d.org || "";
      const asnMatch = org.match(/^(AS\d+)\s*(.*)$/);
      return {
        provider_id: "ipinfo",
        ip,
        country: d.country,
        country_code: d.country,
        region: d.region,
        city: d.city,
        postal: d.postal,
        latitude: Number.isFinite(lat) ? lat : null,
        longitude: Number.isFinite(lon) ? lon : null,
        timezone: d.timezone,
        asn: asnMatch ? asnMatch[1] : null,
        as_name: asnMatch ? asnMatch[2] || null : org || null,
        isp: asnMatch ? asnMatch[2] || org : org,
        org: org,
        is_proxy: null,
        is_hosting: null,
        is_mobile: null,
        error: null,
      };
    },
  },
  {
    id: "freeipapi",
    label: "freeipapi",
    mode: "browser",
    buildUrl: (ip) =>
      `https://free.freeipapi.com/api/json/${encodeURIComponent(ip)}`,
    map: (d, ip) => ({
      provider_id: "freeipapi",
      ip,
      country: d.countryName,
      country_code: d.countryCode,
      region: d.regionName,
      city: d.cityName,
      postal: d.zipCode,
      latitude: d.latitude,
      longitude: d.longitude,
      timezone: Array.isArray(d.timeZones) ? d.timeZones[0] : d.timeZones,
      asn: d.asn ? `AS${d.asn}` : null,
      as_name: d.asnOrganization || null,
      isp: d.asnOrganization || null,
      org: d.asnOrganization || null,
      is_proxy: d.isProxy ?? null,
      is_hosting: null,
      is_mobile: null,
      error: null,
    }),
  },
  {
    id: "ipsb",
    label: "ip.sb",
    mode: "browser",
    buildUrl: (ip) => `https://api.ip.sb/geoip/${encodeURIComponent(ip)}`,
    map: (d, ip) => ({
      provider_id: "ipsb",
      ip,
      country: d.country,
      country_code: d.country_code,
      region: d.region || d.region_code || null,
      city: d.city || null,
      postal: d.postal_code || null,
      latitude: d.latitude,
      longitude: d.longitude,
      timezone: d.timezone,
      asn: d.asn != null ? `AS${d.asn}` : null,
      as_name: d.asn_organization || null,
      isp: d.isp || d.organization,
      org: d.organization || d.asn_organization,
      is_proxy: null,
      is_hosting: null,
      is_mobile: null,
      error: null,
    }),
  },
];

function showStatus(msg, isError = false) {
  const el = $("#status");
  el.textContent = msg;
  el.classList.remove("hidden");
  el.style.color = isError ? "var(--bad)" : "var(--muted)";
}

function hideStatus() {
  $("#status").classList.add("hidden");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "-";
}

function fillDl(el, rows) {
  el.innerHTML = rows
    .map(
      ([k, v]) =>
        `<dt>${k}</dt><dd>${v == null || v === "" ? "-" : escapeHtml(String(v))}</dd>`
    )
    .join("");
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function badge(text, kind) {
  return `<span class="badge ${kind || ""}">${escapeHtml(text)}</span>`;
}

/** ISO 3166-1 alpha-2 → flag emoji */
function countryFlag(code) {
  if (!code || typeof code !== "string" || code.length !== 2) return "";
  const cc = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  const A = 0x1f1e6;
  return String.fromCodePoint(
    A + cc.charCodeAt(0) - 65,
    A + cc.charCodeAt(1) - 65
  );
}

function countryLabel(code, name) {
  const flag = countryFlag(code);
  const text = name || code || "";
  if (!flag && !text) return "-";
  return flag ? `${flag} ${text}` : text;
}

async function fetchExtraSource(src, ip, timeoutMs = 5000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(src.buildUrl(ip), {
      signal: ctrl.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return src.map(data, ip);
  } catch (err) {
    let error = err.name === "AbortError" ? "timeout" : String(err.message || err);
    if (/networkerror|failed to fetch|load failed/i.test(error)) {
      error = `${error} - is an adblocker enabled?`;
    }
    return {
      provider_id: src.id,
      ip,
      error,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function enrichWithExtraSources(report) {
  const ip = report.query;
  if (!ip || report.classification?.address_class === "private") {
    return report;
  }
  const results = await Promise.all(
    EXTRA_SOURCES.map((s) => fetchExtraSource(s, ip))
  );
  const byId = new Map((report.sources || []).map((s) => [s.provider_id, s]));
  for (const r of results) {
    byId.set(r.provider_id, r);
  }
  report.sources = Array.from(byId.values()).sort((a, b) =>
    String(a.provider_id).localeCompare(String(b.provider_id))
  );
  return report;
}

async function enrichReportTree(report) {
  report = await enrichWithExtraSources(report);
  if (Array.isArray(report.related) && report.related.length) {
    report.related = await Promise.all(
      report.related.map((r) => enrichWithExtraSources(r))
    );
  }
  return report;
}

function renderRelated(data) {
  const card = $("#related-card");
  const list = $("#related-list");
  const related = data.related || [];
  if (!related.length) {
    card.classList.add("hidden");
    list.innerHTML = "";
    return;
  }
  card.classList.remove("hidden");
  list.innerHTML = related
    .map((r, idx) => {
      const p = r.primary || {};
      const c = r.classification || {};
      const flag = countryFlag(p.country_code);
      const loc = [p.country || p.country_code, p.city].filter(Boolean).join(" · ");
      return `<button type="button" class="related-item" data-related-idx="${idx}">
        <span class="badge">${r.ip_version === 6 ? "IPv6" : "IPv4"}</span>
        <span class="related-ip">${escapeHtml(r.query)}</span>
        <span class="related-meta">${flag} ${escapeHtml(loc || "-")}</span>
        <span class="related-meta">${escapeHtml(p.asn || "")}</span>
        <span class="related-meta">risk ${r.risk_score ?? "-"} · ${escapeHtml(
          c.usage || ""
        )}</span>
      </button>`;
    })
    .join("");

  list.querySelectorAll("[data-related-idx]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-related-idx"));
      focusRelated(idx);
    });
  });
}

function focusRelated(idx) {
  if (!lastDomainBundle || !lastDomainBundle.related?.[idx]) return;
  const chosen = lastDomainBundle.related[idx];
  const others = [
    {
      ...lastDomainBundle,
      related: [],
    },
    ...lastDomainBundle.related.filter((_, i) => i !== idx).map((r) => ({ ...r, related: [] })),
  ];
  const focused = {
    ...chosen,
    related: others,
    dns: lastDomainBundle.dns || chosen.dns,
    domain: lastDomainBundle.domain || chosen.domain,
    query_type: "domain",
  };
  lastDomainBundle = focused;
  renderReport(focused);
}

function renderSourcesTable(sources) {
  const tbody = $("#sources-table tbody");
  tbody.innerHTML = (sources || [])
    .map((s) => {
      const flags = [
        s.is_proxy ? "proxy" : null,
        s.is_hosting ? "hosting" : null,
        s.is_mobile ? "mobile" : null,
        ...(Array.isArray(s.flags) ? s.flags : []),
      ]
        .filter(Boolean)
        .join(", ");
      const flag = countryFlag(s.country_code);
      const country = s.country || s.country_code || "";
      return `<tr>
        <td>${escapeHtml(s.provider_id || "")}</td>
        <td><span class="flag-cell">${flag}</span>${escapeHtml(country)}</td>
        <td>${escapeHtml(s.region || "")}</td>
        <td>${escapeHtml(s.city || "")}</td>
        <td>${escapeHtml(s.asn || "")}</td>
        <td>${escapeHtml(s.isp || s.org || s.as_name || "")}</td>
        <td>${escapeHtml(flags)}</td>
        <td>${escapeHtml(s.error || "")}</td>
      </tr>`;
    })
    .join("");
  const ok = (sources || []).filter((s) => !s.error).length;
  $("#sources-count").textContent = `(${ok}/${(sources || []).length} ok)`;
}

function renderBlocklists(report) {
  const card = $("#blocklists-card");
  const bl = report.blocklists;
  if (!bl) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");

  const hits = bl.hits || [];
  $("#blocklists-count").textContent = `(${hits.length} hit${hits.length === 1 ? "" : "s"})`;

  const ts = new Date((bl.checked_at || 0) * 1000).toLocaleTimeString();
  const ips = (bl.checked_ips || []).join(", ") || "-";
  const dom = bl.checked_domain || "-";
  $("#blocklists-summary").textContent =
    `checked at ${ts} · IPs: ${ips} · domain: ${dom}`;

  const tbody = $("#blocklists-table tbody");
  tbody.innerHTML = hits.map(h => {
    const sev = h.severity >= 20 ? "bad" : h.severity >= 10 ? "warn" : "";
    return `<tr>
      <td>${escapeHtml(h.source_id || "")}</td>
      <td>${badge(h.category || "", sev)}</td>
      <td>${escapeHtml(String(h.severity ?? ""))}</td>
      <td>${escapeHtml(h.matched_value || "")}</td>
      <td>${escapeHtml(h.detail || "")}</td>
    </tr>`;
  }).join("") ||
    `<tr><td colspan="5" class="muted">No hits - clean across ${
      Object.keys(bl.source_counts || {}).length
    } sources</td></tr>`;

  const counts = bl.source_counts || {};
  $("#loaded-count").textContent = String(Object.keys(counts).length);
  $("#loaded-sources").innerHTML = Object.entries(counts)
    .map(([id, n]) => `${escapeHtml(id)}: ${n} entries`)
    .join("<br>");
}

function renderReport(data) {
  $("#hero").classList.remove("hidden");

  const p = data.primary || {};
  const code = p.country_code || "";
  $("#hero-flag").textContent = countryFlag(code);

  setText("hero-ip", data.query);

  const domainLine = $("#domain-line");
  if (data.domain) {
    domainLine.classList.remove("hidden");
    domainLine.textContent = `domain: ${data.domain}`;
  } else {
    domainLine.classList.add("hidden");
    domainLine.textContent = "";
  }

  const score = data.risk_score ?? 0;
  setText("risk-score", String(score));
  const scoreEl = $("#risk-score");
  scoreEl.style.color =
    score >= 70 ? "var(--bad)" : score >= 30 ? "var(--warn)" : "var(--good)";

  const c = data.classification || {};
  const badges = [];
  if (c.ip_type) {
    badges.push(
      badge(
        c.ip_type,
        c.ip_type === "native" ? "good" : c.ip_type === "broadcast" ? "warn" : ""
      )
    );
  }
  if (c.usage) badges.push(badge(c.usage, c.usage === "hosting" ? "warn" : "good"));
  (c.proxy_signals || []).forEach((s) => badges.push(badge(s, "bad")));
  if (c.address_class && c.address_class !== "public") {
    badges.push(badge(c.address_class, "warn"));
  }
  if (data.query_type === "domain") badges.push(badge("domain", ""));
  $("#badges").innerHTML = badges.join("");

  fillDl($("#loc-dl"), [
    ["Country", countryLabel(p.country_code, p.country)],
    ["Region", p.region],
    ["City", p.city],
    ["Postal", p.postal],
    ["Timezone", p.timezone],
    ["Coords", p.latitude != null ? `${p.latitude}, ${p.longitude}` : null],
  ]);

  const n = data.network || {};
  fillDl($("#net-dl"), [
    ["ASN", n.asn],
    ["AS Name", n.as_name],
    ["ISP", n.isp],
    ["Org", n.org],
    ["rDNS", n.rdns],
    ["IP version", data.ip_version],
  ]);

  fillDl($("#class-dl"), [
    ["Type", c.ip_type],
    ["Usage", c.usage],
    ["Address", c.address_class],
    ["Signals", (c.proxy_signals || []).join(", ") || "none"],
    ["Risk", score],
  ]);

  const dnsCard = $("#dns-card");
  if (data.dns) {
    dnsCard.classList.remove("hidden");
    fillDl($("#dns-dl"), [
      ["Domain", data.dns.domain || data.domain],
      ["A", (data.dns.a || []).join(", ") || "-"],
      ["AAAA", (data.dns.aaaa || []).join(", ") || "-"],
      [
        "Analyzed",
        [data.query, ...(data.related || []).map((r) => r.query)].join(" · "),
      ],
    ]);
  } else {
    dnsCard.classList.add("hidden");
  }

  renderSourcesTable(data.sources);
  renderRelated(data);
  renderBlocklists(data);

  const w = data.whois || {};
  fillDl($("#whois-dl"), [
    ["Registry", w.registry],
    ["Country", w.country],
    ["Net name", w.netname],
    ["Org", w.org],
    ["CIDR", w.cidr],
    ["Allocated", w.allocated],
    ["Source", w.source],
    ["Note", w.raw_summary],
  ]);

  if (data.map && data.map.lat != null && data.map.lon != null) {
    ensureMap(data.map.lat, data.map.lon, data.query);
  }

  const blCount = data.blocklists ? Object.keys(data.blocklists.source_counts || {}).length : 0;
  $("#meta").textContent = `request ${data.request_id} · server ${data.took_ms} ms${
    data.cached ? " · cached" : ""
  } · client ${data.client_ip || "-"} · extra sources ${EXTRA_SOURCES.length} · blocklists ${blCount}`;
}

function ensureMap(lat, lon, label) {
  if (!map) {
    map = L.map("map");
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: "&copy; OpenStreetMap",
    }).addTo(map);
  }
  map.setView([lat, lon], 8);
  if (marker) marker.remove();
  marker = L.marker([lat, lon]).addTo(map).bindPopup(label);
  setTimeout(() => map.invalidateSize(), 50);
}

async function lookup(query) {
  showStatus("Looking up…");
  const url = query
    ? `/api/lookup?q=${encodeURIComponent(query)}`
    : "/api/lookup";
  const res = await fetch(url);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body.detail;
    throw new Error(
      typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : `HTTP ${res.status}`
    );
  }
  let data = await res.json();
  showStatus("Fetching multi-source geo…");
  data = await enrichReportTree(data);
  if (data.query_type === "domain" || (data.related && data.related.length)) {
    lastDomainBundle = data;
  } else {
    lastDomainBundle = null;
  }
  hideStatus();
  renderReport(data);
}

function setupTabs() {
  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
      $(`#tab-${tab}`).classList.remove("hidden");
      if (tab === "map" && map) setTimeout(() => map.invalidateSize(), 50);
    });
  });
}

/** Single-segment path names that should NOT trigger an auto-lookup. */
const RESERVED_PATH_SEGMENTS = new Set([
  "api",
  "static",
  "docs",
  "openapi.json",
  "redoc",
  "health",
  "favicon.ico",
  "robots.txt",
]);

/** Extract the lookup target from the URL path (e.g. /8.8.8.8 -> "8.8.8.8"). */
function getQueryFromPath() {
  const seg = window.location.pathname.split("/").filter(Boolean)[0];
  if (!seg) return "";
  const decoded = decodeURIComponent(seg);
  if (RESERVED_PATH_SEGMENTS.has(decoded.toLowerCase())) return "";
  return decoded;
}

document.getElementById("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const q = $("#ip-input").value.trim();
  try {
    await lookup(q);
    history.replaceState(null, "", q ? `/${encodeURIComponent(q)}` : "/");
  } catch (err) {
    showStatus(String(err.message || err), true);
  }
});

setupTabs();
const _initialQuery = getQueryFromPath();
if (_initialQuery) $("#ip-input").value = _initialQuery;
lookup(_initialQuery).catch((err) => showStatus(String(err.message || err), true));

$("#refresh-blocklists-btn").addEventListener("click", async () => {
  try {
    const res = await fetch("/api/blocklists", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showStatus("Refreshed blocklist status");
    setTimeout(hideStatus, 1500);
  } catch (err) {
    showStatus(String(err.message || err), true);
  }
});
