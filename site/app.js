// PA NEVI dashboard. Everything runs in the browser:
//   1. decrypt the data bundle with the user's password (WebCrypto)
//   2. load the aggregated tables into DuckDB-WASM
//   3. every chart is a SQL query against those tables (shown under "SQL")
//   4. "Ask the data" sends the question to a Cloudflare Worker that returns SQL;
//      the SQL runs here, so every number in an answer comes from the data.
import * as duckdb from "./vendor/duckdb-wasm.mjs";

const CFG = window.NEVI_CONFIG || {};
const $ = (s, el = document) => el.querySelector(s);
const enc = (s) => new TextEncoder().encode(s);
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (u8) => btoa(String.fromCharCode(...u8));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha = async (s) => hex(await crypto.subtle.digest("SHA-256", enc(s)));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { sessionStorage.setItem(k, v); } catch {} },
  clear: () => { try { sessionStorage.clear(); } catch {} },
};

// ------------------------------------------------------------------ formatting
const fmt = {
  int: (v) => (v == null ? "–" : Math.round(v).toLocaleString("en-US")),
  dec: (v, d = 1) => (v == null ? "–" : Number(v).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d })),
  pct: (v, d = 1) => (v == null ? "–" : (v * 100).toFixed(d) + "%"),
  pctv: (v, d = 1) => (v == null ? "–" : Number(v).toFixed(d) + "%"),
  compact: (v) => (v == null ? "–" : Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(v)),
  month: (s) => { const [y, m] = String(s).split("-"); return new Date(+y, +m - 1, 1).toLocaleString("en-US", { month: "short", year: "numeric" }); },
  q: (s) => String(s).replace(/(\d{4})Q(\d)/, "Q$2 $1"),
};
const DOW = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const SPARK = `<svg class="spark" viewBox="0 0 16 16" width="13" height="13" aria-hidden="true"><path d="M8 0.8 9.7 6.3 15.2 8 9.7 9.7 8 15.2 6.3 9.7 0.8 8 6.3 6.3Z" fill="currentColor"/></svg>`;
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const SERIES = () => [1, 2, 3, 4, 5, 6, 7, 8].map((i) => css(`--s${i}`));
const OPERATOR_SLOT = { EVgo: 0, ChargePoint: 1, Tesla: 2, "Francis Energy": 3 };
function status(u) {
  if (u == null || Number.isNaN(u)) return { cls: "none", icon: "–", label: "No data", color: css("--none") };
  if (u >= 97) return { cls: "good", icon: "✓", label: "Meets 97%", color: css("--good") };
  if (u >= 90) return { cls: "warn", icon: "!", label: "90–97%", color: css("--warn") };
  return { cls: "crit", icon: "✕", label: "Below 90%", color: css("--crit") };
}
const statusHTML = (u, text) => { const s = status(u); return `<span class="status ${s.cls}"><i aria-hidden="true">${s.icon}</i>${text ?? s.label}</span>`; };

// ------------------------------------------------------------------ decrypt
async function unlock(user, pass) {
  user = user.trim().toLowerCase();
  const meta = await (await fetch("data/bundle.json", { cache: "no-cache" })).json();
  const entry = meta.users[await sha(user)];
  if (!entry) throw new Error("That username and password don't match. Check both and try again.");
  const base = await crypto.subtle.importKey("raw", enc(`${user}:${pass}`), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64d(entry.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let dek;
  try { dek = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(entry.iv) }, kek, b64d(entry.wrapped))); }
  catch { throw new Error("That username and password don't match. Check both and try again."); }
  const token = await sha(`nevi-worker:${user}:${pass}`);
  return { user, dek, token };
}
async function openBundle(dekRaw) {
  const dek = await crypto.subtle.importKey("raw", dekRaw, "AES-GCM", false, ["decrypt"]);
  const bin = new Uint8Array(await (await fetch("data/bundle.bin", { cache: "no-cache" })).arrayBuffer());
  const gz = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bin.slice(0, 12) }, dek, bin.slice(12));
  const plain = new Uint8Array(await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer());
  const mlen = new DataView(plain.buffer).getUint32(0, true);
  const manifest = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + mlen)));
  return { manifest, body: plain.slice(4 + mlen) };
}

// ------------------------------------------------------------------ duckdb
let conn, META;
async function initDB({ manifest, body }) {
  const bundle = await duckdb.selectBundle(duckdb.getJsDelivrBundles());
  const wurl = URL.createObjectURL(new Blob([`importScripts("${bundle.mainWorker}");`], { type: "text/javascript" }));
  const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), new Worker(wurl));
  await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
  URL.revokeObjectURL(wurl);
  await db.open({ query: { castBigIntToDouble: true, castDecimalToDouble: true } });
  conn = await db.connect();
  for (const t of manifest.tables) {
    await conn.insertArrowFromIPCStream(body.slice(t.offset, t.offset + t.length), { name: t.name });
  }
  try { await conn.query("SET enable_external_access = false"); } catch {}
  META = manifest.meta;
}
function conv(v, type) {
  if (v == null) return null;
  if (typeof v === "bigint") return Number(v);
  const id = type?.typeId;
  if (id === 8 || id === 10) { const d = new Date(Number(v)); return isNaN(d) ? String(v) : d.toISOString().slice(0, 10); }
  if (typeof v === "object" && !(v instanceof Date)) { const n = Number(v); return Number.isFinite(n) ? n : String(v); }
  return v;
}
async function q(sql) {
  const res = await conn.query(sql);
  const fields = res.schema.fields;
  return {
    columns: fields.map((f) => f.name),
    rows: res.toArray().map((r) => { const o = {}; for (const f of fields) o[f.name] = conv(r[f.name], f.type); return o; }),
  };
}

// ------------------------------------------------------------------ charts
const charts = new Set();
function echart(el, optionFn, persist = false) {
  const c = echarts.init(el, null, { renderer: "svg" });
  const entry = { c, optionFn, el, persist };
  const draw = () => c.setOption(withBase(optionFn()), true);
  entry.draw = draw;
  draw();
  charts.add(entry);
  return c;
}
function withBase(o) {
  const ink2 = css("--ink-2"), muted = css("--muted"), hair = css("--hair"), axis = css("--axis");
  const ax = (a) => a && [].concat(a).map((x) => ({
    axisLine: { lineStyle: { color: axis } }, axisTick: { show: false },
    axisLabel: { color: muted, fontFamily: css("--font"), fontSize: 12 },
    splitLine: { lineStyle: { color: hair, type: "solid" } },
    nameTextStyle: { color: muted, fontSize: 12 }, ...x,
  }));
  return {
    ...o,
    textStyle: { fontFamily: css("--font"), color: ink2 },
    animation: !matchMedia("(prefers-reduced-motion: reduce)").matches,
    tooltip: { backgroundColor: css("--surface"), borderColor: hair, textStyle: { color: css("--ink"), fontSize: 13 }, ...(o.tooltip || {}) },
    grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true, ...(o.grid || {}) },
    xAxis: ax(o.xAxis), yAxis: ax(o.yAxis),
  };
}
const ro = new ResizeObserver((es) => es.forEach((e) => echarts.getInstanceByDom(e.target)?.resize()));
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => charts.forEach((e) => e.el.isConnected && e.draw()));
const BAR = (color, extra = {}) => ({ type: "bar", barMaxWidth: 24, itemStyle: { color, borderRadius: [4, 4, 0, 0] }, ...extra });
const legendHTML = (items) => `<ul class="legend">${items.map(([name, color]) => `<li><span class="sw" style="background:${color}"></span>${esc(name)}</li>`).join("")}</ul>`;

// ------------------------------------------------------------------ cards
// card({title, sub, sql, render(rows, body, columns), cls, caveat})
// Runs its own SQL so what is shown under "SQL" is exactly what produced the chart.
async function card(parent, { title, sub, sql, render, cls = "c12", caveat, table = true, ask }) {
  const el = document.createElement("section");
  el.className = `card ${cls}`;
  el.innerHTML = `<div class="card-head"><div><h3>${esc(title)}</h3>${sub ? `<p class="sub">${sub}</p>` : ""}</div>
    <div class="card-tools">${ask ? `<button class="tool tool-ask" data-t="ask" title="Ask: ${esc(ask)}">${SPARK}Ask</button>` : ""}${table ? `<button class="tool" data-t="table" aria-pressed="false">Table</button>` : ""}<button class="tool" data-t="sql" aria-pressed="false">SQL</button></div></div>
    <pre class="sql" hidden></pre><div class="body"></div><div class="tbl" hidden></div>${caveat ? `<p class="caveat">${caveat}</p>` : ""}`;
  parent.appendChild(el);
  $("pre.sql", el).textContent = sql.trim();
  const body = $(".body", el);
  try {
    const { rows, columns } = await q(sql);
    render(rows, body, columns);
    body.querySelectorAll(".chart").forEach((c) => ro.observe(c));
    el.querySelectorAll(".tool").forEach((b) => b.addEventListener("click", () => {
      if (b.dataset.t === "ask") return Ask.open(ask, true);
      const on = b.getAttribute("aria-pressed") !== "true";
      b.setAttribute("aria-pressed", on);
      if (b.dataset.t === "sql") $("pre.sql", el).hidden = !on;
      else { const t = $(".tbl", el); t.hidden = !on; if (on && !t.innerHTML) t.innerHTML = tableHTML(columns, rows); }
    }));
  } catch (e) {
    body.innerHTML = `<p class="err-box">This chart could not load: ${esc(e.message)}</p>`;
    console.error(sql, e);
  }
  return el;
}
function tableHTML(columns, rows, max = 500) {
  const isNum = (c) => rows.some((r) => typeof r[c] === "number");
  const nc = Object.fromEntries(columns.map((c) => [c, isNum(c)]));
  const cell = (v, c) => (v == null ? "" : nc[c] ? (Number.isInteger(v) ? v.toLocaleString("en-US") : Number(v).toLocaleString("en-US", { maximumFractionDigits: 3 })) : esc(v));
  return `<div class="tbl-wrap"><table><thead><tr>${columns.map((c) => `<th class="${nc[c] ? "n" : ""}">${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows.slice(0, max).map((r) => `<tr>${columns.map((c) => `<td class="${nc[c] ? "n" : ""}">${cell(r[c], c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>${rows.length > max ? `<p class="caveat">Showing ${max} of ${rows.length} rows.</p>` : ""}`;
}
function grid(view) { const g = document.createElement("div"); g.className = "grid"; view.appendChild(g); return g; }

// ------------------------------------------------------------------ views
let STATIONS = [];
const VIEWS = {};

VIEWS.overview = async (view) => {
  const k = (await q(`SELECT SUM(sessions_success) s, SUM(energy_kwh)/1000 mwh, SUM(sessions_success)/SUM(sessions_total) sr FROM daily_station`)).rows[0];
  const pc = (await q(`SELECT COUNT(*) FILTER (WHERE uptime_nevi_pct >= 97) ok, COUNT(*) n FROM port_uptime_reported`)).rows[0];
  const aw = (await q(`SELECT COUNT(*) n, COUNT(*) FILTER (WHERE status = 'Operational') op, COUNT(*) FILTER (WHERE has_session_data) d FROM awarded_stations`)).rows[0];
  const month = (d) => new Date(d + "T12:00").toLocaleDateString("en-US", { month: "long", year: "numeric" });
  view.insertAdjacentHTML("beforeend", `
    <section class="hero-ask" aria-labelledby="hero-ask-h">
      <div class="hero-copy">
        <h2 id="hero-ask-h">Ask the data</h2>
        <p>Ask in plain English. A language model turns your question into SQL, the query runs in your browser on the station data, and the answer comes back with its chart and the query behind it, so every number can be checked.</p>
      </div>
      ${Ask.formHTML({ placeholder: "e.g. Which ports fell below 97% uptime, and for how long were they down?", examples: EXAMPLES.slice(0, 4), cls: "hero-form" })}
      <div class="hero-answers"></div>
    </section>
    <p class="lede">PennDOT's inventory lists <strong>${aw.n} NEVI award sites</strong>, ${aw.op} of them operational. Charging data in this dashboard covers the <strong>${aw.d} stations</strong> that reported through EV-ChART from ${month(META.data_start)} to ${month(META.data_end)}; the rest are shown on the map for context.</p>
    <div class="tiles">
      <div class="tile"><div class="label">Successful sessions</div><div class="value">${fmt.int(k.s)}</div><div class="note">${aw.d} reporting stations, all quarters</div></div>
      <div class="tile"><div class="label">Energy delivered</div><div class="value">${fmt.dec(k.mwh, 0)} MWh</div><div class="note">≈ ${fmt.compact(k.mwh * 1000 * 3)} EV miles at 3 mi/kWh</div></div>
      <div class="tile"><div class="label">Charge success</div><div class="value">${fmt.pct(k.sr)}</div><div class="note">Share of plug-ins that delivered energy</div></div>
      <div class="tile"><div class="label">Ports meeting 97% uptime</div><div class="value">${pc.ok} of ${pc.n}</div><div class="note">Share of time each port was online</div></div>
    </div>`);
  Ask.bind($(".hero-form", view), $(".hero-answers", view));
  const g = grid(view);
  await card(g, {
    title: "NEVI sites across Pennsylvania", cls: "c7", table: false,
    ask: "How many awarded sites are operational, in progress and planned in each PennDOT district?",
    sub: `Large circles are the ${aw.d} stations with charging data: size is sessions per day in Q1 2025, color is the uptime of the weakest port. Gray markers are the other ${aw.n - aw.d} sites in PennDOT's award inventory, which have no charging data here.`,
    sql: `SELECT a.award_id, a.station_id, a.has_session_data, a.organization_name, a.site_host, a.city, a.county, a.latitude AS lat, a.longitude AS lon,
  a.funding_round, a.project_type, a.status, a.highway, a.exit, a.total_dc_ports, a.total_l2_ports, a.award_amount,
  s.station_name, s.network_operator, strftime(s.operational_date, '%Y-%m-%d') AS opened, q.sessions_per_day, u.min_uptime
FROM awarded_stations a
LEFT JOIN stations s USING (station_id)
LEFT JOIN (SELECT * FROM quarterly_station WHERE quarter = '2025Q1') q USING (station_id)
LEFT JOIN (SELECT station_id, MIN(uptime_nevi_pct) AS min_uptime FROM port_uptime_reported GROUP BY 1) u USING (station_id)
ORDER BY a.has_session_data, a.station_id NULLS FIRST`,
    render: (rows, body) => {
      const gray = css("--muted"), surf = css("--surface");
      body.innerHTML = `<div class="map" id="map" role="img" aria-label="Map of NEVI award sites and reporting stations in Pennsylvania"></div>` +
        legendHTML([["Meets 97%", css("--good")], ["90–97%", css("--warn")], ["Below 90%", css("--crit")], ["Roster station, no data yet", css("--none")]]) +
        `<ul class="legend legend-sites"><li><span class="mk mk-op"></span>Other site, operational</li><li><span class="mk mk-ip"></span>In progress</li><li><span class="mk mk-pl"></span>Planned</li></ul>`;
      const map = L.map($("#map", body), { scrollWheelZoom: false, attributionControl: true }).setView([40.95, -77.6], 7);
      L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 13, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      }).addTo(map);
      const others = L.layerGroup().addTo(map), ours = L.layerGroup().addTo(map);
      const pts = [];
      const money = (v) => (v == null ? "no NEVI award (AFC creditable)" : "$" + Math.round(v).toLocaleString("en-US") + " award");
      rows.forEach((r) => {
        pts.push([r.lat, r.lon]);
        const place = `${esc(r.site_host || r.organization_name)}, ${esc(r.city)}`;
        const where = [r.highway, r.exit ? `exit ${r.exit}` : ""].filter(Boolean).join(" ");
        if (!r.station_id || !r.station_name) {
          const style = r.status === "Operational" ? { radius: 4, color: surf, weight: 1, fillColor: gray, fillOpacity: 0.85 }
            : r.status === "In Progress" ? { radius: 4, color: gray, weight: 1.5, fillColor: surf, fillOpacity: 1 }
            : { radius: 3, color: gray, weight: 1, fillColor: surf, fillOpacity: 0.6, opacity: 0.7 };
          L.circleMarker([r.lat, r.lon], style).addTo(others)
            .bindPopup(`<b>${place}</b><br>${esc(r.organization_name)}<br>${esc(r.status)} · ${esc(r.project_type)} · ${esc(r.funding_round)}<br>${esc(where)}${where ? "<br>" : ""}${money(r.award_amount)}<br><span style="color:var(--muted)">No charging data in this dashboard</span>`);
          return;
        }
        const st = status(r.has_session_data ? r.min_uptime : null);
        const rad = r.sessions_per_day ? 6 + 3.2 * Math.sqrt(r.sessions_per_day) : 6;
        const m = L.circleMarker([r.lat, r.lon], { radius: rad, color: surf, weight: 2, fillColor: st.color, fillOpacity: 0.95 }).addTo(ours);
        m.bindTooltip(r.station_name, { direction: "top", offset: [0, -rad] });
        m.bindPopup(`<b>${esc(r.station_name)}</b> · ${place}<br>${esc(r.network_operator)} · ${esc(where)} · opened ${r.opened}<br>${money(r.award_amount)}<br>` +
          (r.has_session_data ? `${fmt.dec(r.sessions_per_day)} sessions/day (Q1 2025)<br>${statusHTML(r.min_uptime, "Weakest port uptime " + fmt.pctv(r.min_uptime))}<br><a href="#stations/${encodeURIComponent(r.station_id)}">Station details</a>` : "Opened after the data cut-off (Q1 2025)"));
      });
      L.control.layers(null, { "Stations with data": ours, "Other award sites": others }, { collapsed: false, position: "topright" }).addTo(map);
      map.fitBounds(pts, { padding: [16, 16] });
      setTimeout(() => map.invalidateSize(), 50);
    },
  });
  await card(g, {
    title: "Stations with data", cls: "c5", table: false,
    ask: "Rank the stations by successful sessions per day in Q1 2025 and show their charge success rate",
    sub: "<b>Charge success</b>: when a driver plugged in, did they get energy? <b>Uptime</b>: how much of the time was the station's weakest port online? NEVI sets 97% for uptime. A station can score well on one and poorly on the other. Select a station for details.",
    sql: `SELECT s.station_id, s.station_name, s.network_operator, strftime(s.operational_date, '%Y-%m-%d') AS opened,
  q.sessions_per_day, t.success_rate, u.min_uptime
FROM stations s
LEFT JOIN (SELECT * FROM quarterly_station WHERE quarter = '2025Q1') q USING (station_id)
LEFT JOIN (SELECT station_id, SUM(sessions_success) / SUM(sessions_total) AS success_rate FROM daily_station GROUP BY 1) t USING (station_id)
LEFT JOIN (SELECT station_id, MIN(uptime_nevi_pct) AS min_uptime FROM port_uptime_reported GROUP BY 1) u USING (station_id)
ORDER BY q.sessions_per_day DESC NULLS LAST`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Station</th><th class="n">Sessions/day</th><th class="n hide-sm">Charge success</th><th>Uptime, weakest port</th></tr></thead><tbody>${rows.map((r) => `
        <tr class="${r.success_rate != null ? "click" : ""}" data-id="${esc(r.station_id)}" tabindex="${r.success_rate != null ? 0 : -1}">
          <td><b>${esc(r.station_name)}</b><br><span style="color:var(--muted);font-size:13px">${esc(r.network_operator)}, since ${new Date(r.opened + "T12:00").toLocaleDateString("en-US", { month: "short", year: "numeric" })}</span></td>
          <td class="n">${r.sessions_per_day != null ? fmt.dec(r.sessions_per_day) : "–"}</td>
          <td class="n hide-sm">${fmt.pct(r.success_rate, 0)}</td>
          <td>${r.success_rate != null ? statusHTML(r.min_uptime, fmt.pctv(r.min_uptime)) : `<span style="color:var(--muted)">Not reporting yet</span>`}</td></tr>`).join("")}</tbody></table></div>`;
      body.querySelectorAll("tr.click").forEach((tr) => {
        const go = () => (location.hash = `#stations/${encodeURIComponent(tr.dataset.id)}`);
        tr.addEventListener("click", go); tr.addEventListener("keydown", (e) => e.key === "Enter" && go());
      });
    },
  });
  await card(g, {
    title: "Successful sessions per month, by network",
    ask: "What was the month-over-month growth in successful sessions across all stations?",
    sub: "Pittston (EVgo) carried the program alone until Aston (Tesla) opened in September 2024. December 2023 is a partial month.",
    sql: `SELECT strftime(d.month, '%Y-%m') AS month, s.network_operator, SUM(d.sessions_success) AS sessions
FROM daily_station d JOIN stations s USING (station_id)
GROUP BY ALL ORDER BY month`,
    render: (rows, body) => {
      const months = [...new Set(rows.map((r) => r.month))];
      const ops = Object.keys(OPERATOR_SLOT).filter((o) => rows.some((r) => r.network_operator === o));
      const S = SERIES();
      body.innerHTML = `<div class="chart"></div>` + legendHTML(ops.map((o) => [o, S[OPERATOR_SLOT[o]]]));
      echart($(".chart", body), () => {
        const S = SERIES();
        return {
          tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
          xAxis: { type: "category", data: months, axisLabel: { formatter: (v) => fmt.month(v).replace(" ", "\n") } },
          yAxis: { type: "value" },
          series: ops.map((o, i) => ({
            ...BAR(S[OPERATOR_SLOT[o]]), name: o, stack: "s",
            itemStyle: { color: S[OPERATOR_SLOT[o]], borderColor: css("--surface"), borderWidth: 1, borderRadius: i === ops.length - 1 ? [4, 4, 0, 0] : 0 },
            data: months.map((m) => rows.find((r) => r.month === m && r.network_operator === o)?.sessions ?? 0),
          })),
        };
      });
    },
  });
  await card(g, {
    title: "NEVI program inventory by funding round",
    ask: "Which counties have the most planned NEVI sites, and how much funding is awarded there?",
    sub: "Award sites in PennDOT's inventory by status. AFC Creditable sites are existing NEVI-compliant stations counted toward the corridor build-out without a NEVI award. Status as of the October 2026 export.",
    sql: `SELECT funding_round, status, COUNT(*) AS sites, SUM(award_amount) AS award_usd
FROM awarded_stations GROUP BY ALL ORDER BY funding_round, status`,
    render: (rows, body) => {
      const statuses = ["Operational", "In Progress", "Planned"];
      const tot = {}, usd = {};
      rows.forEach((r) => { tot[r.funding_round] = (tot[r.funding_round] || 0) + r.sites; usd[r.funding_round] = (usd[r.funding_round] || 0) + (r.award_usd || 0); });
      const rounds = Object.keys(tot).sort((a, b) => tot[a] - tot[b]);
      const S = SERIES();
      body.innerHTML = `<div class="chart" style="height:${80 + rounds.length * 34}px"></div>` + legendHTML(statuses.map((t, i) => [t, S[i]]));
      echart($(".chart", body), () => {
        const S = SERIES();
        return {
          tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, formatter: (p) => `<b>${esc(p[0].name)}</b><br>${p.filter((x) => x.value).map((x) => `${x.seriesName}: ${x.value}`).join("<br>")}<br>${usd[p[0].name] ? "Awards: $" + fmt.compact(usd[p[0].name]) : "No NEVI awards"}` },
          grid: { left: 8, right: 64, top: 8, bottom: 8 },
          yAxis: { type: "category", data: rounds, splitLine: { show: false } },
          xAxis: { type: "value" },
          series: statuses.map((t, i) => ({ type: "bar", name: t, stack: "s", barMaxWidth: 18,
            itemStyle: { color: S[i], borderColor: css("--surface"), borderWidth: 1, borderRadius: i === 2 ? [0, 4, 4, 0] : 0 },
            label: i === 2 ? { show: true, position: "right", color: css("--ink-2"), formatter: (p) => `${tot[p.name]} site${tot[p.name] === 1 ? "" : "s"}` } : undefined,
            data: rounds.map((r) => rows.find((x) => x.funding_round === r && x.status === t)?.sites ?? 0) })),
        };
      });
    },
  });
};

VIEWS.reliability = async (view) => {
  view.insertAdjacentHTML("beforeend", `<p class="lede">NEVI requires every port to be available at least <strong>97%</strong> of the time over a year, after excluding outages outside the operator's control (23 CFR 680.116). Monthly figures below count every reported outage, so they are a conservative lower bound.</p>`);
  const g = grid(view);
  await card(g, {
    title: "Uptime of the weakest port, by month",
    ask: "Which months had the most outage hours, and at which stations?",
    sub: "Each cell is the worst of a station's four ports that month, from reported outage minutes with no exclusions. Hover for every port.",
    sql: `SELECT s.station_name, s.station_order, strftime(m.month, '%Y-%m') AS month, MIN(m.uptime_pct) AS min_uptime,
  string_agg(m.port_label || ' ' || round(m.uptime_pct, 1) || '%', ', ' ORDER BY m.port_label) AS ports
FROM monthly_port m JOIN stations s USING (station_id)
WHERE m.uptime_pct IS NOT NULL
GROUP BY ALL ORDER BY s.station_order, month`,
    render: (rows, body) => {
      const months = [...new Set(rows.map((r) => r.month))].sort();
      const names = [...new Set(rows.map((r) => r.station_name))].reverse();
      body.innerHTML = `<div class="chart tall"></div>` + legendHTML([["≥ 97%", css("--good")], ["90–97%", css("--warn")], ["< 90%", css("--crit")]]);
      echart($(".chart", body), () => ({
        tooltip: { formatter: (p) => { const r = rows.find((x) => x.station_name === names[p.value[1]] && x.month === months[p.value[0]]); return `<b>${esc(r.station_name)}</b>, ${fmt.month(r.month)}<br>${statusHTML(r.min_uptime, "Weakest port " + fmt.pctv(r.min_uptime, 2))}<br>${esc(r.ports)}`; } },
        grid: { left: 8, right: 8, top: 8, bottom: 8 },
        xAxis: { type: "category", data: months, splitLine: { show: false }, axisLabel: { formatter: (v) => fmt.month(v).replace(" ", "\n") } },
        yAxis: { type: "category", data: names, splitLine: { show: false } },
        visualMap: { show: false, type: "piecewise", dimension: 2, pieces: [{ gte: 97, color: css("--good") }, { gte: 90, lt: 97, color: css("--warn") }, { lt: 90, color: css("--crit") }] },
        series: [{ type: "heatmap", data: rows.map((r) => [months.indexOf(r.month), names.indexOf(r.station_name), r.min_uptime]),
          itemStyle: { borderColor: css("--surface"), borderWidth: 2, borderRadius: 3 } }],
      }));
    },
  });
  await card(g, {
    title: "Port uptime since opening, NEVI method", cls: "c7",
    ask: "Which ports are below the 97% uptime requirement, and how many outage hours did each have?",
    sub: "The operator's reported 12-month uptime where one exists; for ports under a year old, the same formula over the period since opening. Excluded outages are removed.",
    sql: `SELECT s.station_name, p.port_label, strftime(p.reporting_start, '%Y-%m-%d') AS since, strftime(p.reporting_end, '%Y-%m-%d') AS through,
  round(p.total_outage_min / 60, 1) AS outage_hours, round(p.excluded_outage_min / 60, 1) AS excluded_hours, p.reported_uptime_pct, p.uptime_nevi_pct
FROM port_uptime_reported p JOIN stations s USING (station_id)
ORDER BY p.uptime_nevi_pct, s.station_order, p.port_label`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Station</th><th>Port</th><th class="n">Outage h</th><th class="n">Excluded h</th><th>Uptime</th></tr></thead><tbody>${rows.map((r) => `
        <tr><td>${esc(r.station_name)}</td><td>${r.port_label}</td><td class="n">${fmt.dec(r.outage_hours)}</td><td class="n">${fmt.dec(r.excluded_hours)}</td><td>${statusHTML(r.uptime_nevi_pct, fmt.pctv(r.uptime_nevi_pct, 2))}</td></tr>`).join("")}</tbody></table></div>`;
    },
    caveat: "Chambersburg ports P1 and P2 were reported down from February 12, 2025 through the end of the data (about 47 days).",
  });
  await card(g, {
    title: "Longest outages", cls: "c5",
    ask: "List outages longer than 24 hours by station and month",
    sql: `SELECT s.station_name, o.port_label, strftime(o.start_date, '%Y-%m-%d') AS started, round(o.duration_hours, 1) AS hours
FROM outage_events o JOIN stations s USING (station_id)
ORDER BY o.duration_min DESC LIMIT 12`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Station</th><th>Port</th><th>Started</th><th class="n">Hours</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${esc(r.station_name)}</td><td>${r.port_label}</td><td>${r.started}</td><td class="n">${fmt.dec(r.hours)}</td></tr>`).join("")}</tbody></table></div>`;
    },
  });
  await card(g, {
    title: "Charge success rate", cls: "c6",
    ask: "How has the charge success rate changed by quarter at each station?",
    sub: "Of all plug-ins, the share that delivered at least 1 kWh with no error. This measures the driver's experience while the port is online; uptime above measures whether it is online at all.",
    sql: `SELECT s.station_name, SUM(d.sessions_success) / SUM(d.sessions_total) AS success_rate, SUM(d.sessions_total) AS attempts
FROM daily_station d JOIN stations s USING (station_id)
GROUP BY ALL ORDER BY success_rate`,
    render: (rows, body) => {
      body.innerHTML = `<div class="chart"></div>`;
      echart($(".chart", body), () => ({
        tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, formatter: (p) => { const r = rows[p[0].dataIndex]; return `<b>${esc(r.station_name)}</b><br>${fmt.pct(r.success_rate)} of ${fmt.int(r.attempts)} attempts`; } },
        grid: { left: 8, right: 48, top: 8, bottom: 8 },
        yAxis: { type: "category", data: rows.map((r) => r.station_name), splitLine: { show: false } },
        xAxis: { type: "value", max: 1, axisLabel: { formatter: (v) => v * 100 + "%" } },
        series: [{ type: "bar", barMaxWidth: 18, data: rows.map((r) => r.success_rate), itemStyle: { color: css("--s1"), borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: "right", color: css("--ink-2"), formatter: (p) => fmt.pct(p.value, 0) } }],
      }));
    },
    caveat: "Aston (Tesla) reports no failed sessions at all, which suggests Tesla's submission leaves failures out. Treat its 100% as unverified.",
  });
  await card(g, {
    title: "Why sessions fail", cls: "c6",
    ask: "What are the main reasons sessions fail at the Francis Energy stations?",
    sub: "Failed sessions by type. CX codes are the ChargeX customer-facing error codes; the most common pattern is a session that ends with no error but delivers almost no energy.",
    sql: `WITH f AS (
  SELECT s.station_name, f.failure_type, SUM(f.sessions) AS n
  FROM failures_quarterly f JOIN stations s USING (station_id) GROUP BY ALL),
top AS (SELECT failure_type FROM f GROUP BY 1 ORDER BY SUM(n) DESC LIMIT 4)
SELECT station_name,
  CASE WHEN failure_type IN (SELECT failure_type FROM top) THEN failure_type ELSE 'all_other' END AS failure_type,
  SUM(n) AS sessions
FROM f GROUP BY ALL ORDER BY station_name`,
    render: (rows, body) => {
      const tot = {}; rows.forEach((r) => (tot[r.station_name] = (tot[r.station_name] || 0) + r.sessions));
      const names = Object.keys(tot).sort((a, b) => tot[a] - tot[b]);
      const typeTot = {}; rows.forEach((r) => (typeTot[r.failure_type] = (typeTot[r.failure_type] || 0) + r.sessions));
      const types = Object.keys(typeTot).filter((t) => t !== "all_other").sort((a, b) => typeTot[b] - typeTot[a]).concat(typeTot.all_other ? ["all_other"] : []);
      const label = (t) => ({ "no_error_but_<1kWh": "No error, < 1 kWh", other: "Unspecified error", all_other: "All other codes" }[t] || t);
      const color = (i, t) => (t === "all_other" ? css("--none") : SERIES()[i]);
      body.innerHTML = `<div class="chart"></div>` + legendHTML(types.map((t, i) => [label(t), color(i, t)]));
      echart($(".chart", body), () => ({
        tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
        grid: { left: 8, right: 16, top: 8, bottom: 8 },
        yAxis: { type: "category", data: names, splitLine: { show: false } },
        xAxis: { type: "value" },
        series: types.map((t, i) => ({ type: "bar", name: label(t), stack: "f", barMaxWidth: 18,
          itemStyle: { color: color(i, t), borderColor: css("--surface"), borderWidth: 1, borderRadius: i === types.length - 1 ? [0, 4, 4, 0] : 0 },
          data: names.map((n) => rows.find((r) => r.station_name === n && r.failure_type === t)?.sessions ?? 0) })),
      }));
    },
  });
};

function stationFilter(view, onChange, includeAll = true) {
  const opts = STATIONS.filter((s) => s.has_session_data);
  const saved = store.get("usage-station") || "all";
  view.insertAdjacentHTML("beforeend", `<div class="filters"><label>Station <select id="stsel">${includeAll ? `<option value="all">All stations</option>` : ""}${opts.map((s) => `<option value="${esc(s.station_id)}">${esc(s.station_name)} (${esc(s.network_operator)})</option>`).join("")}</select></label></div>`);
  const sel = $("#stsel", view);
  if ([...sel.options].some((o) => o.value === saved)) sel.value = saved;
  sel.addEventListener("change", () => { store.set("usage-station", sel.value); onChange(sel.value); });
  return sel.value;
}
const where = (id, alias = "") => (id === "all" ? "" : `WHERE ${alias}station_id = '${id.replace(/'/g, "''")}'`);

VIEWS.usage = async (view) => {
  view.insertAdjacentHTML("beforeend", `<p class="lede">When drivers charge, how long they stay, and whether stations are running out of ports. Pick a station to compare it against the network.</p>`);
  const holder = document.createElement("div");
  const draw = async (id) => {
    holder.innerHTML = "";
    const g = grid(holder);
    const w = where(id);
    await card(g, {
      title: "When sessions start", cls: "c7",
    ask: "What share of sessions start on weekends at each station?",
      sub: "Successful sessions by local start hour and day of week, all quarters.",
      sql: `SELECT day_of_week, hour, SUM(sessions) AS sessions FROM hourly_profile ${w} GROUP BY ALL ORDER BY 1, 2`,
      render: (rows, body) => {
        const max = Math.max(...rows.map((r) => r.sessions), 1);
        body.innerHTML = `<div class="chart"></div>`;
        echart($(".chart", body), () => ({
          tooltip: { formatter: (p) => `${DOW[p.value[1]]} ${String(p.value[0]).padStart(2, "0")}:00–${String(p.value[0]).padStart(2, "0")}:59<br><b>${fmt.int(p.value[2])}</b> sessions` },
          grid: { left: 8, right: 8, top: 8, bottom: 40 },
          xAxis: { type: "category", data: [...Array(24).keys()], splitLine: { show: false }, axisLabel: { interval: 0, formatter: (v) => { v = +v; return v % 6 === 0 ? (v === 0 ? "12am" : v === 12 ? "noon" : v < 12 ? v + "am" : v - 12 + "pm") : ""; } } },
          yAxis: { type: "category", data: DOW, inverse: true, splitLine: { show: false } },
          visualMap: { min: 0, max, orient: "horizontal", left: "center", bottom: 0, itemWidth: 12, itemHeight: 160, text: [fmt.int(max), "0"], textStyle: { color: css("--muted") },
            inRange: { color: [css("--seq-0"), css("--seq-1"), css("--seq-2"), css("--seq-3"), css("--seq-4")] } },
          series: [{ type: "heatmap", data: rows.map((r) => [r.hour, r.day_of_week, r.sessions]), itemStyle: { borderColor: css("--surface"), borderWidth: 2, borderRadius: 2 } }],
        }));
      },
    });
    await card(g, {
      title: "Payment methods", cls: "c5",
    ask: "How does the payment method mix differ between networks?",
      sub: "Share of successful sessions.",
      sql: `SELECT payment_method, SUM(sessions) AS sessions FROM payments_quarterly ${w} GROUP BY ALL ORDER BY sessions DESC`,
      render: (rows, body) => {
        const tot = rows.reduce((a, r) => a + r.sessions, 0);
        const label = { credit_card_terminal: "Card at charger", phone_online: "Phone / app", membership: "Membership", roaming: "Roaming", other: "Other", none: "None recorded" };
        body.innerHTML = `<div class="chart short"></div>`;
        echart($(".chart", body), () => ({
          tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, formatter: (p) => `${p[0].name}<br><b>${fmt.pct(p[0].value / tot)}</b> (${fmt.int(p[0].value)})` },
          grid: { left: 8, right: 48, top: 8, bottom: 8 },
          yAxis: { type: "category", data: rows.map((r) => label[r.payment_method] || r.payment_method), inverse: true, splitLine: { show: false } },
          xAxis: { type: "value", axisLabel: { show: false }, splitLine: { show: false } },
          series: [{ type: "bar", barMaxWidth: 18, data: rows.map((r) => r.sessions), itemStyle: { color: css("--s1"), borderRadius: [0, 4, 4, 0] },
            label: { show: true, position: "right", color: css("--ink-2"), formatter: (p) => fmt.pct(p.value / tot, 0) } }],
        }));
      },
    });
    await card(g, {
      title: "Port utilization by quarter", cls: "c6",
    ask: "Which stations had the highest port utilization in each quarter?",
      sub: "Share of port-hours occupied by a charging vehicle. A busy highway station runs 15–25%.",
      sql: `SELECT s.station_name, q.quarter, q.port_utilization FROM quarterly_station q JOIN stations s USING (station_id)
${id === "all" ? "WHERE q.quarter = '2025Q1'" : where(id, "q.")} ORDER BY ${id === "all" ? "q.port_utilization" : "q.quarter"}`,
      render: (rows, body) => {
        const cats = rows.map((r) => (id === "all" ? r.station_name : fmt.q(r.quarter)));
        body.innerHTML = `<div class="chart"></div>`;
        echart($(".chart", body), () => ({
          tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, valueFormatter: (v) => fmt.pct(v) },
          grid: { left: 8, right: 48, top: 8, bottom: 8 },
          yAxis: { type: "category", data: cats, splitLine: { show: false } },
          xAxis: { type: "value", axisLabel: { formatter: (v) => Math.round(v * 100) + "%" } },
          series: [{ type: "bar", barMaxWidth: 18, data: rows.map((r) => r.port_utilization), itemStyle: { color: css("--s1"), borderRadius: [0, 4, 4, 0] },
            label: { show: true, position: "right", color: css("--ink-2"), formatter: (p) => fmt.pct(p.value, 1) } }],
        }));
      },
      caveat: id === "all" ? "Q1 2025 shown for every station." : "",
    });
    await card(g, {
      title: "Minutes per week with every port taken", cls: "c6",
    ask: "Which station has the most minutes with all ports busy, and in which month?",
      sub: "When all four ports are occupied, the next driver waits. This is the leading indicator for adding capacity.",
      sql: `SELECT strftime(date_trunc('week', d.date), '%Y-%m-%d') AS week, SUM(d.all_ports_busy_minutes) AS minutes_all_busy
FROM daily_station d ${where(id, "d.")} GROUP BY ALL ORDER BY week`,
      render: (rows, body) => {
        body.innerHTML = `<div class="chart"></div>`;
        echart($(".chart", body), () => ({
          tooltip: { trigger: "axis", formatter: (p) => `Week of ${p[0].name}<br><b>${fmt.int(p[0].value)}</b> minutes with all ports busy` },
          xAxis: { type: "category", data: rows.map((r) => r.week), axisLabel: { formatter: (v) => new Date(v + "T12:00").toLocaleDateString("en-US", { month: "short", year: "2-digit" }) } },
          yAxis: { type: "value" },
          series: [{ type: "bar", barMaxWidth: 10, data: rows.map((r) => r.minutes_all_busy), itemStyle: { color: css("--s2"), borderRadius: [3, 3, 0, 0] } }],
        }));
      },
    });
    for (const [metric, title, sub, unit, ref] of [
      ["energy_kwh", "Energy per session", "Successful sessions by kWh delivered.", "kWh", null],
      ["power_kw", "Average power per session", "Session average power, which the vehicle limits as much as the charger. The line marks the NEVI 150 kW port minimum.", "kW", 150],
    ]) {
      await card(g, {
        title, sub, cls: "c6",
        ask: metric === "energy_kwh" ? "What is the average and median energy per session at each station?" : "What share of sessions averaged 150 kW or more at each station?",
        sql: `SELECT bin_lo, bin_hi, SUM(sessions) AS sessions FROM session_distribution WHERE metric = '${metric}'${id === "all" ? "" : ` AND station_id = '${id}'`} GROUP BY ALL ORDER BY bin_lo`,
        render: (rows, body) => {
          body.innerHTML = `<div class="chart short"></div>`;
          const el = $(".chart", body), last = rows.length - 1, top = rows[last].bin_hi, w = rows[0].bin_hi - rows[0].bin_lo;
          echart(el, () => ({
            tooltip: { trigger: "item", formatter: (p) => { const r = rows[p.dataIndex]; return `${r.bin_lo}${p.dataIndex === last ? "+" : "–" + r.bin_hi} ${unit}<br><b>${fmt.int(r.sessions)}</b> sessions`; } },
            grid: { left: 8, right: 40, top: 20, bottom: 8 },
            xAxis: { type: "value", min: 0, max: top, interval: w * (rows.length > 16 ? 4 : 2), splitLine: { show: false },
              axisLabel: { formatter: (v) => (v === top ? `${top}+` : v) + (v === 0 ? "" : ""), hideOverlap: true }, name: unit, nameGap: 4 },
            yAxis: { type: "value" },
            series: [{ type: "bar", barWidth: Math.max(3, ((el.clientWidth || 500) - 80) / rows.length - 3), data: rows.map((r) => [(r.bin_lo + r.bin_hi) / 2, r.sessions]),
              itemStyle: { color: css("--s1"), borderRadius: [3, 3, 0, 0] },
              markLine: ref ? { symbol: "none", silent: true, lineStyle: { color: css("--ink"), type: "solid", width: 1.5 }, label: { formatter: `NEVI minimum ${ref} kW`, color: css("--ink-2"), position: "end" }, data: [{ xAxis: ref }] } : undefined }],
          }));
        },
      });
    }
  };
  stationFilter(view, draw);
  view.appendChild(holder);
  await draw($("#stsel", view).value);
};

VIEWS.stations = async (view, arg) => {
  const opts = STATIONS.filter((s) => s.has_session_data);
  const id = arg && opts.some((s) => s.station_id === arg) ? arg : opts[0].station_id;
  view.insertAdjacentHTML("beforeend", `<div class="filters"><label>Station <select id="stsel2">${opts.map((s) => `<option value="${esc(s.station_id)}" ${s.station_id === id ? "selected" : ""}>${esc(s.station_name)} (${esc(s.network_operator)})</option>`).join("")}</select></label></div>`);
  $("#stsel2", view).addEventListener("change", (e) => (location.hash = `#stations/${encodeURIComponent(e.target.value)}`));
  const s = STATIONS.find((x) => x.station_id === id);
  const sid = id.replace(/'/g, "''");
  const k = (await q(`SELECT SUM(sessions_success) s, SUM(sessions_success)/SUM(sessions_total) sr, SUM(energy_kwh) kwh, COUNT(*) n_days FROM daily_station WHERE station_id='${sid}'`)).rows[0];
  const u = (await q(`SELECT MIN(uptime_nevi_pct) u FROM port_uptime_reported WHERE station_id='${sid}'`)).rows[0];
  view.insertAdjacentHTML("beforeend", `
    <p class="lede"><strong>${esc(s.station_name)}</strong>, ${esc(s.address)}, ${esc(s.city)}. ${esc(s.awardee)} on the ${esc(s.network_operator)} network, near ${esc(s.interstate)}. Opened ${new Date(s.operational_date + "T12:00").toLocaleDateString("en-US", { dateStyle: "long" })}; O&amp;M obligation runs to ${new Date(s.om_end_date + "T12:00").toLocaleDateString("en-US", { month: "long", year: "numeric" })}.</p>
    <div class="tiles">
      <div class="tile"><div class="label">Successful sessions</div><div class="value">${fmt.int(k.s)}</div><div class="note">${fmt.int(k.n_days)} days of data</div></div>
      <div class="tile"><div class="label">Sessions per day</div><div class="value">${fmt.dec(k.s / k.n_days)}</div><div class="note">Average since opening</div></div>
      <div class="tile"><div class="label">Charge success</div><div class="value">${fmt.pct(k.sr)}</div><div class="note">${fmt.compact(k.kwh)} kWh delivered</div></div>
      <div class="tile"><div class="label">Uptime, weakest port</div><div class="value">${fmt.pctv(u.u)}</div><div class="note">${statusHTML(u.u)}</div></div>
    </div>`);
  const nm = s.station_name;
  const sq = [`How did monthly successful sessions and energy change at ${nm}?`, `What were the longest outages at ${nm}?`, `What are the busiest hours at ${nm}?`, `Why do sessions fail at ${nm}?`];
  view.insertAdjacentHTML("beforeend", `<div class="ask-inline"><span>${SPARK} Ask about ${esc(nm)}</span>${sq.map((x) => `<button class="chip" data-q="${esc(x)}">${esc(x)}</button>`).join("")}</div>`);
  view.querySelectorAll(".ask-inline .chip").forEach((c) => c.addEventListener("click", () => Ask.open(c.dataset.q, true)));
  const g = grid(view);
  await card(g, {
    title: "Daily successful sessions",
    ask: `Which were the busiest days at ${nm}, and what day of the week were they?`,
    sub: "Bars are daily counts; the line is the 7-day average.",
    sql: `SELECT strftime(date, '%Y-%m-%d') AS day, sessions_success,
  AVG(sessions_success) OVER (ORDER BY date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS avg_7d
FROM daily_station WHERE station_id = '${sid}' ORDER BY date`,
    render: (rows, body) => {
      body.innerHTML = `<div class="chart"></div>` + legendHTML([["Daily", css("--seq-1")], ["7-day average", css("--s1")]]);
      echart($(".chart", body), () => ({
        tooltip: { trigger: "axis", formatter: (p) => `${p[0].name}<br>${p.map((x) => `${x.seriesName}: <b>${fmt.dec(x.value, x.seriesIndex ? 1 : 0)}</b>`).join("<br>")}` },
        xAxis: { type: "category", data: rows.map((r) => r.day), axisLabel: { formatter: (v) => new Date(v + "T12:00").toLocaleDateString("en-US", { month: "short", year: "2-digit" }) } },
        yAxis: { type: "value" },
        series: [
          { type: "bar", name: "Daily", data: rows.map((r) => r.sessions_success), barMaxWidth: 6, itemStyle: { color: css("--seq-1"), borderRadius: [2, 2, 0, 0] } },
          { type: "line", name: "7-day average", data: rows.map((r) => r.avg_7d), showSymbol: false, lineStyle: { width: 2, color: css("--s1") }, itemStyle: { color: css("--s1") } },
        ],
      }));
    },
  });
  await card(g, {
    title: "Ports", cls: "c6",
    sql: `SELECT m.port_label, SUM(m.sessions_success) AS sessions, round(SUM(m.energy_kwh)) AS kwh,
  round(SUM(m.outage_minutes) / 60, 1) AS outage_hours, ANY_VALUE(p.uptime_nevi_pct) AS uptime_pct
FROM monthly_port m LEFT JOIN port_uptime_reported p USING (station_id, port_label)
WHERE m.station_id = '${sid}' GROUP BY ALL ORDER BY m.port_label`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Port</th><th class="n">Sessions</th><th class="n">kWh</th><th class="n">Outage h</th><th>Uptime (NEVI)</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${r.port_label}</td><td class="n">${fmt.int(r.sessions)}</td><td class="n">${fmt.int(r.kwh)}</td><td class="n">${fmt.dec(r.outage_hours)}</td><td>${statusHTML(r.uptime_pct, fmt.pctv(r.uptime_pct, 2))}</td></tr>`).join("")}</tbody></table></div>`;
    },
  });
  await card(g, {
    title: "Quarterly figures: computed vs PennDOT summary", cls: "c6",
    sub: "Successful sessions computed here from the raw submissions, next to PennDOT's quarterly workbook.",
    sql: `SELECT q.quarter, q.sessions_success AS computed, r.sessions_success AS penndot_summary,
  q.sessions_success - r.sessions_success AS difference, r.rolling_12mo_uptime_pct AS penndot_uptime_pct
FROM quarterly_station q LEFT JOIN quarterly_reported r USING (station_id, quarter)
WHERE q.station_id = '${sid}' ORDER BY q.quarter`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Quarter</th><th class="n">Computed</th><th class="n">PennDOT</th><th class="n">Diff.</th><th class="n">PennDOT uptime</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${fmt.q(r.quarter)}</td><td class="n">${fmt.int(r.computed)}</td><td class="n">${fmt.int(r.penndot_summary)}</td><td class="n">${r.difference == null ? "–" : (r.difference > 0 ? "+" : "") + r.difference}</td><td class="n">${fmt.pctv(r.penndot_uptime_pct, 2)}</td></tr>`).join("")}</tbody></table></div>`;
    },
    caveat: "Differences come from how failed sessions are counted. See Data notes.",
  });
};

// ------------------------------------------------------------------ ask
// One engine, three entry points: the box on the overview, the side panel on every page,
// and the "Ask" button on each chart (opens the panel with a question about that chart).
const EXAMPLES = [
  "Which ports are below the 97% uptime requirement?",
  "How have monthly sessions grown at Aston since it opened?",
  "What are the main reasons sessions fail at the Francis Energy stations?",
  "Which station has the most minutes with all ports busy, and in which month?",
  "How many awarded sites are operational in each funding round?",
  "What share of sessions start on weekends at each station?",
];
const SQL_OK = /^\s*(with|select)\b/i;
const SQL_BAD = /\b(copy|attach|detach|install|load|pragma|export|import|create|insert|update|delete|drop|alter|call|set|read_csv|read_parquet|read_json|glob)\b/i;
function guardSQL(sql) {
  const s = sql.trim().replace(/;\s*$/, "");
  if (!SQL_OK.test(s) || s.includes(";") || SQL_BAD.test(s.replace(/'[^']*'/g, "''"))) throw new Error("Only a single read-only SELECT query is allowed.");
  return s;
}
async function api(path, payload) {
  const r = await fetch(CFG.workerUrl.replace(/\/$/, "") + path, {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${store.get("user")}:${store.get("token")}` },
    body: JSON.stringify(payload),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `The question service returned ${r.status}.`);
  return j;
}
function autoChart(spec, columns, rows) {
  if (!rows.length || rows.length > 400) return null;
  const numeric = columns.filter((c) => rows.every((r) => r[c] == null || typeof r[c] === "number"));
  let x = spec?.x && columns.includes(spec.x) ? spec.x : columns.find((c) => !numeric.includes(c)) || columns[0];
  let ys = (spec?.y || []).filter((c) => numeric.includes(c) && c !== x);
  if (!ys.length) ys = numeric.filter((c) => c !== x).slice(0, 1);
  if (!ys.length || rows.length < 2) return null;
  const type = spec?.type === "line" || /month|date|day|week|quarter/i.test(x) ? "line" : "bar";
  if (spec?.type === "none") return null;
  return { type, x, ys: ys.slice(0, 3) };
}

const Ask = {
  busy: false,
  // Runs one question end to end and renders the answer into `box`.
  async run(question, box, persist) {
    box.className = "answer";
    box.innerHTML = `<div class="q">${esc(question)}</div><p class="a"><span class="spin"></span>Writing a query…</p>`;
    try {
      let sql, rows, columns, err = null, model;
      for (let attempt = 0; attempt < 3; attempt++) {
        const r = await api("/sql", { question, previous_sql: sql, error: err });
        model = r.model;
        if (!r.sql) throw new Error(r.explanation || "The model could not write a query for this question. Try rephrasing it.");
        sql = r.sql;
        try { ({ rows, columns } = await q(guardSQL(sql))); err = null; break; }
        catch (x) { err = x.message; $(".a", box).innerHTML = `<span class="spin"></span>Fixing the query (attempt ${attempt + 2})…`; }
      }
      if (err) throw new Error(`The query failed to run: ${err}`);
      $(".a", box).innerHTML = `<span class="spin"></span>Reading ${rows.length} rows…`;
      let a;
      try { a = await api("/answer", { question, sql, columns, rows: rows.slice(0, 60), row_count: rows.length }); }
      catch (x) { a = { answer: `The query returned ${rows.length} row${rows.length === 1 ? "" : "s"} (shown below), but the written summary could not be generated this time. Try asking again.`, model }; }
      const spec = autoChart(a.chart, columns, rows);
      box.innerHTML = `<div class="q">${esc(question)}</div>
        <p class="a">${esc(a.answer)}</p>${spec ? `<div class="chart" style="margin-top:12px"></div>` : ""}
        <div class="answer-foot"><span class="who">${esc(a.model || model || "model")} · ${rows.length} row${rows.length === 1 ? "" : "s"}</span>
        <span class="card-tools"><button class="tool" data-t="table" aria-pressed="false">Table</button><button class="tool" data-t="sql" aria-pressed="false">SQL</button></span></div>
        <pre class="sql" hidden></pre><div class="tbl" hidden></div>`;
      $("pre.sql", box).textContent = sql;
      box.querySelectorAll(".tool").forEach((b) => b.addEventListener("click", () => {
        const on = b.getAttribute("aria-pressed") !== "true"; b.setAttribute("aria-pressed", on);
        if (b.dataset.t === "sql") $("pre.sql", box).hidden = !on; else { const t = $(".tbl", box); t.hidden = !on; if (on && !t.innerHTML) t.innerHTML = tableHTML(columns, rows); }
      }));
      if (spec) {
        const el = $(".chart", box); ro.observe(el);
        const horiz = spec.type === "bar" && rows.length > 6;
        el.style.height = horiz ? Math.min(900, 60 + rows.length * 26) + "px" : "260px";
        const cat = { type: "category", data: rows.map((r) => r[spec.x]), inverse: horiz, splitLine: { show: false } };
        echart(el, () => {
          const S = SERIES();
          return {
            tooltip: { trigger: "axis", axisPointer: { type: horiz ? "shadow" : "line" } },
            legend: spec.ys.length > 1 ? { top: 0, textStyle: { color: css("--ink-2") } } : undefined,
            grid: { top: spec.ys.length > 1 ? 32 : 16 },
            xAxis: horiz ? { type: "value" } : cat,
            yAxis: horiz ? cat : { type: "value" },
            series: spec.ys.map((y, i) => (spec.type === "line"
              ? { type: "line", name: y, data: rows.map((r) => r[y]), showSymbol: rows.length < 30, symbolSize: 8, lineStyle: { width: 2, color: S[i] }, itemStyle: { color: S[i] } }
              : { ...BAR(S[i]), name: y, data: rows.map((r) => r[y]), barMaxWidth: horiz ? 16 : 24, itemStyle: { color: S[i], borderRadius: horiz ? [0, 4, 4, 0] : [4, 4, 0, 0] } })),
          };
        }, persist);
      }
    } catch (x) {
      $(".a", box).innerHTML = `<span class="err-box">${esc(x.message)}</span>`;
    }
  },
  // Wires a form (input + button + chips) to an answers container.
  bind(form, out, { persist = false, onSubmit } = {}) {
    const input = $("textarea, input", form), btn = $("button[type=submit]", form);
    form.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => { input.value = c.dataset.q || c.textContent; form.requestSubmit(); }));
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const question = input.value.trim();
      if (!question || !CFG.workerUrl || btn.disabled) return;
      if (onSubmit && onSubmit(question) === false) return;
      btn.disabled = true;
      const box = document.createElement("section");
      out.prepend(box);
      await Ask.run(question, box, persist);
      btn.disabled = false;
    });
    if (!CFG.workerUrl) btn.disabled = true;
  },
  formHTML({ placeholder, examples = [], cls = "" }) {
    return `<form class="ask-form ${cls}" autocomplete="off">
      <div class="ask-input"><textarea rows="1" placeholder="${esc(placeholder)}" aria-label="Your question"></textarea>
      <button type="submit" class="ask-go">${SPARK}<span>Ask</span></button></div>
      ${examples.length ? `<div class="chips">${examples.map((e) => `<button type="button" class="chip" data-q="${esc(e)}">${esc(e)}</button>`).join("")}</div>` : ""}
      ${CFG.workerUrl ? "" : `<p class="notice">The question service is not connected on this copy of the dashboard.</p>`}
    </form>`;
  },
  // Side panel, available on every page.
  init() {
    const d = $("#ask-drawer");
    d.insertAdjacentHTML("beforeend", Ask.formHTML({ placeholder: "Ask about any station, port, month or award…", examples: EXAMPLES.slice(0, 4) }) + `<div class="drawer-answers"></div>`);
    Ask.drawerForm = $(".ask-form", d);
    Ask.bind(Ask.drawerForm, $(".drawer-answers", d), { persist: true });
    $("#ask-close").addEventListener("click", Ask.close);
    $("#ask-fab").addEventListener("click", () => Ask.open());
    $("#nav-ask").addEventListener("click", (e) => { e.preventDefault(); Ask.open(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !d.hidden) Ask.close(); });
    $("#ask-fab").hidden = false;
  },
  open(question, run = false) {
    const d = $("#ask-drawer");
    d.hidden = false;
    document.body.classList.add("drawer-open");
    const input = $("textarea", Ask.drawerForm);
    if (question) input.value = question;
    if (run && question) Ask.drawerForm.requestSubmit(); else input.focus();
    setTimeout(() => charts.forEach((e) => e.persist && e.c.resize()), 50);
  },
  close() {
    $("#ask-drawer").hidden = true;
    document.body.classList.remove("drawer-open");
    $("#ask-fab").focus();
  },
};

// ------------------------------------------------------------------ downloads
// Everything here is generated in the browser from the decrypted aggregates. No session-level
// records exist in the bundle, so none can be exported.
const loadScript = (src) => new Promise((ok, no) => { const s = document.createElement("script"); s.src = src; s.onload = ok; s.onerror = () => no(new Error(`Could not load ${src}`)); document.head.appendChild(s); });
const today = () => new Date().toLocaleDateString("en-US", { dateStyle: "long" });
const saveBlob = (blob, name) => { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000); };
const NAMED = "JOIN stations s USING (station_id)";

const SHEETS = [
  { name: "Station summary", desc: "One row per reporting station, all quarters: sessions, success, energy, utilization, queue minutes, uptime.",
    sql: `WITH t AS (
  SELECT station_id, MIN(date) AS first_day, MAX(date) AS last_day, COUNT(*) AS days_in_service,
    SUM(sessions_total) AS attempts, SUM(sessions_success) AS sessions, SUM(sessions_failed) AS failed,
    SUM(energy_kwh) AS energy_kwh, SUM(avg_power_kw * sessions_success) / NULLIF(SUM(sessions_success), 0) AS avg_power_kw,
    SUM(avg_duration_min * sessions_success) / NULLIF(SUM(sessions_success), 0) AS avg_duration_min,
    AVG(port_utilization) AS port_utilization, SUM(all_ports_busy_minutes) AS all_ports_busy_minutes,
    MAX(peak_concurrent) AS peak_concurrent, SUM(outage_port_minutes) / 60 AS outage_port_hours
  FROM daily_station GROUP BY 1),
u AS (SELECT station_id, MIN(uptime_nevi_pct) AS weakest_port_uptime_pct, COUNT(*) FILTER (WHERE uptime_nevi_pct < 97) AS ports_below_97 FROM port_uptime_reported GROUP BY 1)
SELECT s.station_name, s.station_id, s.network_operator, s.awardee, s.city, s.county, s.highway, s.exit, s.funding_round, s.award_amount AS award_usd,
  s.operational_date, s.n_ports, t.first_day, t.last_day, t.days_in_service, t.attempts, t.sessions, t.failed,
  t.sessions / t.attempts AS charge_success_rate, t.sessions / t.days_in_service AS sessions_per_day, t.energy_kwh,
  t.energy_kwh / t.sessions AS kwh_per_session, t.energy_kwh * 3 AS est_ev_miles, t.avg_power_kw, t.avg_duration_min,
  t.port_utilization, t.all_ports_busy_minutes, t.peak_concurrent, t.outage_port_hours, u.weakest_port_uptime_pct, u.ports_below_97
FROM t ${NAMED} LEFT JOIN u USING (station_id) ORDER BY t.sessions DESC` },
  { name: "Quarterly by station", desc: "Computed quarterly figures next to PennDOT's quarterly workbook, with differences.",
    sql: `SELECT s.station_name, q.quarter, q.days_in_service, q.sessions_total AS attempts, q.sessions_success, q.sessions_failed, q.success_rate AS charge_success_rate,
  q.energy_kwh, q.avg_energy_kwh AS kwh_per_session, q.median_power_kw, q.avg_duration_min, q.sessions_per_day, q.port_utilization,
  q.all_ports_busy_minutes, q.outage_port_minutes / 60 AS outage_port_hours, q.uptime_pct_raw AS availability_raw_pct,
  r.sessions_success AS penndot_sessions_success, r.sessions_failed AS penndot_sessions_failed, r.energy_kwh AS penndot_energy_kwh,
  r.rolling_12mo_uptime_pct AS penndot_rolling_uptime_pct, q.sessions_success - r.sessions_success AS diff_sessions_success
FROM quarterly_station q ${NAMED} LEFT JOIN quarterly_reported r USING (station_id, quarter) ORDER BY s.station_order, q.quarter` },
  { name: "Monthly by station", desc: "Monthly usage, reliability and capacity indicators per station.",
    sql: `SELECT s.station_name, strftime(d.month, '%Y-%m') AS month, COUNT(*) AS days, SUM(d.sessions_total) AS attempts, SUM(d.sessions_success) AS sessions,
  SUM(d.sessions_failed) AS failed, SUM(d.sessions_success) / NULLIF(SUM(d.sessions_total), 0) AS charge_success_rate,
  SUM(d.energy_kwh) AS energy_kwh, SUM(d.sessions_success) / COUNT(*) AS sessions_per_day,
  SUM(d.energy_kwh) / NULLIF(SUM(d.sessions_success), 0) AS kwh_per_session, AVG(d.port_utilization) AS port_utilization,
  SUM(d.all_ports_busy_minutes) AS all_ports_busy_minutes, MAX(d.peak_concurrent) AS peak_concurrent, SUM(d.outage_port_minutes) / 60 AS outage_port_hours
FROM daily_station d ${NAMED} GROUP BY ALL ORDER BY s.station_name, month` },
  { name: "Daily by station", desc: "Daily totals per station, including zero-session days.",
    sql: `SELECT strftime(d.date, '%Y-%m-%d') AS date, s.station_name, d.sessions_total AS attempts, d.sessions_success AS sessions, d.sessions_failed AS failed,
  d.energy_kwh, d.ports_used, d.port_utilization, d.all_ports_busy_minutes, d.peak_concurrent, d.outage_port_minutes
FROM daily_station d ${NAMED} ORDER BY s.station_name, d.date` },
  { name: "Port uptime (NEVI)", desc: "Per-port uptime by the 23 CFR 680.116 formula, with excluded outages removed.",
    sql: `SELECT s.station_name, p.port_label, p.reporting_start, p.reporting_end, p.reported_uptime_pct AS operator_reported_12mo_pct,
  p.total_outage_min / 60 AS outage_hours, p.excluded_outage_min / 60 AS excluded_hours, p.uptime_since_start_pct, p.uptime_nevi_pct,
  CASE WHEN p.uptime_nevi_pct >= 97 THEN 'Meets 97%' WHEN p.uptime_nevi_pct >= 90 THEN '90-97%' ELSE 'Below 90%' END AS status
FROM port_uptime_reported p ${NAMED} ORDER BY p.uptime_nevi_pct` },
  { name: "Monthly port availability", desc: "Per port and month, from outage events with no exclusions (a lower bound).",
    sql: `SELECT s.station_name, m.port_label, strftime(m.month, '%Y-%m') AS month, m.sessions_success AS sessions, m.energy_kwh, m.busy_minutes,
  m.outage_events, m.outage_minutes, m.uptime_pct AS availability_raw_pct
FROM monthly_port m ${NAMED} ORDER BY s.station_name, m.port_label, month` },
  { name: "Outage events", desc: "Every reported outage event, longest first.",
    sql: `SELECT s.station_name, o.port_label, o.start_date, o.end_date, o.duration_hours FROM outage_events o ${NAMED} ORDER BY o.duration_min DESC` },
  { name: "Failures by type", desc: "Failed sessions by station, quarter and error type (ChargeX CX codes where reported).",
    sql: `SELECT s.station_name, s.network_operator, f.quarter, f.failure_type, f.sessions FROM failures_quarterly f ${NAMED} ORDER BY s.station_name, f.quarter, f.sessions DESC` },
  { name: "Payment methods", desc: "Successful sessions by payment method.",
    sql: `SELECT s.station_name, p.quarter, p.payment_method, p.sessions,
  p.sessions / SUM(p.sessions) OVER (PARTITION BY p.station_id, p.quarter) AS share FROM payments_quarterly p ${NAMED} ORDER BY s.station_name, p.quarter, p.sessions DESC` },
  { name: "Time of day profile", desc: "Successful sessions by local start hour and day of week (0 = Monday).",
    sql: `SELECT s.station_name, h.quarter, h.day_of_week, h.hour, h.sessions, h.energy_kwh FROM hourly_profile h ${NAMED} ORDER BY s.station_name, h.quarter, h.day_of_week, h.hour` },
  { name: "Session distributions", desc: "Histograms of energy, average power and duration per successful session.",
    sql: `SELECT s.station_name, d.metric, d.bin_lo, d.bin_hi, d.is_top_bin, d.sessions FROM session_distribution d ${NAMED} ORDER BY s.station_name, d.metric, d.bin_lo` },
  { name: "Award inventory", desc: "PennDOT's NEVI award sites (GIS export, Oct 2026), flagged where charging data exists.",
    sql: `SELECT a.has_session_data, s.station_name, a.organization_name, a.site_host, a.city, a.county, a.penndot_district, a.planning_partner,
  a.funding_round, a.project_type, a.status, a.highway, a.exit, a.nevi_dc_ports, a.total_dc_ports, a.nevi_l2_ports, a.total_l2_ports,
  a.award_amount AS award_usd, a.electric_distribution_company, a.latitude, a.longitude, a.notes
FROM awarded_stations a LEFT JOIN stations s USING (station_id) ORDER BY a.has_session_data DESC, a.funding_round, a.city` },
];

function numFmt(col) {
  if (/rate$|utilization|^share$/.test(col)) return "0.0%";
  if (/_pct$/.test(col)) return "0.00";
  if (/usd/.test(col)) return "$#,##0";
  if (/kwh|hours|_kw$|_min$|per_day|duration/.test(col)) return "#,##0.0";
  if (/lat|lon/.test(col)) return "0.000000";
  return "#,##0";
}
async function buildWorkbook(onProgress) {
  if (!window.ExcelJS) await loadScript("vendor/exceljs.min.js");
  const wb = new ExcelJS.Workbook();
  wb.creator = "Smart Mobility Lab, Penn State"; wb.created = new Date();
  const green = "FF006A4E";
  const readme = wb.addWorksheet("README");
  readme.columns = [{ width: 28 }, { width: 110 }];
  const lines = [
    ["Pennsylvania NEVI charging performance: analysis workbook"],
    ["Generated", `${today()} from the dashboard at ${location.origin}${location.pathname}`],
    ["Charging data", `${META.data_start} to ${META.data_end}: EV-ChART quarterly submissions (Modules 2, 3, 4) for ${META.n_stations_with_data} stations`],
    ["Award inventory", `PennDOT NEVI GIS export (${META.award_source || "n/a"}), ${META.n_awarded} sites`],
    ["Not included", "Individual charging-session records. Every sheet is an aggregate."],
    [],
    ["Definitions"],
    ["Charge success rate", "Share of plug-ins with no error code and at least 1 kWh delivered."],
    ["Uptime (NEVI)", "100 x (1 - (outage - excluded outage) / minutes in period), per port (23 CFR 680.116). Uses the operator's 12-month figure when reported, otherwise the period since opening."],
    ["Availability (raw)", "Same formula from outage events with no exclusions; a lower bound."],
    ["Port utilization", "Minutes a port is occupied by a successful session / minutes in the day."],
    ["All ports busy minutes", "Minutes when every port at the station was occupied, so an arriving driver would wait."],
    ["Est. EV miles", "Energy x 3 miles per kWh (assumption)."],
    [],
    ["Data quality notes"],
    ["Tesla (Aston)", "Reports no failed sessions; its charge success rate is not comparable to other networks."],
    ["EVgo uptime reports", "2025 reports use a one-month window with cumulative outage totals; the pipeline measures from each port's first report."],
    ["PennDOT workbook", "Counts failures inconsistently across sheets; see 'Quarterly by station' (diff column). Pittston 2024 Q3 appears to count all sessions as successful."],
    [],
    ["Sheets"],
    ...SHEETS.map((x) => [x.name, x.desc]),
  ];
  lines.forEach((l) => readme.addRow(l));
  readme.getRow(1).font = { bold: true, size: 14, color: { argb: green } };
  [7, 15, 20].forEach((r) => (readme.getRow(r).font = { bold: true, color: { argb: green } }));
  readme.getColumn(1).font = { bold: true };
  readme.getColumn(2).alignment = { wrapText: true, vertical: "top" };

  for (const [i, sh] of SHEETS.entries()) {
    onProgress?.(`Building "${sh.name}" (${i + 1} of ${SHEETS.length})…`);
    const { rows, columns } = await q(sh.sql);
    const ws = wb.addWorksheet(sh.name, { views: [{ state: "frozen", ySplit: 1 }] });
    ws.columns = columns.map((c) => ({ header: c, key: c, width: Math.min(40, Math.max(10, c.length + 2)) }));
    const dateCols = columns.filter((c) => rows.some((r) => typeof r[c] === "string" && /^\d{4}-\d{2}-\d{2}$/.test(r[c])) && /date|day|start|end/.test(c));
    rows.forEach((r) => {
      const o = { ...r };
      dateCols.forEach((c) => { if (o[c]) { const [y, m, d] = o[c].split("-").map(Number); o[c] = new Date(Date.UTC(y, m - 1, d)); } });
      ws.addRow(o);
    });
    columns.forEach((c, j) => {
      const col = ws.getColumn(j + 1);
      if (dateCols.includes(c)) col.numFmt = "yyyy-mm-dd";
      else if (rows.some((r) => typeof r[c] === "number")) col.numFmt = numFmt(c);
      const longest = Math.max(c.length, ...rows.slice(0, 200).map((r) => String(r[c] ?? "").length));
      col.width = Math.min(42, Math.max(9, longest + 2));
    });
    const h = ws.getRow(1);
    h.font = { bold: true, color: { argb: "FFFFFFFF" } };
    h.fill = { type: "pattern", pattern: "solid", fgColor: { argb: green } };
    h.alignment = { vertical: "middle", wrapText: true };
    h.height = 30;
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
  }
  onProgress?.("Writing file…");
  const buf = await wb.xlsx.writeBuffer();
  saveBlob(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `PA_NEVI_analysis_${new Date().toISOString().slice(0, 10)}.xlsx`);
}

// ---------- executive summary: every sentence is built from query results, no language model
async function summaryFacts() {
  const one = async (sql) => (await q(sql)).rows[0];
  const all = async (sql) => (await q(sql)).rows;
  const F = {};
  F.tot = await one(`SELECT SUM(sessions_success) s, SUM(sessions_total) a, SUM(energy_kwh) kwh FROM daily_station`);
  F.aw = await one(`SELECT COUNT(*) n, COUNT(*) FILTER (WHERE status = 'Operational') op, COUNT(*) FILTER (WHERE status = 'In Progress') ip,
    COUNT(*) FILTER (WHERE status = 'Planned') pl, SUM(award_amount) usd, COUNT(*) FILTER (WHERE has_session_data) d FROM awarded_stations`);
  F.quarters = await all(`SELECT quarter, SUM(sessions_success) s, SUM(energy_kwh) kwh, COUNT(*) st FROM quarterly_station GROUP BY 1 ORDER BY 1`);
  F.lastQ = F.quarters.at(-1).quarter;
  F.stations = await all(`SELECT s.station_name, s.network_operator, strftime(s.operational_date, '%Y-%m') AS opened, q.sessions_success, q.sessions_per_day,
      q.port_utilization, q.all_ports_busy_minutes, t.sr, u.worst
    FROM quarterly_station q ${NAMED}
    JOIN (SELECT station_id, SUM(sessions_success) / SUM(sessions_total) sr FROM daily_station GROUP BY 1) t USING (station_id)
    LEFT JOIN (SELECT station_id, MIN(uptime_nevi_pct) worst FROM port_uptime_reported GROUP BY 1) u USING (station_id)
    WHERE q.quarter = '${F.lastQ}' ORDER BY q.sessions_success DESC`);
  F.ports = await one(`SELECT COUNT(*) n, COUNT(*) FILTER (WHERE uptime_nevi_pct >= 97) ok, COUNT(*) FILTER (WHERE uptime_nevi_pct < 90) crit FROM port_uptime_reported`);
  F.badStations = await all(`SELECT s.station_name, COUNT(*) n, MIN(p.uptime_nevi_pct) worst FROM port_uptime_reported p ${NAMED} WHERE p.uptime_nevi_pct < 97 GROUP BY 1 ORDER BY worst`);
  F.longest = await one(`SELECT s.station_name, o.port_label, strftime(o.start_date, '%B %-d, %Y') started, o.duration_hours h, COUNT(*) OVER (PARTITION BY o.station_id, o.start_date, o.duration_min) same
    FROM outage_events o ${NAMED} ORDER BY o.duration_min DESC LIMIT 1`);
  F.failType = await all(`SELECT failure_type, SUM(sessions) n FROM failures_quarterly GROUP BY 1 ORDER BY n DESC LIMIT 2`);
  F.busy = await one(`SELECT s.station_name, strftime(d.month, '%B %Y') m, SUM(d.all_ports_busy_minutes) mins FROM daily_station d ${NAMED} GROUP BY ALL ORDER BY mins DESC LIMIT 1`);
  F.peak = await one(`SELECT day_of_week, hour, SUM(sessions) n FROM hourly_profile GROUP BY ALL ORDER BY n DESC LIMIT 1`);
  F.weekend = await one(`SELECT SUM(sessions) FILTER (WHERE day_of_week >= 5) / SUM(sessions) w FROM hourly_profile`);
  F.pay = await all(`SELECT payment_method, SUM(sessions) / (SELECT SUM(sessions) FROM payments_quarterly) AS sh FROM payments_quarterly GROUP BY 1 ORDER BY sh DESC LIMIT 2`);
  F.recon = await one(`SELECT COUNT(*) n, COUNT(*) FILTER (WHERE abs(q.sessions_success - r.sessions_success) <= 2) AS near FROM quarterly_station q JOIN quarterly_reported r USING (station_id, quarter)`);
  F.badPorts = await all(`SELECT s.station_name, p.port_label, p.total_outage_min / 60 AS oh, p.excluded_outage_min / 60 AS eh, p.uptime_nevi_pct AS u,
    CASE WHEN p.reported_uptime_pct IS NULL THEN 'Since opening' ELSE '12-month (operator)' END AS basis
    FROM port_uptime_reported p ${NAMED} WHERE p.uptime_nevi_pct < 97 ORDER BY p.uptime_nevi_pct`);
  F.rounds = await all(`SELECT funding_round, COUNT(*) AS n, COUNT(*) FILTER (WHERE status = 'Operational') AS op, COUNT(*) FILTER (WHERE status = 'In Progress') AS ip,
    COUNT(*) FILTER (WHERE status = 'Planned') AS pl, SUM(nevi_dc_ports) AS dc, SUM(award_amount) AS usd FROM awarded_stations GROUP BY 1 ORDER BY n DESC`);
  F.monthly = await all(`SELECT strftime(d.month, '%Y-%m') AS month, s.network_operator, SUM(d.sessions_success) AS sessions FROM daily_station d ${NAMED} GROUP BY ALL ORDER BY month`);
  return F;
}
const DOW_FULL = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const failName = (t) => (t === "no_error_but_<1kWh" ? "sessions that end with no error but deliver under 1 kWh"
  : t === "other" ? "an unspecified error code ('other')" : t === "Corrupted" ? "corrupted session records" : `error code ${t}`);
function summaryContent(F) {
  const pct = (v, d = 0) => fmt.pct(v, d), n = fmt.int;
  const [q1, q0] = [F.quarters.at(-1), F.quarters.at(-2)];
  const top2 = F.stations.slice(0, 2), top2share = (top2[0].sessions_success + top2[1].sessions_success) / F.stations.reduce((a, r) => a + r.sessions_success, 0);
  const lowSuccess = F.stations.filter((r) => r.sr < 0.8 && r.network_operator !== "Tesla").sort((a, b) => a.sr - b.sr);
  const hiUtil = [...F.stations].sort((a, b) => b.port_utilization - a.port_utilization)[0];
  const ql = fmt.q(F.lastQ);
  const findings = [
    ["Demand is concentrated.", `${top2[0].station_name} and ${top2[1].station_name} carried ${pct(top2share)} of successful sessions in ${ql}; most other stations average fewer than ${Math.ceil(F.stations[2].sessions_per_day)} sessions a day.`],
    ["Usage is growing.", `Successful sessions rose from ${n(q0.s)} in ${fmt.q(q0.quarter)} to ${n(q1.s)} in ${ql} (${q1.s >= q0.s ? "+" : ""}${pct(q1.s / q0.s - 1)}), with ${q1.st} stations reporting versus ${q0.st}.`],
    ["Reliability falls short at some sites.", `${F.ports.ok} of ${F.ports.n} ports meet the 97% uptime requirement; ${F.ports.crit} are below 90%. The weakest are at ${F.badStations.slice(0, 3).map((r) => `${r.station_name} (${fmt.pctv(r.worst)})`).join(", ")}. The longest outage began ${F.longest.started} at ${F.longest.station_name} and lasted ${n(F.longest.h)} hours.`],
    ["Some plug-ins don't deliver a charge.", lowSuccess.length ? `${lowSuccess.map((r) => `${r.station_name} (${pct(r.sr)})`).join(" and ")} ${lowSuccess.length > 1 ? "have" : "has"} charge success below 80%, against ${pct(F.tot.s / F.tot.a)} statewide. The most common failure types are ${F.failType.map((f) => failName(f.failure_type)).join(" and ")}.` : `Charge success is ${pct(F.tot.s / F.tot.a)} statewide.`],
    ["Capacity pressure is emerging.", `${hiUtil.station_name}'s ports were occupied ${pct(hiUtil.port_utilization, 1)} of the time in ${ql}. The most time with every port taken was ${n(F.busy.mins)} minutes at ${F.busy.station_name} in ${F.busy.m}.`],
    ["Drivers charge midday and on weekends.", `The busiest hour is ${DOW_FULL[F.peak.day_of_week]} at ${F.peak.hour > 12 ? F.peak.hour - 12 + " pm" : F.peak.hour === 12 ? "noon" : F.peak.hour + " am"}; ${pct(F.weekend.w)} of sessions start on Saturday or Sunday. The card reader at the charger (${pct(F.pay[0].sh)}) and phone apps (${pct(F.pay[1].sh)}) dominate payment.`],
  ];
  const actions = [
    F.badStations.length ? `Follow up with the operators of ${F.badStations.map((r) => r.station_name).join(", ")} on ports below 97% uptime, starting with ${F.badStations[0].station_name}.` : null,
    lowSuccess.length ? `Ask ${lowSuccess.map((r) => r.station_name).join(" and ")} for a root-cause review of failed sessions.` : null,
    `Track all-ports-busy minutes at ${hiUtil.station_name} and ${F.busy.station_name} as the trigger for adding ports.`,
    `Standardize EV-ChART checks: require failed-session reporting from every network (Tesla reports none), a consistent uptime reporting window, and automated quarterly processing. Only ${F.recon.near} of ${F.recon.n} station-quarters in the current workbook match the raw submissions within two sessions.`,
  ].filter(Boolean);
  return {
    title: "Pennsylvania NEVI Charging Performance",
    subtitle: `Executive summary · EV-ChART data ${fmt.month(META.data_start.slice(0, 7))} to ${fmt.month(META.data_end.slice(0, 7))}`,
    byline: `Prepared by the Smart Mobility Lab, Penn State · ${today()}`,
    figures: [
      [`${F.aw.n}`, `NEVI award sites (${F.aw.op} operational)`],
      [`${F.aw.d}`, "stations with charging data"],
      [n(F.tot.s), "successful sessions"],
      [`${n(F.tot.kwh / 1000)} MWh`, `delivered (≈ ${fmt.compact(F.tot.kwh * 3)} EV miles)`],
      [`${F.ports.ok} of ${F.ports.n}`, "ports meet 97% uptime"],
    ],
    findings, actions,
    table: { head: ["Station", "Network", "Opened", `Sessions/day, ${ql}`, "Charge success", "Weakest-port uptime", "Port utilization"],
      rows: F.stations.map((r) => [r.station_name, r.network_operator, fmt.month(r.opened), fmt.dec(r.sessions_per_day), pct(r.sr), fmt.pctv(r.worst), pct(r.port_utilization, 1)]) },
    extra: [
      { title: "Ports below the 97% uptime requirement", rightFrom: 2,
        head: ["Station", "Port", "Outage hours", "Excluded hours", "Uptime", "Basis"],
        rows: F.badPorts.map((r) => [r.station_name, r.port_label, fmt.dec(r.oh), fmt.dec(r.eh), fmt.pctv(r.u), r.basis]),
        note: "Uptime = 100 × (1 − (outage − excluded) / minutes in period). Ports under a year old are measured since opening." },
      { title: "NEVI program pipeline by funding round", rightFrom: 1,
        head: ["Funding round", "Sites", "Operational", "In progress", "Planned", "NEVI DC ports", "Awarded"],
        rows: [...F.rounds.map((r) => [r.funding_round, n(r.n), n(r.op), n(r.ip), n(r.pl), n(r.dc), r.usd ? "$" + fmt.dec(r.usd / 1e6, 1) + "M" : "–"]),
          ["Total", n(F.aw.n), n(F.aw.op), n(F.aw.ip), n(F.aw.pl), n(F.rounds.reduce((a, r) => a + (r.dc || 0), 0)), "$" + fmt.dec(F.aw.usd / 1e6, 1) + "M"]],
        note: `From PennDOT's NEVI award inventory (${META.award_source || "GIS export"}). Charging data is available for ${F.aw.d} of these sites.` },
    ],
    about: `Source: EV-ChART quarterly submissions (charging sessions, uptime, outages) for the ${F.aw.d} stations reporting through ${ql}, processed by an automated pipeline, and PennDOT's NEVI award inventory (${F.aw.n} sites). Charge success = plug-ins with no error and at least 1 kWh delivered. Uptime follows 23 CFR 680.116 with excluded outages removed. Tesla reports no failed sessions, so its success rate is not comparable. Individual session records are not included in this report.`,
    monthly: F.monthly,
  };
}
function monthlyChartOption(rows, light = false) {
  const months = [...new Set(rows.map((r) => r.month))];
  const ops = Object.keys(OPERATOR_SLOT).filter((o) => rows.some((r) => r.network_operator === o));
  const S = light ? ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"] : SERIES();
  const ink = light ? "#4c5157" : css("--ink-2"), hair = light ? "#e1e2dc" : css("--hair");
  return {
    animation: false, backgroundColor: light ? "#ffffff" : "transparent",
    textStyle: { fontFamily: "Overpass, Arial, sans-serif", color: ink },
    legend: { top: 0, left: 0, itemWidth: 12, itemHeight: 12, textStyle: { color: ink, fontSize: 12 } },
    grid: { left: 8, right: 8, top: 30, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: months, axisTick: { show: false }, axisLine: { lineStyle: { color: hair } }, axisLabel: { color: ink, fontSize: 11, formatter: (v) => fmt.month(v).replace(" ", "\n") } },
    yAxis: { type: "value", splitLine: { lineStyle: { color: hair } }, axisLabel: { color: ink, fontSize: 11 } },
    series: ops.map((o, i) => ({ type: "bar", name: o, stack: "s", barMaxWidth: 22,
      itemStyle: { color: S[OPERATOR_SLOT[o]], borderColor: light ? "#fff" : css("--surface"), borderWidth: 1, borderRadius: i === ops.length - 1 ? [3, 3, 0, 0] : 0 },
      data: months.map((m) => rows.find((r) => r.month === m && r.network_operator === o)?.sessions ?? 0) })),
  };
}
function summaryHTML(C) {
  return `<article class="summary-doc">
    <header><h1>${esc(C.title)}</h1><p class="sd-sub">${esc(C.subtitle)}</p><p class="sd-by">${esc(C.byline)}</p></header>
    <div class="sd-figs">${C.figures.map(([v, l]) => `<div><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join("")}</div>
    <h2>Key findings</h2>
    <ul class="sd-find">${C.findings.map(([h, t]) => `<li><b>${esc(h)}</b> ${esc(t)}</li>`).join("")}</ul>
    <h2>Successful sessions per month, by network</h2>
    <div class="sd-chart"></div>
    <h2>Stations with charging data</h2>
    <table class="sd-table"><thead><tr>${C.table.head.map((h, i) => `<th class="${i > 2 ? "n" : ""}">${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${C.table.rows.map((r) => `<tr>${r.map((c, i) => `<td class="${i > 2 ? "n" : ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>
    <h2>Recommended actions</h2>
    <ol class="sd-act">${C.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol>
    ${C.extra.map((t) => `<h2>${esc(t.title)}</h2>
      <table class="sd-table"><thead><tr>${t.head.map((h, i) => `<th class="${i >= t.rightFrom && i < t.head.length - (t.head.at(-1) === "Basis" ? 1 : 0) ? "n" : ""}">${esc(h)}</th>`).join("")}</tr></thead>
      <tbody>${t.rows.map((r, ri) => `<tr${ri === t.rows.length - 1 && r[0] === "Total" ? ' class="sd-total"' : ""}>${r.map((c, i) => `<td class="${i >= t.rightFrom && i < t.head.length - (t.head.at(-1) === "Basis" ? 1 : 0) ? "n" : ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>
      <p class="sd-note">${esc(t.note)}</p>`).join("")}
    <p class="sd-about">${esc(C.about)}</p>
  </article>`;
}
async function chartPNG(option, w = 1600, h = 560) {
  const div = document.createElement("div");
  div.style.cssText = `position:fixed;left:-9999px;top:0;width:${w / 2}px;height:${h / 2}px`;
  document.body.appendChild(div);
  const c = echarts.init(div, null, { renderer: "canvas", devicePixelRatio: 2 });
  c.setOption(option);
  const url = c.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: "#ffffff" });
  c.dispose(); div.remove();
  return Uint8Array.from(atob(url.split(",")[1]), (ch) => ch.charCodeAt(0));
}
async function buildDocx(C) {
  const D = await import("./vendor/docx.mjs");
  const GREEN = "006A4E", INK = "16191D", GREY = "4C5157";
  const P = (children, opts = {}) => new D.Paragraph({ children, spacing: { after: 80 }, ...opts });
  const T = (text, o = {}) => new D.TextRun({ text, font: "Arial", size: 19, color: INK, ...o });
  const H = (text) => new D.Paragraph({ children: [T(text, { bold: true, size: 22, color: GREEN })], spacing: { before: 180, after: 80 } });
  const png = await chartPNG(monthlyChartOption(C.monthly, true));
  const border = { style: D.BorderStyle.SINGLE, size: 4, color: "E1E2DC" };
  const cell = (text, { head = false, right = false, w, bold = false } = {}) => new D.TableCell({
    children: [new D.Paragraph({ alignment: right ? D.AlignmentType.RIGHT : D.AlignmentType.LEFT, children: [T(text, { size: 16, bold: head || bold, color: head ? "FFFFFF" : INK })] })],
    shading: head ? { type: D.ShadingType.SOLID, color: GREEN, fill: GREEN } : undefined,
    margins: { top: 40, bottom: 40, left: 80, right: 80 }, width: w ? { size: w, type: D.WidthType.PERCENTAGE } : undefined,
    borders: { top: border, bottom: border, left: border, right: border },
  });
  const figW = Math.floor(100 / C.figures.length);
  const doc = new D.Document({
    creator: "Smart Mobility Lab, Penn State", title: `${C.title}: executive summary`,
    styles: { default: { document: { run: { font: "Arial", size: 19 } } } },
    sections: [{
      properties: { page: { margin: { top: 720, bottom: 720, left: 860, right: 860 } } },
      footers: { default: new D.Footer({ children: [P([T("Demonstration analysis prepared by the Smart Mobility Lab, Penn State, from EV-ChART data shared by PennDOT. Not an official PennDOT product.", { size: 14, color: GREY })])] }) },
      children: [
        P([T(C.title, { bold: true, size: 34, color: GREEN })], { spacing: { after: 40 } }),
        P([T(C.subtitle, { size: 21, color: GREY })], { spacing: { after: 20 } }),
        P([T(C.byline, { size: 17, color: GREY })], { spacing: { after: 160 } }),
        new D.Table({ width: { size: 100, type: D.WidthType.PERCENTAGE }, rows: [new D.TableRow({ children: C.figures.map(([v, l]) => new D.TableCell({
          width: { size: figW, type: D.WidthType.PERCENTAGE }, margins: { top: 60, bottom: 60, left: 80, right: 80 },
          borders: { top: { style: D.BorderStyle.SINGLE, size: 12, color: GREEN }, bottom: border, left: { style: D.BorderStyle.NONE }, right: { style: D.BorderStyle.NONE } },
          children: [P([T(v, { bold: true, size: 30 })], { spacing: { after: 0 } }), P([T(l, { size: 15, color: GREY })], { spacing: { after: 0 } })] })) })] }),
        H("Key findings"),
        ...C.findings.map(([h, t]) => new D.Paragraph({ bullet: { level: 0 }, spacing: { after: 60 }, children: [T(h + " ", { bold: true }), T(t)] })),
        H("Successful sessions per month, by network"),
        new D.Paragraph({ children: [new D.ImageRun({ type: "png", data: png, transformation: { width: 640, height: 224 } })] }),
        H("Stations with charging data"),
        new D.Table({ width: { size: 100, type: D.WidthType.PERCENTAGE }, rows: [
          new D.TableRow({ tableHeader: true, children: C.table.head.map((h, i) => cell(h, { head: true, right: i > 2 })) }),
          ...C.table.rows.map((r) => new D.TableRow({ children: r.map((c, i) => cell(c, { right: i > 2 })) })),
        ] }),
        H("Recommended actions"),
        ...C.actions.map((a) => new D.Paragraph({ numbering: { reference: "acts", level: 0 }, spacing: { after: 60 }, children: [T(a)] })),
        ...C.extra.flatMap((t) => {
          const right = (i) => i >= t.rightFrom && !(t.head.at(-1) === "Basis" && i === t.head.length - 1);
          return [H(t.title),
            new D.Table({ width: { size: 100, type: D.WidthType.PERCENTAGE }, rows: [
              new D.TableRow({ tableHeader: true, children: t.head.map((h, i) => cell(h, { head: true, right: right(i) })) }),
              ...t.rows.map((r) => new D.TableRow({ children: r.map((c, i) => cell(c, { right: right(i), bold: r[0] === "Total" })) })),
            ] }),
            P([T(t.note, { size: 15, color: GREY })], { spacing: { before: 40 } })];
        }),
        P([T(C.about, { size: 15, color: GREY })], { spacing: { before: 160 } }),
      ],
    }],
    numbering: { config: [{ reference: "acts", levels: [{ level: 0, format: D.LevelFormat.DECIMAL, text: "%1.", alignment: D.AlignmentType.START, style: { paragraph: { indent: { left: 360, hanging: 260 } } } }] }] },
  });
  saveBlob(await D.Packer.toBlob(doc), `PA_NEVI_executive_summary_${new Date().toISOString().slice(0, 10)}.docx`);
}

VIEWS.downloads = async (view) => {
  view.insertAdjacentHTML("beforeend", `
    <p class="lede">Ready-to-use outputs, generated in your browser from the processed EV-ChART data each time you click. Individual charging-session records are not available here; every file contains aggregates only.</p>
    <div class="grid">
      <section class="card c5 dl-card">
        <h3>Analysis workbook <span class="fmt">Excel</span></h3>
        <p class="sub">${SHEETS.length + 1} sheets: a README with definitions and data-quality notes, then</p>
        <ul class="dl-list">${SHEETS.map((x) => `<li><b>${esc(x.name)}</b>: ${esc(x.desc)}</li>`).join("")}</ul>
        <button class="dl-btn" id="dl-xlsx">Download workbook</button>
        <p class="dl-status" id="dl-xlsx-st" role="status" aria-live="polite"></p>
      </section>
      <section class="card c7 dl-card">
        <h3>Executive summary <span class="fmt">Word · PDF</span></h3>
        <p class="sub">Two pages for program leadership. Every number and sentence is generated from the data by code, not by a language model, so it is reproducible and uses none of the AI quota.</p>
        <div class="dl-row"><button class="dl-btn" id="dl-docx">Download Word</button><button class="dl-btn ghost" id="dl-pdf">Print or save as PDF</button></div>
        <p class="dl-status" id="dl-docx-st" role="status" aria-live="polite"></p>
        <div class="summary-wrap" id="summary-preview"><p class="loading"><span class="spin"></span>Preparing the summary…</p></div>
      </section>
    </div>`);
  const C = summaryContent(await summaryFacts());
  const wrap = $("#summary-preview", view);
  wrap.innerHTML = summaryHTML(C);
  const sc = $(".sd-chart", wrap); sc.style.height = "220px";
  echart(sc, () => monthlyChartOption(C.monthly, true));
  const busy = (btn, st, fn) => async () => {
    btn.disabled = true;
    try { await fn((m) => (st.textContent = m)); st.textContent = "Downloaded."; }
    catch (e) { st.textContent = `Could not build the file: ${e.message}`; console.error(e); }
    finally { btn.disabled = false; }
  };
  $("#dl-xlsx", view).addEventListener("click", busy($("#dl-xlsx", view), $("#dl-xlsx-st", view), buildWorkbook));
  $("#dl-docx", view).addEventListener("click", busy($("#dl-docx", view), $("#dl-docx-st", view), async (p) => { p("Building the Word file…"); await buildDocx(C); }));
  $("#dl-pdf", view).addEventListener("click", () => { document.body.classList.add("print-summary"); window.print(); });
  window.addEventListener("afterprint", () => document.body.classList.remove("print-summary"));
};

VIEWS.notes = async (view) => {
  const sem = await (await fetch("semantic.json")).json();
  const rec = (await q(`SELECT s.station_name, q.quarter, q.sessions_success - r.sessions_success AS d
    FROM quarterly_station q JOIN quarterly_reported r USING (station_id, quarter) JOIN stations s USING (station_id)
    WHERE q.sessions_success <> r.sessions_success ORDER BY abs(d) DESC LIMIT 1`)).rows[0];
  view.insertAdjacentHTML("beforeend", `<div class="prose">
    <h3>Source</h3>
    <p>Quarterly EV-ChART submissions (Module 2 charging sessions, Module 3 uptime, Module 4 outages) from the operators of Pennsylvania's NEVI-funded stations, plus PennDOT's quarterly summary workbook. Data runs from ${META.data_start} to ${META.data_end}: ${fmt.int(META.n_sessions_raw)} sessions at ${META.n_stations_with_data} stations. Three later stations (Mifflinville, New Castle, Brookville) are on the roster with no data yet.</p>
    <p>The map and program views also use PennDOT's NEVI award inventory (${esc(META.award_source || "GIS export")}, ${META.n_awarded} sites), the spreadsheet behind PennDOT's NEVI GIS map. It lists every award site with its status, funding round, ports and award amount, but no usage. Charging data covers only the ${META.n_stations_with_data} stations above, through ${META.data_end}.</p>
    <h3>What this page holds</h3>
    <p>Only aggregates: daily, monthly, hourly and per-port summaries. Individual session records are not published. The aggregates are encrypted with AES-256-GCM; each user's password unlocks a copy of the key in the browser, so the files on the server can't be read without a password.</p>
    <h3>Cleaning</h3>
    <ul>
      <li>Timestamps arrive in a mix of UTC, EST and EDT labels; all are converted to Eastern local time.</li>
      <li>Field names differ between submissions (<code>station_id</code> vs <code>station_id_upload</code>) and are unified.</li>
      <li>Error codes are normalized across networks (<code>none</code>, <code>{none}</code>, <code>{CX011,other}</code> → <code>none</code> or the CX code).</li>
      <li>Ports are labeled P1 to P4 within each station, consistently across all three modules.</li>
      <li>Outage events are split across days and months so long outages count in every period they cover.</li>
    </ul>
    <h3>Definitions</h3>
    <ul>
      <li><b>Charge success</b> (per plug-in): the share of charging attempts with no error code and at least 1 kWh delivered. It answers "when a driver plugged in, did it work?"</li>
      <li><b>Uptime</b> (per port, over time): the share of minutes a port was online. It answers "was the charger available?" and is the measure NEVI regulates (97%). The two are independent: at Aston, every recorded charge succeeded, yet its weakest port was online only 94% of the time.</li>
      <li><b>Uptime (NEVI method)</b>: 100 × (1 − (outage − excluded outage) / minutes in period), per port, from the operator's cumulative Module 3 report. Below one year of history this uses the period since opening.</li>
      <li><b>Monthly availability</b>: the same formula from Module 4 outage events with no exclusions, so it can read lower than the NEVI figure.</li>
      <li><b>Port utilization</b>: minutes a port is occupied by a successful session ÷ minutes in the day.</li>
    </ul>
    <h3>Reconciliation with PennDOT's summary</h3>
    <p>Computed successful sessions match the PennDOT workbook exactly for most station-quarters and within a few sessions for the rest. The workbook does not apply one rule throughout: some sheets count sessions with an error code as successful when energy was delivered. The largest gap is ${rec ? `${esc(rec.station_name)} in ${fmt.q(rec.quarter)} (${rec.d > 0 ? "+" : ""}${rec.d})` : "none"}, where the workbook appears to count every session as successful. Energy totals agree within 3%.</p>
    <h3>Known limits</h3>
    <ul>
      <li>Tesla (Aston) reports no failed sessions, so its success rate can't be compared directly.</li>
      <li>Station coordinates are approximate, placed from the street address.</li>
      <li>Session power reflects the vehicle as well as the charger; a median below 150 kW is not by itself a compliance issue.</li>
    </ul>
    <h3>Tables available to "Ask the data"</h3>
    ${Object.entries(sem.tables).map(([t, s]) => `<details class="dict"><summary>${t}</summary><p>${esc(s.grain)}</p>${tableHTML(["column", "type", "meaning"], s.columns.map((c) => ({ column: c.name, type: c.type, meaning: c.desc })))}</details>`).join("")}
  </div>`);
};

// ------------------------------------------------------------------ router
async function route() {
  const [name, arg] = (location.hash.slice(1) || "overview").split("/");
  if (name === "ask") { history.replaceState(null, "", "#overview"); setTimeout(() => Ask.open(arg && decodeURIComponent(arg)), 0); }
  const key = VIEWS[name] ? name : "overview";
  document.querySelectorAll(".tabs a").forEach((a) =>
    a.getAttribute("href") === `#${key}` ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  charts.forEach((e) => { if (!e.persist) { ro.unobserve(e.el); e.c.dispose(); charts.delete(e); } });
  const view = $("#view");
  view.innerHTML = "";
  window.scrollTo(0, 0);
  await VIEWS[key](view, arg && decodeURIComponent(arg));
}

async function start(dekRaw) {
  $("#login").hidden = true;
  const v = $("#view");
  v.hidden = false;
  v.innerHTML = `<p class="loading"><span class="spin"></span>Loading the data engine…</p>`;
  await initDB(await openBundle(dekRaw));
  STATIONS = (await q(`SELECT station_id, station_name, network_operator, awardee, address, city, interstate, has_session_data,
    strftime(operational_date, '%Y-%m-%d') AS operational_date, strftime(om_end_date, '%Y-%m-%d') AS om_end_date FROM stations ORDER BY station_order`)).rows;
  $("#tabs").hidden = false;
  Ask.init();
  $("#logout").hidden = false;
  $("#sign-sub").textContent = `Station performance from EV-ChART reports, ${fmt.month(META.data_start.slice(0, 7))} to ${fmt.month(META.data_end.slice(0, 7))}`;
  window.addEventListener("hashchange", route);
  await route();
}

$("#logout").addEventListener("click", () => { store.clear(); location.hash = ""; location.reload(); });
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#login-msg"), btn = $("#login-btn");
  msg.className = "login-msg"; msg.textContent = "Checking…"; btn.disabled = true;
  try {
    const { user, dek, token } = await unlock($("#u").value, $("#p").value);
    store.set("user", user); store.set("token", token); store.set("dek", b64e(dek));
    msg.textContent = "";
    await start(dek);
  } catch (x) {
    msg.className = "login-msg err"; msg.textContent = x.message; btn.disabled = false;
    $("#login").hidden = false; $("#view").hidden = true;
    console.error(x);
  }
});

window.addEventListener("load", async () => {
  const saved = store.get("dek");
  if (saved) {
    try { await start(b64d(saved)); }
    catch (x) { console.error(x); store.clear(); $("#login").hidden = false; $("#view").hidden = true; }
  } else $("#u").focus();
});
