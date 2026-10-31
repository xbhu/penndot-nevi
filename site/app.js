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
function echart(el, optionFn) {
  const c = echarts.init(el, null, { renderer: "svg" });
  const entry = { c, optionFn, el };
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
async function card(parent, { title, sub, sql, render, cls = "c12", caveat, table = true }) {
  const el = document.createElement("section");
  el.className = `card ${cls}`;
  el.innerHTML = `<div class="card-head"><div><h3>${esc(title)}</h3>${sub ? `<p class="sub">${sub}</p>` : ""}</div>
    <div class="card-tools">${table ? `<button class="tool" data-t="table" aria-pressed="false">Table</button>` : ""}<button class="tool" data-t="sql" aria-pressed="false">SQL</button></div></div>
    <pre class="sql" hidden></pre><div class="body"></div><div class="tbl" hidden></div>${caveat ? `<p class="caveat">${caveat}</p>` : ""}`;
  parent.appendChild(el);
  $("pre.sql", el).textContent = sql.trim();
  const body = $(".body", el);
  try {
    const { rows, columns } = await q(sql);
    render(rows, body, columns);
    body.querySelectorAll(".chart").forEach((c) => ro.observe(c));
    el.querySelectorAll(".tool").forEach((b) => b.addEventListener("click", () => {
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
  const nData = STATIONS.filter((s) => s.has_session_data).length;
  view.insertAdjacentHTML("beforeend", `
    <p class="lede"><strong>${nData} of ${STATIONS.length}</strong> NEVI stations on PennDOT's roster were reporting between
    ${new Date(META.data_start + "T12:00").toLocaleDateString("en-US", { month: "long", year: "numeric" })} and
    ${new Date(META.data_end + "T12:00").toLocaleDateString("en-US", { month: "long", year: "numeric" })}. Demand is concentrated at two stations, and reliability varies widely by operator.</p>
    <div class="tiles">
      <div class="tile"><div class="label">Successful sessions</div><div class="value">${fmt.int(k.s)}</div><div class="note">All stations, all quarters</div></div>
      <div class="tile"><div class="label">Energy delivered</div><div class="value">${fmt.dec(k.mwh, 0)} MWh</div><div class="note">≈ ${fmt.compact(k.mwh * 1000 * 3)} EV miles at 3 mi/kWh</div></div>
      <div class="tile"><div class="label">Charge success</div><div class="value">${fmt.pct(k.sr)}</div><div class="note">Share of plug-ins that delivered energy</div></div>
      <div class="tile"><div class="label">Ports meeting 97% uptime</div><div class="value">${pc.ok} of ${pc.n}</div><div class="note">Share of time each port was online</div></div>
    </div>`);
  const g = grid(view);
  await card(g, {
    title: "Where the stations are", cls: "c7", table: false,
    sub: "Circle size is successful sessions per day in Q1 2025; color is the uptime of the station's weakest port.",
    sql: `SELECT s.station_id, s.station_name, s.network_operator, s.awardee, s.city, s.interstate, s.lat, s.lon, s.has_session_data,
  strftime(s.operational_date, '%Y-%m-%d') AS opened, q.sessions_per_day, q.success_rate, u.min_uptime
FROM stations s
LEFT JOIN (SELECT * FROM quarterly_station WHERE quarter = '2025Q1') q USING (station_id)
LEFT JOIN (SELECT station_id, MIN(uptime_nevi_pct) AS min_uptime FROM port_uptime_reported GROUP BY 1) u USING (station_id)
ORDER BY s.station_order`,
    render: (rows, body) => {
      body.innerHTML = `<div class="map" id="map" role="img" aria-label="Map of NEVI stations in Pennsylvania"></div>` +
        legendHTML([["Meets 97%", css("--good")], ["90–97%", css("--warn")], ["Below 90%", css("--crit")], ["Not reporting yet", css("--none")]]);
      const map = L.map($("#map", body), { scrollWheelZoom: false, attributionControl: true }).setView([40.95, -77.6], 7);
      L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 12, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      }).addTo(map);
      const pts = [];
      rows.forEach((r) => {
        const st = status(r.has_session_data ? r.min_uptime : null);
        const rad = r.sessions_per_day ? 5 + 3.2 * Math.sqrt(r.sessions_per_day) : 5;
        const m = L.circleMarker([r.lat, r.lon], { radius: rad, color: css("--surface"), weight: 2, fillColor: st.color, fillOpacity: 0.9 }).addTo(map);
        m.bindTooltip(r.station_name, { direction: "top", offset: [0, -rad] });
        m.bindPopup(`<b>${esc(r.station_name)}</b><br>${esc(r.network_operator)} · ${esc(r.awardee)}<br>${esc(r.interstate)} · opened ${r.opened}<br>` +
          (r.has_session_data ? `${fmt.dec(r.sessions_per_day)} sessions/day (Q1 2025)<br>${statusHTML(r.min_uptime, "Weakest port uptime " + fmt.pctv(r.min_uptime))}<br><a href="#stations/${encodeURIComponent(r.station_id)}">Station details</a>` : "Opened after the data cut-off"));
        pts.push([r.lat, r.lon]);
      });
      map.fitBounds(pts, { padding: [24, 24] });
      setTimeout(() => map.invalidateSize(), 50);
    },
  });
  await card(g, {
    title: "Stations", cls: "c5", table: false,
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
};

VIEWS.reliability = async (view) => {
  view.insertAdjacentHTML("beforeend", `<p class="lede">NEVI requires every port to be available at least <strong>97%</strong> of the time over a year, after excluding outages outside the operator's control (23 CFR 680.116). Monthly figures below count every reported outage, so they are a conservative lower bound.</p>`);
  const g = grid(view);
  await card(g, {
    title: "Uptime of the weakest port, by month",
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
    sql: `SELECT s.station_name, o.port_label, strftime(o.start_date, '%Y-%m-%d') AS started, round(o.duration_hours, 1) AS hours
FROM outage_events o JOIN stations s USING (station_id)
ORDER BY o.duration_min DESC LIMIT 12`,
    render: (rows, body) => {
      body.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Station</th><th>Port</th><th>Started</th><th class="n">Hours</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${esc(r.station_name)}</td><td>${r.port_label}</td><td>${r.started}</td><td class="n">${fmt.dec(r.hours)}</td></tr>`).join("")}</tbody></table></div>`;
    },
  });
  await card(g, {
    title: "Charge success rate", cls: "c6",
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
  const g = grid(view);
  await card(g, {
    title: "Daily successful sessions",
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
const EXAMPLES = [
  "Which ports are below the 97% uptime requirement?",
  "How have monthly sessions grown at Aston since it opened?",
  "What are the main reasons sessions fail at the Francis Energy stations?",
  "Which station has the most minutes with all ports busy, and in which month?",
  "Compare average energy per session across networks in Q1 2025",
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
VIEWS.ask = async (view) => {
  view.insertAdjacentHTML("beforeend", `
    <p class="lede">Ask a question in plain English. A language model writes a SQL query against the tables listed in Data notes; the query runs here in your browser, and the answer is written only from its result. The SQL is shown with every answer so it can be checked.</p>
    ${CFG.workerUrl ? "" : `<div class="notice">The question service is not connected yet, so questions can't be answered on this copy of the dashboard. Everything else works.</div>`}
    <form class="ask-box" id="askf">
      <label for="askq" style="font-weight:700">Your question</label>
      <textarea id="askq" placeholder="e.g. Which station had the most outage hours in Q1 2025?"></textarea>
      <div class="ask-row"><button class="primary" id="askbtn" ${CFG.workerUrl ? "" : "disabled"}>Ask</button><span id="askst" role="status" aria-live="polite" style="color:var(--ink-2)"></span></div>
      <div class="chips">${EXAMPLES.map((e) => `<button type="button" class="chip">${esc(e)}</button>`).join("")}</div>
    </form>
    <div id="answers"></div>`);
  const ta = $("#askq", view), btn = $("#askbtn", view), st = $("#askst", view), out = $("#answers", view);
  view.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => { ta.value = c.textContent; ta.focus(); }));
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) $("#askf", view).requestSubmit(); });
  $("#askf", view).addEventListener("submit", async (e) => {
    e.preventDefault();
    const question = ta.value.trim();
    if (!question || !CFG.workerUrl) return;
    btn.disabled = true;
    const box = document.createElement("section");
    box.className = "card answer";
    box.innerHTML = `<div class="q">${esc(question)}</div><p class="a"><span class="spin"></span>Writing a query…</p>`;
    out.prepend(box);
    try {
      let sql, rows, columns, err = null, model;
      for (let attempt = 0; attempt < 3; attempt++) {
        const r = await api("/sql", { question, previous_sql: sql, error: err });
        model = r.model;
        if (!r.sql) throw new Error(r.explanation || "The model could not write a query for this question.");
        sql = r.sql;
        try { ({ rows, columns } = await q(guardSQL(sql))); err = null; break; }
        catch (x) { err = x.message; $(".a", box).innerHTML = `<span class="spin"></span>Fixing the query (attempt ${attempt + 2})…`; }
      }
      if (err) throw new Error(`The query failed to run: ${err}`);
      $(".a", box).innerHTML = `<span class="spin"></span>Reading ${rows.length} rows…`;
      const a = await api("/answer", { question, sql, columns, rows: rows.slice(0, 60), row_count: rows.length });
      const spec = autoChart(a.chart, columns, rows);
      box.innerHTML = `<div class="q">${esc(question)}</div><div class="who">Answered by ${esc(a.model || model || "the model")} from ${rows.length} row${rows.length === 1 ? "" : "s"}</div>
        <p class="a">${esc(a.answer)}</p>${spec ? `<div class="chart" style="margin-top:12px"></div>` : ""}
        <div class="card-tools" style="margin:12px 0 0 0;justify-content:flex-start"><button class="tool" data-t="table" aria-pressed="false">Table</button><button class="tool" data-t="sql" aria-pressed="false">SQL</button></div>
        <pre class="sql" hidden></pre><div class="tbl" hidden></div>`;
      $("pre.sql", box).textContent = sql;
      box.querySelectorAll(".tool").forEach((b) => b.addEventListener("click", () => {
        const on = b.getAttribute("aria-pressed") !== "true"; b.setAttribute("aria-pressed", on);
        if (b.dataset.t === "sql") $("pre.sql", box).hidden = !on; else { const t = $(".tbl", box); t.hidden = !on; if (on && !t.innerHTML) t.innerHTML = tableHTML(columns, rows); }
      }));
      if (spec) {
        const el = $(".chart", box); ro.observe(el);
        const S = SERIES();
        const horiz = spec.type === "bar" && rows.length > 6;
        if (horiz) el.style.height = Math.min(900, 60 + rows.length * 26) + "px";
        const cat = { type: "category", data: rows.map((r) => r[spec.x]), inverse: horiz, splitLine: { show: false } };
        echart(el, () => ({
          tooltip: { trigger: "axis", axisPointer: { type: horiz ? "shadow" : "line" } },
          legend: spec.ys.length > 1 ? { top: 0, textStyle: { color: css("--ink-2") } } : undefined,
          grid: { top: spec.ys.length > 1 ? 32 : 16 },
          xAxis: horiz ? { type: "value" } : cat,
          yAxis: horiz ? cat : { type: "value" },
          series: spec.ys.map((y, i) => (spec.type === "line"
            ? { type: "line", name: y, data: rows.map((r) => r[y]), showSymbol: rows.length < 30, symbolSize: 8, lineStyle: { width: 2, color: S[i] }, itemStyle: { color: S[i] } }
            : { ...BAR(S[i]), name: y, data: rows.map((r) => r[y]), barMaxWidth: horiz ? 16 : 24, itemStyle: { color: S[i], borderRadius: horiz ? [0, 4, 4, 0] : [4, 4, 0, 0] } })),
        }));
      }
    } catch (x) {
      $(".a", box).innerHTML = `<span class="err-box">${esc(x.message)}</span>`;
    } finally {
      btn.disabled = false;
    }
  });
};

VIEWS.notes = async (view) => {
  const sem = await (await fetch("semantic.json")).json();
  const rec = (await q(`SELECT s.station_name, q.quarter, q.sessions_success - r.sessions_success AS d
    FROM quarterly_station q JOIN quarterly_reported r USING (station_id, quarter) JOIN stations s USING (station_id)
    WHERE q.sessions_success <> r.sessions_success ORDER BY abs(d) DESC LIMIT 1`)).rows[0];
  view.insertAdjacentHTML("beforeend", `<div class="prose">
    <h3>Source</h3>
    <p>Quarterly EV-ChART submissions (Module 2 charging sessions, Module 3 uptime, Module 4 outages) from the operators of Pennsylvania's NEVI-funded stations, plus PennDOT's quarterly summary workbook. Data runs from ${META.data_start} to ${META.data_end}: ${fmt.int(META.n_sessions_raw)} sessions at ${META.n_stations_with_data} stations. Three later stations (Mifflinville, New Castle, Brookville) are on the roster with no data yet.</p>
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
  const key = VIEWS[name] ? name : "overview";
  document.querySelectorAll(".tabs a").forEach((a) =>
    a.getAttribute("href") === `#${key}` ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  charts.forEach((e) => { ro.unobserve(e.el); e.c.dispose(); });
  charts.clear();
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
