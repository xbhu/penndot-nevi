"""
Build aggregated tables from raw EV-ChART quarterly submissions.

Input  : raw/Quarterly Reports_*/<operator>/<quarter>/Module {2,3,4}*/<uuid>_data.csv
         raw/EV-ChART PennDOT Quarterly Data Summary_*.xlsx
Output : build/tables/*.parquet   (aggregated only - no session-level rows)
         build/schema.json        (table + column docs, used by the dashboard and the LLM prompt)

Raw files and build/ are git-ignored. Only the encrypted bundle (site/data/) is committed.

Usage: python3 pipeline/build.py [raw_dir]
"""
import glob, json, os, re, sys
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.ipc  # noqa: F401
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "raw"
OUT = ROOT / "build"
TAB = OUT / "tables"
TAB.mkdir(parents=True, exist_ok=True)
LOCAL_TZ = "America/New_York"

# --------------------------------------------------------------------------------------
# Station metadata. Coordinates are approximate (geocoded by hand from the street address
# at town level) - good for a statewide map, not for navigation.
# --------------------------------------------------------------------------------------
STATION_META = {
    "62241":                 dict(name="Pittston",      lat=41.3227, lon=-75.7439, interstate="I-81 / I-476"),
    "PA-EMLENTON-00001":     dict(name="Emlenton",      lat=41.1794, lon=-79.7100, interstate="I-80"),
    "35027":                 dict(name="Aston",         lat=39.8634, lon=-75.4170, interstate="I-95"),
    "PA-JONESTOWN-00001":    dict(name="Jonestown",     lat=40.4432, lon=-76.5119, interstate="I-81"),
    "PA-SLIPPERYROCK-00001": dict(name="Slippery Rock", lat=41.0626, lon=-80.0890, interstate="I-79"),
    "221":                   dict(name="Chambersburg",  lat=39.9478, lon=-77.6236, interstate="I-81"),
    "222":                   dict(name="Carlisle",      lat=40.1741, lon=-77.2409, interstate="I-81"),
    "76801":                 dict(name="New Milford",   lat=41.8740, lon=-75.7322, interstate="I-81"),
    "77602":                 dict(name="Mill Hall",     lat=41.0890, lon=-77.4697, interstate="I-80"),
    "231":                   dict(name="Kylertown",     lat=41.0006, lon=-78.1680, interstate="I-80"),
    "PA-MIFFLINVILLE-00001": dict(name="Mifflinville",  lat=41.0321, lon=-76.3083, interstate="I-80"),
    "26704":                 dict(name="New Castle",    lat=41.0012, lon=-80.3820, interstate="I-376"),
    "PA-BROOKVILLE-00001":   dict(name="Brookville",    lat=41.1620, lon=-79.0830, interstate="I-80"),
}
OPERATOR_NORM = {"evgo": "EVgo", "chargepoint": "ChargePoint", "tesla_supercharger": "Tesla",
                 "tesla": "Tesla", "francis_energy": "Francis Energy", "francis energy": "Francis Energy"}

TZ_OFFSETS = {"EST": "-05:00", "EDT": "-04:00", "UTC": "+00:00"}


def parse_ts(x):
    """'03/24/25 1:01 AM UTC' -> tz-aware UTC Timestamp. Raw files mix UTC/EST/EDT labels."""
    if not isinstance(x, str) or not x.strip() or x.strip().upper() == "NULL":
        return pd.NaT
    m = re.match(r"^(.*\S)\s+(EST|EDT|UTC)$", x.strip())
    if not m:
        return pd.NaT
    return pd.to_datetime(m.group(1) + TZ_OFFSETS[m.group(2)], format="%m/%d/%y %I:%M %p%z", utc=True)


def norm_error(e):
    """Unify error encodings across networks: 'none' / '{none}' -> 'none'; '{CX011,other}' -> 'CX011'."""
    if not isinstance(e, str) or not e.strip():
        return "none"
    parts = [p.strip() for p in e.strip("{}").split(",") if p.strip()]
    parts = [p for p in parts if p.lower() != "none"]
    if not parts:
        return "none"
    cx = [p for p in parts if p.upper().startswith("CX")]
    if cx:
        return cx[0].upper()
    return "Corrupted" if any(p.lower() == "corrupted" for p in parts) else "other"


def norm_payment(p):
    p = (p or "").strip().lower()
    return {"terminal_payment": "credit_card_terminal", "": "none"}.get(p, p)


def load_module(mod):
    frames = []
    for f in glob.glob(str(RAW / "Quarterly Reports_*" / "*" / "*" / f"Module {mod}*" / "*.csv")):
        d = pd.read_csv(f, dtype=str, keep_default_na=False)
        d.columns = [c.replace("_upload", "") for c in d.columns]
        frames.append(d)
    return pd.concat(frames, ignore_index=True)


# ======================================================================================
# 1. Sessions (kept in memory only; never written out)
# ======================================================================================
s = load_module(2).drop_duplicates("session_id").copy()
s["station_id"] = s.station_id.astype(str).str.strip()
s["t0"] = s.session_start.map(parse_ts)
s["t1"] = s.session_end.map(parse_ts)
s = s[s.t0.notna()].copy()
for c in ["energy_kwh", "power_kw"]:
    s[c] = pd.to_numeric(s[c], errors="coerce")
s["error_code"] = s.session_error.map(norm_error)
s["payment_method"] = s.payment_method.map(norm_payment)
s["duration_min"] = (s.t1 - s.t0).dt.total_seconds() / 60
# Successful = no error reported AND >= 1 kWh delivered. Reconciles with PennDOT's quarterly
# summary within +/-2 sessions per station-quarter (see README).
s["success"] = (s.error_code == "none") & (s.energy_kwh >= 1)
s["local"] = s.t0.dt.tz_convert(LOCAL_TZ)
s["date"] = s.local.dt.date
s["quarter"] = s.local.dt.year.astype(str) + "Q" + s.local.dt.quarter.astype(str)

# Port labels P1..Pn per station, stable across all modules
ports_all = pd.concat([
    s[["station_id", "port_id"]],
    load_module(3)[["station_id", "port_id"]],
    load_module(4)[["station_id", "port_id"]],
]).astype(str).drop_duplicates()
ports_all = ports_all[ports_all.port_id.str.strip() != ""]
ports_all = ports_all.sort_values(["station_id", "port_id"])
ports_all["port_label"] = "P" + (ports_all.groupby("station_id").cumcount() + 1).astype(str)
PORTMAP = {(r.station_id, r.port_id): r.port_label for r in ports_all.itertuples()}
s["port_label"] = [PORTMAP.get((a, b)) for a, b in zip(s.station_id, s.port_id)]

# ======================================================================================
# 2. stations
# ======================================================================================
xl = RAW / next(p for p in os.listdir(RAW) if p.endswith(".xlsx"))
tot = pd.read_excel(xl, sheet_name="Totals by Station")
q2 = pd.read_excel(xl, sheet_name="2nd Quarter 2025")  # has the full 13-station roster
roster = pd.concat([tot, q2]).drop_duplicates("Station ID")
st = pd.DataFrame({
    "station_id": roster["Station ID"].astype(str),
    "awardee": roster["NEVI Awardee"],
    "network_operator": roster["Network Operator"].map(lambda x: OPERATOR_NORM.get(str(x).lower(), x)),
    "address": roster["Address"],
    "city": roster["City"],
    "operational_date": pd.to_datetime(roster["Operational Date"]).dt.date,
    "om_end_date": pd.to_datetime(roster["End of O&M"]).dt.date,
})
st["station_name"] = st.station_id.map(lambda i: STATION_META[i]["name"])
st["lat"] = st.station_id.map(lambda i: STATION_META[i]["lat"])
st["lon"] = st.station_id.map(lambda i: STATION_META[i]["lon"])
st["interstate"] = st.station_id.map(lambda i: STATION_META[i]["interstate"])
st["n_ports"] = st.station_id.map(ports_all.groupby("station_id").size()).fillna(4).astype(int)
cov = s.groupby("station_id").agg(first_session_date=("date", "min"), last_session_date=("date", "max"))
st = st.merge(cov, left_on="station_id", right_index=True, how="left")
st["has_session_data"] = st.first_session_date.notna()
# --------------------------------------------------------------------------------------
# Awarded-station inventory (PennDOT NEVI GIS export). Link each roster station to its award
# record: same city, matching operator/host keyword, nearest by distance.
# --------------------------------------------------------------------------------------
AWARD_KEY = {"62241": "pilot", "PA-EMLENTON-00001": "6406", "35027": "tesla", "PA-JONESTOWN-00001": "love",
             "PA-SLIPPERYROCK-00001": "love", "221": "francis", "222": "francis", "231": "francis",
             "76801": "pilot", "77602": "pilot", "PA-MIFFLINVILLE-00001": "love", "26704": "tesla",
             "PA-BROOKVILLE-00001": "love"}
aw_files = sorted(glob.glob(str(RAW / "awards" / "*.xlsx")))
aw = pd.read_excel(aw_files[-1]) if aw_files else pd.DataFrame()
if len(aw):
    aw = aw.rename(columns=str.lower)
    for c in ["organization_name", "site_host", "county", "city", "funding_round", "project_type", "highway", "exit",
              "electric_distribution_company", "status", "notes", "planning_partner"]:
        aw[c] = aw[c].astype("string").str.strip().replace({"": pd.NA})
    aw["award_id"] = range(1, len(aw) + 1)
    aw["station_id"] = pd.NA
    for sid, key in AWARD_KEY.items():
        r = st[st.station_id == sid].iloc[0]
        cand = aw[(aw.city.str.lower() == r.city.lower()) &
                  (aw.organization_name.str.lower().str.contains(key) | aw.site_host.str.lower().str.contains(key))]
        if cand.empty:
            continue
        d = np.hypot((cand.latitude - r.lat) * 111, (cand.longitude - r.lon) * 85)
        aw.loc[d.idxmin(), "station_id"] = sid
    linked = aw.dropna(subset=["station_id"]).set_index("station_id")
    # precise coordinates + award attributes for roster stations
    st["lat"] = st.station_id.map(linked.latitude).fillna(st.lat)
    st["lon"] = st.station_id.map(linked.longitude).fillna(st.lon)
    for c in ["funding_round", "highway", "exit", "county", "award_amount", "penndot_district"]:
        st[c] = st.station_id.map(linked[c])
    assert st.funding_round.notna().all(), "unmatched roster station in award file"
    aw["has_session_data"] = aw.station_id.isin(set(s.station_id))
    awarded = aw[["award_id", "station_id", "has_session_data", "organization_name", "site_host", "city", "county",
                  "latitude", "longitude", "funding_round", "project_type", "status", "highway", "exit",
                  "nevi_dc_ports", "total_dc_ports", "nevi_l2_ports", "total_l2_ports", "award_amount",
                  "electric_distribution_company", "penndot_district", "planning_partner", "notes"]].copy()
    awarded["station_id"] = awarded.station_id.astype("string")
    for c in ["nevi_dc_ports", "total_dc_ports", "nevi_l2_ports", "total_l2_ports", "penndot_district"]:
        awarded[c] = pd.to_numeric(awarded[c], errors="coerce").astype("Int64")
    AWARD_SOURCE = os.path.basename(aw_files[-1])
else:
    awarded, AWARD_SOURCE = None, None

st = st.sort_values("operational_date").reset_index(drop=True)
st.insert(0, "station_order", range(1, len(st) + 1))
NAME = dict(zip(st.station_id, st.station_name))
NPORTS = dict(zip(st.station_id, st.n_ports))

# ======================================================================================
# 3. Occupancy (minutes with k ports busy) - per station per local day
# ======================================================================================
def occupancy_daily(g, n_ports):
    """Sweep-line over successful sessions. Returns per-day busy port-minutes, minutes all
    ports busy, and peak concurrency. Sessions are split across midnights."""
    g = g[g.t1.notna() & (g.t1 > g.t0)]
    if g.empty:
        return pd.DataFrame(columns=["date", "busy_port_minutes", "all_ports_busy_minutes", "peak_concurrent"])
    ev = pd.concat([pd.Series(1, index=g.t0.dt.tz_convert(LOCAL_TZ)),
                    pd.Series(-1, index=g.t1.dt.tz_convert(LOCAL_TZ))]).sort_index()
    # add midnight breakpoints
    days = pd.date_range(ev.index.min().normalize(), ev.index.max().normalize() + pd.Timedelta(days=1), freq="D", tz=LOCAL_TZ)
    ev = pd.concat([ev, pd.Series(0, index=days)]).sort_index()
    ev = ev.groupby(level=0).sum()
    level = ev.cumsum()
    t = level.index
    dt_min = (t[1:] - t[:-1]).total_seconds().to_numpy() / 60
    lv = level.values[:-1]
    d = pd.DataFrame({"date": t[:-1].date, "dt": dt_min, "lv": lv})
    out = d.groupby("date").apply(lambda x: pd.Series({
        "busy_port_minutes": float((x.dt * x.lv).sum()),
        "all_ports_busy_minutes": float(x.dt[x.lv >= n_ports].sum()),
        "peak_concurrent": int(x.lv.max()),
    }), include_groups=False).reset_index()
    return out


ok = s[s.success]
occ = pd.concat([occupancy_daily(g, NPORTS.get(k, 4)).assign(station_id=k) for k, g in ok.groupby("station_id")])

# ======================================================================================
# 4. Outages: split each event across local days, per port
# ======================================================================================
o = load_module(4)
o["station_id"] = o.station_id.astype(str).str.strip()
o["start"] = o.outage_id.map(parse_ts)
o["duration_min"] = pd.to_numeric(o.outage_duration, errors="coerce")
o = o[o.start.notna() & (o.duration_min > 0)].copy()
o = o.drop_duplicates(["station_id", "port_id", "start", "duration_min"])
o["port_label"] = [PORTMAP.get((a, b)) for a, b in zip(o.station_id, o.port_id)]
o["end"] = o.start + pd.to_timedelta(o.duration_min, unit="m")

pieces = []
for r in o.itertuples():
    a, b = r.start.tz_convert(LOCAL_TZ), r.end.tz_convert(LOCAL_TZ)
    cur = a
    while cur < b:
        nxt = min(b, (cur.normalize() + pd.Timedelta(days=1)))
        pieces.append((r.station_id, r.port_label, cur.date(), (nxt - cur).total_seconds() / 60))
        cur = nxt
op = pd.DataFrame(pieces, columns=["station_id", "port_label", "date", "outage_minutes"])

outage_events = pd.DataFrame({
    "station_id": o.station_id, "port_label": o.port_label,
    "start_date": o.start.dt.tz_convert(LOCAL_TZ).dt.date,
    "end_date": o.end.dt.tz_convert(LOCAL_TZ).dt.date,
    "duration_min": o.duration_min.round(1),
}).sort_values(["station_id", "start_date", "port_label"]).reset_index(drop=True)
outage_events["duration_hours"] = (outage_events.duration_min / 60).round(2)

# ======================================================================================
# 5. Tables
# ======================================================================================
# daily_station -------------------------------------------------------------------------
grp = s.groupby(["station_id", "date"])
daily = grp.agg(sessions_total=("session_id", "size"), sessions_success=("success", "sum")).reset_index()
okg = ok.groupby(["station_id", "date"]).agg(
    energy_kwh=("energy_kwh", "sum"), avg_energy_kwh=("energy_kwh", "mean"),
    avg_power_kw=("power_kw", "mean"), avg_duration_min=("duration_min", "mean"),
    ports_used=("port_label", "nunique")).reset_index()
daily = daily.merge(okg, how="left", on=["station_id", "date"])
daily["sessions_failed"] = daily.sessions_total - daily.sessions_success
daily = daily.merge(occ, how="left", on=["station_id", "date"])
od = op.groupby(["station_id", "date"]).outage_minutes.sum().rename("outage_port_minutes").reset_index()
# fill every station-day from first activity to end of data so zero-session days exist
frames = []
end_all = max(s.date.max(), op.date.max())
for sid in st[st.has_session_data].station_id:
    start = min(st.set_index("station_id").loc[sid, "operational_date"], s[s.station_id == sid].date.min())
    frames.append(pd.DataFrame({"station_id": sid, "date": pd.date_range(start, s[s.station_id == sid].date.max()).date}))
cal = pd.concat(frames)
daily = cal.merge(daily, how="left", on=["station_id", "date"]).merge(od, how="left", on=["station_id", "date"])
for c in ["sessions_total", "sessions_success", "sessions_failed", "energy_kwh", "busy_port_minutes",
          "all_ports_busy_minutes", "peak_concurrent", "outage_port_minutes", "ports_used"]:
    daily[c] = daily[c].fillna(0)
for c in ["sessions_total", "sessions_success", "sessions_failed", "peak_concurrent", "ports_used"]:
    daily[c] = daily[c].astype(int)
daily["n_ports"] = daily.station_id.map(NPORTS)
daily["port_utilization"] = daily.busy_port_minutes / (daily.n_ports * 1440)
daily["date"] = pd.to_datetime(daily.date)
daily["month"] = daily.date.dt.to_period("M").dt.to_timestamp()
daily["quarter"] = daily.date.dt.year.astype(str) + "Q" + daily.date.dt.quarter.astype(str)
daily = daily.round(3)

# monthly_port ----------------------------------------------------------------------------
s["month"] = pd.to_datetime(s.local.dt.tz_localize(None).dt.to_period("M").dt.to_timestamp())
mp = s.groupby(["station_id", "port_label", "month"]).agg(
    sessions_total=("session_id", "size"), sessions_success=("success", "sum")).reset_index()
mpe = ok.assign(month=s.month).groupby(["station_id", "port_label", "month"]).agg(
    energy_kwh=("energy_kwh", "sum"), busy_minutes=("duration_min", "sum")).reset_index()
op["month"] = pd.to_datetime(pd.to_datetime(op.date).dt.to_period("M").dt.to_timestamp())
opm = op.groupby(["station_id", "port_label", "month"]).outage_minutes.sum().reset_index()
oev = o.assign(month=pd.to_datetime(o.start.dt.tz_convert(LOCAL_TZ).dt.tz_localize(None).dt.to_period("M").dt.to_timestamp())) \
       .groupby(["station_id", "port_label", "month"]).size().rename("outage_events").reset_index()
# full grid: every port x every month from station operational month through end of data
grid = []
end_month = pd.Timestamp(end_all).to_period("M").to_timestamp()
for r in st[st.has_session_data].itertuples():
    m0 = pd.Timestamp(r.operational_date).to_period("M").to_timestamp()
    for pl in ports_all[ports_all.station_id == r.station_id].port_label:
        for m in pd.date_range(m0, end_month, freq="MS"):
            grid.append((r.station_id, pl, m))
mport = pd.DataFrame(grid, columns=["station_id", "port_label", "month"])
for t in (mp, mpe, opm, oev):
    mport = mport.merge(t, how="left", on=["station_id", "port_label", "month"])
mport = mport.fillna({"sessions_total": 0, "sessions_success": 0, "energy_kwh": 0, "busy_minutes": 0,
                      "outage_minutes": 0, "outage_events": 0})
for c in ["sessions_total", "sessions_success", "outage_events"]:
    mport[c] = mport[c].astype(int)
# minutes the port was in service during the month (partial first month)
opdate = dict(zip(st.station_id, pd.to_datetime(st.operational_date)))
def minutes_in_service(r):
    m0, m1 = r.month, r.month + pd.offsets.MonthBegin(1)
    a = max(m0, opdate[r.station_id])
    return max((m1 - a).total_seconds() / 60, 0)
mport["minutes_in_service"] = mport.apply(minutes_in_service, axis=1)
mport["uptime_pct"] = (100 * (1 - mport.outage_minutes / mport.minutes_in_service)).clip(lower=0).round(2)
mport.loc[mport.minutes_in_service == 0, "uptime_pct"] = np.nan
mport = mport.round(2)

# hourly_profile --------------------------------------------------------------------------
hp = ok.assign(hour=ok.local.dt.hour, day_of_week=ok.local.dt.dayofweek) \
       .groupby(["station_id", "quarter", "day_of_week", "hour"]) \
       .agg(sessions=("session_id", "size"), energy_kwh=("energy_kwh", "sum")).reset_index().round(2)

# errors / payments -----------------------------------------------------------------------
fail = s[~s.success].copy()
fail["failure_type"] = np.where(fail.error_code != "none", fail.error_code, "no_error_but_<1kWh")
errs = fail.groupby(["station_id", "quarter", "failure_type"]).size().rename("sessions").reset_index()
pay = s[s.success].groupby(["station_id", "quarter", "payment_method"]).size().rename("sessions").reset_index()

# distributions ---------------------------------------------------------------------------
BINS = {"energy_kwh": np.arange(0, 110, 5), "power_kw": np.arange(0, 375, 25), "duration_min": np.arange(0, 130, 10)}
dist = []
for metric, edges in BINS.items():
    for sid, g in ok.groupby("station_id"):
        v = g[metric].dropna().clip(upper=edges[-1] - 1e-6)
        cnt, _ = np.histogram(v, bins=edges)
        for lo, hi, n in zip(edges[:-1], edges[1:], cnt):
            dist.append((sid, metric, float(lo), float(hi), int(n)))
dist = pd.DataFrame(dist, columns=["station_id", "metric", "bin_lo", "bin_hi", "sessions"])
dist["is_top_bin"] = dist.bin_hi == dist.groupby("metric").bin_hi.transform("max")

# quarterly_station (computed) ------------------------------------------------------------
qs = s.groupby(["station_id", "quarter"]).agg(
    sessions_total=("session_id", "size"), sessions_success=("success", "sum")).reset_index()
qe = ok.groupby(["station_id", "quarter"]).agg(
    energy_kwh=("energy_kwh", "sum"), avg_energy_kwh=("energy_kwh", "mean"),
    median_power_kw=("power_kw", "median"), avg_duration_min=("duration_min", "mean")).reset_index()
qs = qs.merge(qe, how="left", on=["station_id", "quarter"])
qd = daily.groupby(["station_id", "quarter"]).agg(
    days_in_service=("date", "nunique"), port_utilization=("port_utilization", "mean"),
    all_ports_busy_minutes=("all_ports_busy_minutes", "sum"), outage_port_minutes=("outage_port_minutes", "sum")).reset_index()
qs = qs.merge(qd, how="left", on=["station_id", "quarter"])
qs["sessions_failed"] = qs.sessions_total - qs.sessions_success
qs["success_rate"] = qs.sessions_success / qs.sessions_total
qs["sessions_per_day"] = qs.sessions_success / qs.days_in_service
qs["uptime_pct_raw"] = 100 * (1 - qs.outage_port_minutes / (qs.days_in_service * 1440 * qs.station_id.map(NPORTS)))
qs = qs.round(4)

# quarterly_reported (PennDOT summary workbook, as reported) ------------------------------
QSHEETS = {"4th Quarter 2023": "2023Q4", "1st Quarter 2024": "2024Q1", "2nd Quarter 2024": "2024Q2",
           "3rd Quarter 2024": "2024Q3", "4th Quarter 2024": "2024Q4", "1st Quarter 2025": "2025Q1"}
rep = []
for sh, q in QSHEETS.items():
    d = pd.read_excel(xl, sheet_name=sh)
    d = d[d["Station ID"].notna()]
    rep.append(pd.DataFrame({
        "station_id": d["Station ID"].astype(str), "quarter": q,
        "operating_days": d["Number of Operating Days in Quarter"],
        "rolling_12mo_uptime_pct": pd.to_numeric(d["12 Month Rolling Uptime"], errors="coerce") * 100,
        "sessions_success": d["Successful Charging Sessions"], "sessions_failed": d["Failed Charging Sessions"],
        "success_rate": d["Percent Success Rate"], "energy_kwh": d["Total Electricity Dispensed"],
    }))
rep = pd.concat(rep).round(4)

# port_uptime_reported (Module 3, latest cumulative report per port) ----------------------
u = load_module(3)
u["station_id"] = u.station_id.astype(str).str.strip()
u["start"] = u.uptime_reporting_start.map(parse_ts)
u["end"] = u.uptime_reporting_end.map(parse_ts)
u = u[u.end.notna()]
for c in ["total_outage", "total_outage_excl"]:
    u[c] = pd.to_numeric(u[c], errors="coerce").fillna(0)
u["port_label"] = [PORTMAP.get((a, b)) for a, b in zip(u.station_id, u.port_id)]
# total_outage / total_outage_excl are cumulative since the port's first report for every operator,
# but some reports (EVgo 2025) carry a one-month reporting window. Measure from the earliest start.
first_start = u.groupby(["station_id", "port_label"]).start.min().rename("first_start")
u = u.sort_values("end").groupby(["station_id", "port_label"]).tail(1).join(first_start, on=["station_id", "port_label"])
span = (u.end - u.first_start).dt.total_seconds() / 60
since = (100 * (1 - (u.total_outage - u.total_outage_excl) / span)).round(2)
reported = pd.to_numeric(u.uptime, errors="coerce")
pur = pd.DataFrame({
    "station_id": u.station_id, "port_label": u.port_label,
    "reporting_start": u.first_start.dt.tz_convert(LOCAL_TZ).dt.date, "reporting_end": u.end.dt.tz_convert(LOCAL_TZ).dt.date,
    "reported_uptime_pct": reported,
    "total_outage_min": u.total_outage, "excluded_outage_min": u.total_outage_excl,
    "uptime_since_start_pct": since,
    "uptime_nevi_pct": reported.fillna(since),
}).sort_values(["station_id", "port_label"])

# ======================================================================================
# 6. Write parquet + reconciliation report
# ======================================================================================
for c in ["operational_date", "om_end_date", "first_session_date", "last_session_date"]:
    st[c] = pd.to_datetime(st[c])
for df, cols in [(outage_events, ["start_date", "end_date"]), (pur, ["reporting_start", "reporting_end"])]:
    for c in cols:
        df[c] = pd.to_datetime(df[c])

TABLES = {
    "stations": st, "daily_station": daily, "monthly_port": mport, "hourly_profile": hp,
    "failures_quarterly": errs, "payments_quarterly": pay, "session_distribution": dist,
    "quarterly_station": qs, "quarterly_reported": rep, "outage_events": outage_events,
    "port_uptime_reported": pur,
    **({"awarded_stations": awarded} if awarded is not None else {}),
}
con = duckdb.connect()
for name, df in TABLES.items():
    con.register("t", df)
    con.execute(f"COPY (SELECT * FROM t) TO '{TAB / (name + '.parquet')}' (FORMAT parquet, COMPRESSION zstd)")
    # Arrow IPC stream for the browser (DuckDB-WASM reads it natively; Parquet would need a remote extension)
    tbl = con.sql("SELECT * FROM t").to_arrow_table()
    with pa.OSFile(str(TAB / (name + ".arrow")), "wb") as sink, pa.ipc.new_stream(sink, tbl.schema) as w:
        w.write_table(tbl)
    con.unregister("t")
    print(f"{name:24s} {len(df):6d} rows  {os.path.getsize(TAB / (name + '.arrow')):7d} B")

# reconciliation vs PennDOT summary
cmp = qs.merge(rep, on=["station_id", "quarter"], suffixes=("_ours", "_penndot"))
cmp["d_success"] = cmp.sessions_success_ours - cmp.sessions_success_penndot
cmp["d_failed"] = cmp.sessions_failed_ours - cmp.sessions_failed_penndot
cmp["d_kwh_pct"] = 100 * (cmp.energy_kwh_ours / cmp.energy_kwh_penndot - 1)
cmp[["station_id", "quarter", "sessions_success_ours", "sessions_success_penndot", "d_success", "d_failed", "d_kwh_pct"]] \
    .round(2).to_csv(OUT / "reconciliation.csv", index=False)
print("\nReconciliation vs PennDOT summary (max abs diff):",
      "success", cmp.d_success.abs().max(), "| failed", cmp.d_failed.abs().max(),
      "| kWh %", round(cmp.d_kwh_pct.abs().max(), 2))

meta = {
    "built_at": pd.Timestamp.now(tz=LOCAL_TZ).isoformat(timespec="minutes"),
    "data_start": str(s.date.min()), "data_end": str(s.date.max()),
    "n_sessions_raw": int(len(s)), "n_stations_with_data": int(st.has_session_data.sum()),
    "n_stations_roster": int(len(st)),
    "award_source": AWARD_SOURCE, "n_awarded": int(len(awarded)) if awarded is not None else 0,
}
json.dump(meta, open(OUT / "meta.json", "w"), indent=1)
print(meta)
