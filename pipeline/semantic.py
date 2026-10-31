"""
Semantic layer: one source of truth for table/column meaning, business rules, and few-shot
examples. Emits:
  site/semantic.json        - read by the dashboard (data dictionary page)
  worker/src/semantic.js    - bundled into the Cloudflare Worker system prompt
Column lists are read from the built parquet files so the docs can never drift from the data.
"""
import json
from pathlib import Path
import duckdb

ROOT = Path(__file__).resolve().parents[1]
TAB = ROOT / "build" / "tables"

TABLES = {
    "stations": {
        "grain": "one row per NEVI-funded station on PennDOT's roster (13 stations; 10 have session data in this release)",
        "columns": {
            "station_order": "1 = first station to open",
            "station_id": "EV-ChART station identifier (text). Join key for every other table",
            "station_name": "Short town name used throughout the dashboard, e.g. 'Pittston'. Prefer this in answers",
            "awardee": "NEVI awardee / site host (e.g. Pilot Travel Centers, Love's, Tesla Inc.)",
            "network_operator": "Charging network: EVgo, ChargePoint, Tesla, Francis Energy",
            "address": "Street address", "city": "City",
            "operational_date": "Date the station opened", "om_end_date": "End of the 5-year O&M obligation",
            "lat": "Approximate latitude", "lon": "Approximate longitude",
            "interstate": "Nearest Alternative Fuel Corridor interstate",
            "n_ports": "Number of charging ports (all stations have 4)",
            "first_session_date": "First session in the data", "last_session_date": "Last session in the data",
            "has_session_data": "FALSE for stations that opened after the data cut-off (Mifflinville, New Castle, Brookville)",
        },
    },
    "daily_station": {
        "grain": "one row per station per local calendar day (America/New_York), from opening through its last reported day; zero-session days included",
        "columns": {
            "station_id": "", "date": "Local date",
            "sessions_total": "All sessions attempted", "sessions_success": "Successful sessions (see rule)",
            "sessions_failed": "sessions_total - sessions_success",
            "energy_kwh": "kWh delivered by successful sessions", "avg_energy_kwh": "Mean kWh per successful session",
            "avg_power_kw": "Mean of session average power (kW)", "avg_duration_min": "Mean plug-in duration (min)",
            "ports_used": "Distinct ports with a successful session",
            "busy_port_minutes": "Sum over ports of minutes occupied by a successful session",
            "all_ports_busy_minutes": "Minutes in the day when every port was occupied (queue risk)",
            "peak_concurrent": "Max ports simultaneously in use",
            "outage_port_minutes": "Sum over ports of reported outage minutes that day (no exclusions)",
            "n_ports": "", "port_utilization": "busy_port_minutes / (n_ports * 1440), 0-1",
            "month": "First day of month (timestamp)", "quarter": "e.g. '2025Q1'",
        },
    },
    "monthly_port": {
        "grain": "one row per port per month from the station's opening month",
        "columns": {
            "station_id": "", "port_label": "P1..P4 (stable within a station)", "month": "First day of month",
            "sessions_total": "", "sessions_success": "", "energy_kwh": "", "busy_minutes": "Minutes in use",
            "outage_minutes": "Reported outage minutes (Module 4), split across days, no exclusions",
            "outage_events": "Outage events starting this month",
            "minutes_in_service": "Minutes the port was in service this month (partial first month)",
            "uptime_pct": "Raw monthly availability = 100*(1 - outage_minutes/minutes_in_service). Does NOT apply NEVI excluded outages, so it is a conservative lower bound",
        },
    },
    "port_uptime_reported": {
        "grain": "one row per port: the latest cumulative Module 3 uptime report",
        "columns": {
            "station_id": "", "port_label": "", "reporting_start": "", "reporting_end": "",
            "reported_uptime_pct": "Operator-reported 12-month uptime; NULL when the port has < 1 year of history",
            "total_outage_min": "Cumulative outage minutes since reporting_start",
            "excluded_outage_min": "Outage minutes excluded under 23 CFR 680.116 (utility outage, vandalism, etc.)",
            "uptime_since_start_pct": "100*(1 - (total_outage_min - excluded_outage_min)/minutes since reporting_start). NEVI formula applied to the whole period since the port's first report",
            "uptime_nevi_pct": "Compliance figure to use: the operator-reported 12-month uptime when available, otherwise uptime_since_start_pct",
        },
    },
    "outage_events": {
        "grain": "one row per reported outage event per port",
        "columns": {"station_id": "", "port_label": "", "start_date": "Local start date", "end_date": "Local end date",
                    "duration_min": "", "duration_hours": ""},
    },
    "quarterly_station": {
        "grain": "one row per station per quarter, computed from the raw submissions by this pipeline",
        "columns": {
            "station_id": "", "quarter": "", "sessions_total": "", "sessions_success": "", "sessions_failed": "",
            "success_rate": "0-1", "energy_kwh": "", "avg_energy_kwh": "", "median_power_kw": "",
            "avg_duration_min": "", "days_in_service": "", "sessions_per_day": "Successful sessions per day in service",
            "port_utilization": "Mean daily port utilization 0-1", "all_ports_busy_minutes": "",
            "outage_port_minutes": "", "uptime_pct_raw": "Raw quarterly availability across all ports, no exclusions",
        },
    },
    "quarterly_reported": {
        "grain": "one row per station per quarter, exactly as reported in PennDOT's quarterly summary workbook",
        "columns": {"station_id": "", "quarter": "", "operating_days": "",
                    "rolling_12mo_uptime_pct": "PennDOT-reported 12-month rolling uptime (%)",
                    "sessions_success": "", "sessions_failed": "", "success_rate": "0-1", "energy_kwh": ""},
    },
    "hourly_profile": {
        "grain": "successful sessions by station, quarter, day of week, and local start hour",
        "columns": {"station_id": "", "quarter": "", "day_of_week": "0=Monday ... 6=Sunday",
                    "hour": "Local start hour 0-23", "sessions": "", "energy_kwh": ""},
    },
    "failures_quarterly": {
        "grain": "failed sessions by station, quarter, and failure type",
        "columns": {"station_id": "", "quarter": "",
                    "failure_type": "ChargeX error code (CX002, CX009, ...), 'other', 'Corrupted', or 'no_error_but_<1kWh' (session ended with no error code but delivered < 1 kWh)",
                    "sessions": ""},
    },
    "payments_quarterly": {
        "grain": "successful sessions by station, quarter, and payment method",
        "columns": {"station_id": "", "quarter": "",
                    "payment_method": "credit_card_terminal, phone_online, membership, roaming, other, none",
                    "sessions": ""},
    },
    "session_distribution": {
        "grain": "histogram of successful sessions per station; one row per (station, metric, bin)",
        "columns": {"station_id": "", "metric": "'energy_kwh' | 'power_kw' | 'duration_min'",
                    "bin_lo": "inclusive", "bin_hi": "exclusive", "sessions": "",
                    "is_top_bin": "TRUE for the last bin, which also holds every value above it"},
    },
}

RULES = [
    "Data covers 2023-12-22 to 2025-03-31 (EV-ChART quarterly submissions through 2025 Q1). Say so if a question asks about later dates.",
    "Successful session = no error code AND >= 1 kWh delivered. Failed = everything else.",
    "NEVI uptime requirement (23 CFR 680.116): each port >= 97% over a trailing 12 months, with excluded outages removed. Use port_uptime_reported.uptime_nevi_pct for compliance; monthly_port.uptime_pct is a raw lower bound.",
    "NEVI minimum power: 150 kW per port simultaneously. Session power is limited by the vehicle as well as the charger, so median session power below 150 kW is NOT by itself a violation.",
    "Tesla (Aston) reports zero failed sessions - Tesla's submission appears not to include failures; flag this when comparing reliability.",
    "Always join to stations to show station_name; never show raw station_id alone.",
    "Quarters are strings like '2025Q1'. Months are timestamps at the first of the month.",
    "Session-level records are NOT available - only these aggregates. Do not invent columns.",
]

EXAMPLES = [
    ("Which ports are below the 97% uptime requirement?",
     "SELECT s.station_name, p.port_label, p.uptime_nevi_pct, p.reporting_start, p.reporting_end\n"
     "FROM port_uptime_reported p JOIN stations s USING (station_id)\n"
     "WHERE p.uptime_nevi_pct < 97 ORDER BY p.uptime_nevi_pct"),
    ("Monthly successful sessions statewide",
     "SELECT month, SUM(sessions_success) AS sessions FROM daily_station GROUP BY month ORDER BY month"),
    ("What are the main failure causes at Francis Energy stations?",
     "SELECT s.station_name, f.failure_type, SUM(f.sessions) AS sessions\n"
     "FROM failures_quarterly f JOIN stations s USING (station_id)\n"
     "WHERE s.network_operator = 'Francis Energy' GROUP BY ALL ORDER BY s.station_name, sessions DESC"),
    ("Busiest hour of the week at Aston",
     "SELECT day_of_week, hour, SUM(sessions) AS sessions FROM hourly_profile h JOIN stations s USING (station_id)\n"
     "WHERE s.station_name = 'Aston' GROUP BY ALL ORDER BY sessions DESC LIMIT 5"),
]


def build():
    con = duckdb.connect()
    out = {"tables": {}, "rules": RULES, "examples": [{"q": q, "sql": s} for q, s in EXAMPLES]}
    for t, spec in TABLES.items():
        cols = con.execute(f"DESCRIBE SELECT * FROM '{TAB / (t + '.parquet')}'").fetchall()
        actual = [c[0] for c in cols]
        missing = set(spec["columns"]) - set(actual)
        assert not missing, f"{t}: documented columns not in data: {missing}"
        out["tables"][t] = {
            "grain": spec["grain"],
            "columns": [{"name": c[0], "type": c[1], "desc": spec["columns"].get(c[0], "")} for c in cols],
        }
    (ROOT / "site").mkdir(exist_ok=True)
    json.dump(out, open(ROOT / "site" / "semantic.json", "w"), indent=1)

    # compact text for the LLM prompt
    lines = []
    for t, spec in out["tables"].items():
        lines.append(f"TABLE {t} -- {spec['grain']}")
        for c in spec["columns"]:
            lines.append(f"  {c['name']} {c['type']}" + (f" -- {c['desc']}" if c["desc"] else ""))
    stations = con.execute(f"SELECT station_name, network_operator, has_session_data FROM '{TAB / 'stations.parquet'}' ORDER BY station_order").fetchall()
    lines.append("\nSTATIONS: " + "; ".join(f"{n} ({o}{'' if h else ', no data yet'})" for n, o, h in stations))
    lines.append("\nRULES:\n" + "\n".join(f"- {r}" for r in RULES))
    lines.append("\nEXAMPLES:\n" + "\n\n".join(f"Q: {q}\nSQL:\n{s}" for q, s in EXAMPLES))
    text = "\n".join(lines)
    (ROOT / "worker" / "src").mkdir(parents=True, exist_ok=True)
    (ROOT / "worker" / "src" / "semantic.js").write_text(
        "// GENERATED by pipeline/semantic.py - do not edit\nexport const SCHEMA = " + json.dumps(text) + ";\n")
    print(f"semantic layer: {len(out['tables'])} tables, prompt {len(text)} chars")


if __name__ == "__main__":
    build()
