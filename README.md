# Pennsylvania NEVI charging performance dashboard

A demonstration dashboard for Pennsylvania's NEVI-funded fast-charging stations, built by the
[Smart Mobility Lab](https://lab.mobilitypsu.com/) at Penn State from EV-ChART quarterly
submissions shared by PennDOT. Not an official PennDOT product.

**Live site:** https://xbhu.github.io/penndot-nevi/ (sign-in required)

## How it works

```
raw EV-ChART CSVs ──► pipeline/build.py ──► 11 aggregated tables ──► pipeline/encrypt.py ──► site/data/bundle.bin
 (never committed)      clean + aggregate        (never committed)       AES-256-GCM, per-user keys     (committed, encrypted)

browser: sign in ─► decrypt bundle (WebCrypto) ─► DuckDB-WASM ─► every chart is a SQL query (shown under "SQL")
                                                        ▲
"Ask the data": question ─► Cloudflare Worker (LLM writes SQL) ─► SQL runs in the browser ─► Worker writes answer from the rows
```

- **No server, no database to run.** GitHub Pages serves static files; DuckDB runs in the browser.
- **Only aggregates are published.** Session-level records stay on the lab's machines.
- **Encrypted.** The repo is public but the data file is ciphertext. Each user has their own
  username and password, and each unlocks a wrapped copy of one data key, so users can be added or removed
  without touching anyone else's access.
- **Verifiable answers.** The language model never sees the tables, only the schema and the rows of the
  query it wrote. Every answer shows its SQL.

## Repository layout

| Path | What it is |
|---|---|
| `pipeline/build.py` | Cleans raw Module 2/3/4 CSVs + PennDOT summary workbook into aggregated tables |
| `pipeline/semantic.py` | Data dictionary + business rules; feeds the Data notes page and the LLM prompt |
| `pipeline/encrypt.py` | Builds the encrypted bundle and the Worker access tokens |
| `site/` | The static dashboard (published to GitHub Pages) |
| `worker/` | Cloudflare Worker for "Ask the data" |

## Rebuilding after new data arrives

```bash
# 1. put new quarterly folders under raw/Quarterly Reports_*/ and the summary .xlsx under raw/
python3 pipeline/build.py        # prints a reconciliation against PennDOT's summary
python3 pipeline/semantic.py
python3 pipeline/encrypt.py      # needs pipeline/users.local.json
git add site && git commit -m "Data refresh" && git push   # GitHub Actions redeploys
```

Requirements: Python 3.11+, `pandas`, `numpy`, `duckdb`, `pyarrow`, `openpyxl`, `cryptography`.

## Users

`pipeline/users.local.json` (git-ignored) maps usernames to passwords:

```json
{ "nevi": "…", "penndot-colton": "…" }
```

Run `encrypt.py`, commit `site/data/`, and update the Worker's `ACCESS_TOKENS` secret with the
contents of `build/access_tokens.json`.

## "Ask the data" Worker

`worker/src/index.js`. Uses Cloudflare Workers AI (free daily allocation) by default; set an
`ANTHROPIC_API_KEY` secret to switch to Claude.

```bash
cd worker
npx wrangler deploy
npx wrangler secret put ACCESS_TOKENS   # paste build/access_tokens.json
# optional: npx wrangler secret put ANTHROPIC_API_KEY
```

Then set `workerUrl` in `site/config.js` to the deployed URL. `worker/dist/worker.js` is a
single-file build that can be pasted into the Cloudflare dashboard editor instead.

## Definitions

- **Successful session**: no error code and at least 1 kWh delivered.
- **Uptime (NEVI method)**: 100 × (1 − (outage − excluded outage) / minutes in period), per port, from Module 3.
- **Monthly availability**: same formula from Module 4 outage events, no exclusions (a lower bound).
- **Port utilization**: minutes occupied by a successful session ÷ minutes in the day.
