// Cloudflare Worker: turns a question into DuckDB SQL, then turns the query result into a
// short answer. It never sees the data tables - only the schema, and the rows of a query the
// browser already ran. Every number in an answer therefore comes from SQL the user can inspect.
//
// Providers (chosen automatically):
//   - ANTHROPIC_API_KEY secret set  -> Claude via the Messages API (better SQL)
//   - otherwise                     -> Cloudflare Workers AI binding "AI" (free daily allocation), default gpt-oss-120b
//
// Secrets / vars:
//   ACCESS_TOKENS     JSON {"username": sha256("nevi-worker:username:password")}  (secret)
//   ALLOWED_ORIGINS   comma-separated origins allowed to call this worker          (var)
//   ANTHROPIC_API_KEY optional                                                    (secret)
//   ANTHROPIC_MODEL   optional, default claude-sonnet-5-5                         (var)
//   WORKERS_AI_MODEL  optional default model (var); requests may pick one from WORKERS_AI_MODELS
import { SCHEMA } from "./semantic.js";

const DEFAULT_MODEL = "@cf/openai/gpt-oss-120b"; // best SQL accuracy in our side-by-side test (Oct 2026)
// Models a client may request explicitly (for side-by-side evaluation). Anything else falls back to the default.
const WORKERS_AI_MODELS = [
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "@cf/openai/gpt-oss-120b", "@cf/qwen/qwen2.5-coder-32b-instruct",
  "@cf/deepseek-ai/deepseek-v4-flash-0731", "@cf/meta/llama-4-scout-17b-16e-instruct", "@cf/mistralai/mistral-small-3.1-24b-instruct",
  "@cf/zai-org/glm-4.7-flash", "@cf/qwen/qwen3-30b-a3b-fp8",
];

const SQL_SYSTEM = `You translate questions about Pennsylvania NEVI electric-vehicle charging stations into a single DuckDB SQL query.

${SCHEMA}

Instructions:
- Return ONLY a JSON object: {"sql": "<one SELECT query>", "explanation": "<one sentence on the approach>"}.
- If the question cannot be answered from these tables, return {"sql": null, "explanation": "<why, and what the data does cover>"}.
- One read-only SELECT (CTEs allowed). No semicolons. DuckDB dialect.
- Join stations to show station_name. Round decimals sensibly. Order results meaningfully. LIMIT 200 unless the question needs every row.
- SCALES: columns ending in _pct are on a 0-100 scale (the 97% NEVI threshold is written 97, NEVER 0.97). Columns ending in _rate and port_utilization are 0-1 fractions.
- If a previous attempt failed, fix that SQL using the error message.`;

const ANSWER_SYSTEM = `You write a short, factual answer to a question about Pennsylvania NEVI charging stations, using ONLY the query result provided.

Rules:
- 1-3 sentences, at most 70 words, plain prose for a state DOT program manager. No markdown, no bullet points.
- When there are many rows, summarize (totals, extremes, the top few) instead of listing every row; the full table is shown to the user.
- Every number must come from the result rows. Do not invent or estimate numbers. Round sensibly.
- If the result has 0 rows, say only that the query returned no rows; do not draw conclusions from an empty result.
- If the result does not answer the question, say so plainly.
- Mention caveats from these rules only when relevant: data ends 2025-03-31; Tesla (Aston) reports no failed sessions; monthly_port uptime_pct ignores excluded outages.
Return ONLY JSON: {"answer": "<text>", "chart": {"type": "bar"|"line"|"none", "x": "<column>", "y": ["<numeric column>", ...]}}`;

const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });

function cors(req, env) {
  const origin = req.headers.get("origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const ok = allowed.length === 0 || allowed.includes(origin);
  return ok
    ? { "access-control-allow-origin": origin || "*", "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type, authorization", "access-control-max-age": "86400", vary: "origin" }
    : null;
}

function auth(req, env) {
  const m = /^Bearer\s+([^:]+):([0-9a-f]{64})$/i.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  let tokens = {};
  try { tokens = JSON.parse(env.ACCESS_TOKENS || "{}"); } catch {}
  const user = m[1].toLowerCase();
  return tokens[user] && tokens[user] === m[2].toLowerCase() ? user : null;
}

function parseJSON(text) {
  if (text && typeof text === "object") return text;
  const s = String(text || "").replace(/```(?:json)?/g, "");
  const a = s.indexOf("{"), b = s.lastIndexOf("}");
  if (a < 0 || b < a) throw new Error("model did not return JSON");
  return JSON.parse(s.slice(a, b + 1));
}

async function llm(env, system, user, maxTokens = 900, opts = {}) {
  if (env.ANTHROPIC_API_KEY) {
    const model = env.ANTHROPIC_MODEL || "claude-sonnet-5-5";
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model, max_tokens: maxTokens, temperature: 0, system, messages: [{ role: "user", content: user }] }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j?.error?.message || `Anthropic API ${r.status}`);
    return { text: j.content.map((c) => c.text || "").join(""), model };
  }
  if (!env.AI) throw new Error("No model configured: add the Workers AI binding named AI, or an ANTHROPIC_API_KEY secret.");
  const model = (opts.model && WORKERS_AI_MODELS.includes(opts.model)) ? opts.model : (env.WORKERS_AI_MODEL || DEFAULT_MODEL);
  const out = await env.AI.run(model, {
    messages: [{ role: "system", content: system }, { role: "user", content: user }],
    max_tokens: maxTokens, temperature: 0,
  });
  return { text: extractText(out), model: model.replace(/^@cf\//, "") };
}

// Workers AI models differ in response shape (messages vs. OpenAI chat vs. Responses API).
function extractText(out) {
  if (out == null) return "";
  if (typeof out === "string") return out;
  if (out.response != null) return typeof out.response === "string" ? out.response : JSON.stringify(out.response);
  if (out.choices?.[0]?.message?.content) return out.choices[0].message.content;
  if (out.output_text) return out.output_text;
  if (Array.isArray(out.output)) {
    const parts = [];
    for (const o of out.output) for (const c of o.content || []) if (c.type === "output_text" || c.text) parts.push(c.text);
    if (parts.length) return parts.join("");
  }
  return JSON.stringify(out);
}

// Reasoning models occasionally return truncated or non-JSON text: retry once, then fall back.
async function llmJSON(env, system, user, maxTokens, opts, fallbackKey) {
  let last;
  for (let i = 0; i < 2; i++) {
    const { text, model } = await llm(env, system, user, maxTokens, opts);
    try { return { out: parseJSON(text), model }; }
    catch (e) {
      last = { text, model };
      const m = fallbackKey && /"answer"\s*:\s*"((?:[^"\\]|\\.)*)/.exec(String(text || ""));
      if (m) return { out: { answer: JSON.parse(`"${m[1]}"`) + (/"\s*,\s*"chart"/.test(text) ? "" : " …"), chart: null }, model };
    }
  }
  if (fallbackKey && last?.text && !String(last.text).trim().startsWith("{")) return { out: { answer: String(last.text).trim().slice(0, 800), chart: null }, model: last.model };
  throw new Error("model did not return JSON");
}

export default {
  async fetch(req, env) {
    const h = cors(req, env);
    if (!h) return json({ error: "Origin not allowed." }, 403);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/health")
      return json({ ok: true, provider: env.ANTHROPIC_API_KEY ? "anthropic" : env.AI ? "workers-ai" : "none" }, 200, h);
    if (req.method !== "POST") return json({ error: "Use POST." }, 405, h);

    const user = auth(req, env);
    if (!user) return json({ error: "Sign in again: this session is not authorized to ask questions." }, 401, h);

    let body;
    try { body = await req.json(); } catch { return json({ error: "Request body must be JSON." }, 400, h); }
    const question = String(body.question || "").slice(0, 600).trim();
    if (!question) return json({ error: "Type a question first." }, 400, h);

    try {
      if (url.pathname === "/sql") {
        let prompt = `Question: ${question}`;
        if (body.previous_sql && body.error)
          prompt += `\n\nYour previous SQL failed.\nSQL:\n${String(body.previous_sql).slice(0, 4000)}\nError:\n${String(body.error).slice(0, 1000)}\nReturn corrected JSON.`;
        const { out, model } = await llmJSON(env, SQL_SYSTEM, prompt, 3000, { model: body.model });
        console.log(JSON.stringify({ user, kind: "sql", question, model, sql: out.sql }));
        return json({ sql: out.sql ? String(out.sql).trim().replace(/;\s*$/, "") : null, explanation: out.explanation || "", model }, 200, h);
      }
      if (url.pathname === "/answer") {
        const columns = (body.columns || []).slice(0, 30);
        const rows = (body.rows || []).slice(0, 60);
        const prompt = `Question: ${question}\n\nSQL that was run:\n${String(body.sql || "").slice(0, 4000)}\n\n` +
          `Result: ${body.row_count ?? rows.length} rows${rows.length < (body.row_count ?? 0) ? ` (first ${rows.length} shown)` : ""}\n` +
          `Columns: ${JSON.stringify(columns)}\nRows: ${JSON.stringify(rows).slice(0, 12000)}`;
        const { out, model } = await llmJSON(env, ANSWER_SYSTEM, prompt, 2500, { model: body.model }, "answer");
        console.log(JSON.stringify({ user, kind: "answer", question, model }));
        return json({ answer: String(out.answer || ""), chart: out.chart || null, model }, 200, h);
      }
      return json({ error: "Unknown endpoint." }, 404, h);
    } catch (e) {
      console.log(JSON.stringify({ user, error: e.message }));
      return json({ error: `The language model could not answer: ${e.message}` }, 502, h);
    }
  },
};
