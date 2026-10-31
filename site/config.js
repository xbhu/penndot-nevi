// Runtime configuration. workerUrl = the Cloudflare Worker that turns questions into SQL.
// Leave empty to hide the live LLM (the rest of the dashboard works without it).
window.NEVI_CONFIG = {
  workerUrl: "https://penndot-nevi-ask.xbhu-service.workers.dev",
};
