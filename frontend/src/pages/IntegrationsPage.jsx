import { Save, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

const statuses = ["Not configured", "Pending", "Active", "Error"];

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState([]);
  const [drafts, setDrafts] = useState({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function loadIntegrations() {
    setError("");
    try {
      const response = await api.get("/enterprise/integrations");
      setIntegrations(response.data);
      setDrafts(Object.fromEntries(response.data.map((item) => [item.id, item])));
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadIntegrations();
  }, []);

  function updateDraft(id, field, value) {
    setDrafts({ ...drafts, [id]: { ...drafts[id], [field]: value } });
  }

  async function saveIntegration(id) {
    setError("");
    setMessage("");
    try {
      const draft = drafts[id];
      await api.patch(`/enterprise/integrations/${id}`, {
        status: draft.status,
        config_summary: draft.config_summary,
        last_result: draft.last_result
      });
      setMessage("Integration updated.");
      await loadIntegrations();
    } catch (err) {
      setError(apiError(err));
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <p className="text-sm font-semibold uppercase tracking-wide text-cyan">Commercial Connectors</p>
        <h1 className="mt-1 text-2xl font-semibold text-white">SSO, gateway, threat intel, sandbox, and SIEM</h1>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      {message ? <Notice>{message}</Notice> : null}

      <section className="grid gap-4 xl:grid-cols-2">
        {integrations.map((integration) => {
          const draft = drafts[integration.id] || integration;
          return (
            <article key={integration.id} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="rounded-md border border-line bg-panelSoft p-2 text-cyan">
                    <ShieldCheck size={18} />
                  </div>
                  <div>
                    <h2 className="font-semibold text-white">{integration.name}</h2>
                    <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{integration.type.replace("_", " ")}</p>
                  </div>
                </div>
                <Badge value={draft.status === "Active" ? "Safe" : draft.status === "Error" ? "Critical" : "In Review"} />
              </div>

              <label className="mt-4 block text-sm font-medium text-slate-300">
                Status
                <select className="input mt-2" value={draft.status} onChange={(event) => updateDraft(integration.id, "status", event.target.value)}>
                  {statuses.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </label>
              <label className="mt-4 block text-sm font-medium text-slate-300">
                Configuration summary
                <textarea className="input mt-2 min-h-[96px]" value={draft.config_summary || ""} onChange={(event) => updateDraft(integration.id, "config_summary", event.target.value)} />
              </label>
              <label className="mt-4 block text-sm font-medium text-slate-300">
                Last check
                <input className="input mt-2" value={draft.last_result || ""} onChange={(event) => updateDraft(integration.id, "last_result", event.target.value)} />
              </label>
              <button className="btn-primary mt-4" type="button" onClick={() => saveIntegration(integration.id)}>
                <Save size={16} />
                Save
              </button>
            </article>
          );
        })}
      </section>
    </div>
  );
}
