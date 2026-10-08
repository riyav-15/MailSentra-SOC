import { ArrowUpRight, Clock3, Database, FileInput, RadioTower, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import StatCard from "../components/StatCard";
import { api, apiError } from "../services/api";

const sampleBatch = `From: Microsoft Security <alert@secure-reset.example>
Subject: Microsoft account verification required

Your Microsoft account access is restricted. Review immediately:
https://secure-reset.example/login
--- PHISHGUARD EMAIL ---
From: Payroll <payroll@vendor-payments.example>
Subject: Invoice payment change

Please update bank details for invoice processing.`;

export default function EnterpriseOperations() {
  const [overview, setOverview] = useState(null);
  const [queue, setQueue] = useState([]);
  const [campaignKey, setCampaignKey] = useState("m365-credential-campaign");
  const [batchText, setBatchText] = useState(sampleBatch);
  const [exportForm, setExportForm] = useState({ incident_id: "", destination: "SIEM Webhook", format: "json" });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function loadEnterprise() {
    setError("");
    try {
      const [overviewResponse, queueResponse] = await Promise.all([
        api.get("/enterprise/overview"),
        api.get("/enterprise/queue")
      ]);
      setOverview(overviewResponse.data);
      setQueue(queueResponse.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadEnterprise();
  }, []);

  async function updateQueue(incidentId, payload) {
    setError("");
    setMessage("");
    try {
      await api.patch(`/enterprise/queue/${incidentId}`, payload);
      await loadEnterprise();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function enrichIncident(incidentId) {
    setError("");
    setMessage("");
    try {
      const response = await api.post(`/enterprise/incidents/${incidentId}/enrich`);
      setMessage(`Enriched ${response.data.length} indicators for incident #${incidentId}.`);
      await loadEnterprise();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function submitBulkImport(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      const response = await api.post("/enterprise/bulk-import", {
        campaign_key: campaignKey,
        raw_batch_text: batchText
      });
      setMessage(`Imported ${response.data.created_incidents} incidents for ${response.data.campaign_key || "uncategorized"}.`);
      await loadEnterprise();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function queueExport(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      const response = await api.post("/enterprise/siem-export", {
        incident_id: exportForm.incident_id ? Number(exportForm.incident_id) : null,
        destination: exportForm.destination,
        format: exportForm.format
      });
      setMessage(`Queued ${response.data.format.toUpperCase()} export to ${response.data.destination}.`);
      await loadEnterprise();
    } catch (err) {
      setError(apiError(err));
    }
  }

  const totals = overview?.totals || {};

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wide text-cyan">Enterprise Operations</p>
          <h1 className="mt-1 text-2xl font-semibold text-white">Queue, enrichment, imports, and SIEM exports</h1>
        </div>
        <button className="btn-secondary" type="button" onClick={loadEnterprise}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </header>

      {error ? <Notice tone="error">{error}</Notice> : null}
      {message ? <Notice>{message}</Notice> : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={ShieldCheck} label="Active integrations" value={totals.active_integrations} />
        <StatCard icon={Clock3} label="Open queue" value={totals.open_queue} accent="text-warning" />
        <StatCard icon={Database} label="Enrichments" value={totals.enrichments} accent="text-success" />
        <StatCard icon={RadioTower} label="SIEM exports" value={totals.siem_exports} accent="text-cyan" />
      </div>

      <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-sm font-semibold text-slate-200">SLA Case Queue</h2>
          <span className="text-xs uppercase tracking-wide text-slate-500">{totals.sla_breaches || 0} breached</span>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Incident</th>
                <th className="px-4 py-3">Priority</th>
                <th className="px-4 py-3">Campaign</th>
                <th className="px-4 py-3">SLA</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {queue.map((item) => (
                <tr key={item.id} className="hover:bg-panelSoft/60">
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">#{item.incident_id} {item.incident_title}</p>
                    <p className="text-xs text-slate-500">Risk {item.risk_score} / {item.assigned_to_name || "Unassigned"}</p>
                  </td>
                  <td className="px-4 py-3"><Badge value={item.priority} /></td>
                  <td className="px-4 py-3 text-slate-300">{item.campaign_key || "None"}</td>
                  <td className={`px-4 py-3 ${item.sla_breached ? "text-danger" : "text-slate-300"}`}>{new Date(item.sla_due_at).toLocaleString()}</td>
                  <td className="px-4 py-3"><Badge value={item.queue_status === "Open" ? "New" : item.queue_status} /></td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-2">
                      <button className="btn-secondary" type="button" onClick={() => updateQueue(item.incident_id, { queue_status: "In Progress" })}>Start</button>
                      <button className="btn-secondary" type="button" onClick={() => enrichIncident(item.incident_id)}>Enrich</button>
                      <button className="btn-secondary" type="button" onClick={() => updateQueue(item.incident_id, { queue_status: "Closed" })}>Close</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <form onSubmit={submitBulkImport} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
          <div className="mb-4 flex items-center gap-2">
            <FileInput className="text-cyan" size={18} />
            <h2 className="text-sm font-semibold text-slate-200">Bulk Campaign Import</h2>
          </div>
          <label className="text-sm font-medium text-slate-300">
            Campaign key
            <input className="input mt-2" value={campaignKey} onChange={(event) => setCampaignKey(event.target.value)} />
          </label>
          <label className="mt-4 block text-sm font-medium text-slate-300">
            Batch emails
            <textarea className="input mt-2 min-h-[220px] font-mono text-xs" value={batchText} onChange={(event) => setBatchText(event.target.value)} />
          </label>
          <button className="btn-primary mt-4" type="submit">Import campaign</button>
        </form>

        <form onSubmit={queueExport} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
          <div className="mb-4 flex items-center gap-2">
            <ArrowUpRight className="text-cyan" size={18} />
            <h2 className="text-sm font-semibold text-slate-200">SIEM Export Queue</h2>
          </div>
          <label className="text-sm font-medium text-slate-300">
            Incident ID
            <input className="input mt-2" value={exportForm.incident_id} onChange={(event) => setExportForm({ ...exportForm, incident_id: event.target.value })} />
          </label>
          <label className="mt-4 block text-sm font-medium text-slate-300">
            Destination
            <input className="input mt-2" value={exportForm.destination} onChange={(event) => setExportForm({ ...exportForm, destination: event.target.value })} />
          </label>
          <label className="mt-4 block text-sm font-medium text-slate-300">
            Format
            <select className="input mt-2" value={exportForm.format} onChange={(event) => setExportForm({ ...exportForm, format: event.target.value })}>
              <option value="json">JSON</option>
              <option value="webhook">Webhook</option>
              <option value="syslog">Syslog</option>
            </select>
          </label>
          <button className="btn-primary mt-4" type="submit">Queue export</button>
        </form>
      </div>
    </div>
  );
}
