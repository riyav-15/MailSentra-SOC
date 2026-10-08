import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

export default function IncidentList() {
  const [incidents, setIncidents] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [query, setQuery] = useState("");
  const [becOnly, setBecOnly] = useState(false);
  const [campaignId, setCampaignId] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.get("/incidents"), api.get("/campaigns")])
      .then(([incidentResponse, campaignResponse]) => {
        setIncidents(incidentResponse.data);
        setCampaigns(campaignResponse.data);
      })
      .catch((err) => setError(apiError(err)));
  }, []);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase();
    return incidents.filter((incident) => {
      const matchesQuery = incident.title.toLowerCase().includes(needle) || String(incident.id).includes(needle);
      const matchesBec = !becOnly || incident.suspected_bec;
      const matchesCampaign = !campaignId || String(incident.campaign_id || "") === campaignId;
      return matchesQuery && matchesBec && matchesCampaign;
    });
  }, [incidents, query, becOnly, campaignId]);

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <h1 className="text-2xl font-semibold text-white">Incident Queue</h1>
          <p className="mt-1 text-sm text-slate-400">Review, triage, and close reported emails.</p>
        </div>
        <div className="flex w-full flex-col gap-3 sm:max-w-xl sm:flex-row sm:items-center">
          <label className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
            <input className="input pl-10" placeholder="Search incidents" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <label className="flex items-center gap-2 rounded-md border border-line bg-panelSoft px-3 py-2 text-sm text-slate-300">
            <input className="h-4 w-4 accent-cyan" type="checkbox" checked={becOnly} onChange={(event) => setBecOnly(event.target.checked)} />
            BEC suspected
          </label>
          <select className="input sm:max-w-[220px]" value={campaignId} onChange={(event) => setCampaignId(event.target.value)}>
            <option value="">All campaigns</option>
            {campaigns.map((campaign) => (
              <option key={campaign.id} value={campaign.id}>{campaign.name}</option>
            ))}
          </select>
        </div>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <section className="overflow-hidden rounded-lg border border-line bg-panel shadow-glow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[960px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Campaign</th>
                <th className="px-4 py-3">BEC</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Verdict</th>
                <th className="px-4 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {filtered.map((incident) => (
                <tr key={incident.id} className="hover:bg-panelSoft/60">
                  <td className="px-4 py-3 font-mono text-slate-400">#{incident.id}</td>
                  <td className="px-4 py-3 font-medium text-white">
                    <Link className="hover:text-cyan" to={`/incidents/${incident.id}`}>{incident.title}</Link>
                  </td>
                  <td className="px-4 py-3"><Badge value={incident.status} /></td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{incident.campaign_id ? `#${incident.campaign_id}` : "-"}</td>
                  <td className="px-4 py-3">{incident.suspected_bec ? <Badge value="High" /> : <span className="text-slate-500">-</span>}</td>
                  <td className="px-4 py-3"><Badge value={incident.severity} /></td>
                  <td className="px-4 py-3"><Badge value={incident.verdict} /></td>
                  <td className="px-4 py-3 text-right font-semibold text-cyan">{incident.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
