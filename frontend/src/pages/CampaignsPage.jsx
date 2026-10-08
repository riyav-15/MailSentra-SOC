import { GitBranch, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");

  async function loadCampaigns() {
    setError("");
    try {
      const response = await api.get("/campaigns");
      setCampaigns(response.data);
      const nextId = selectedId || response.data[0]?.id || null;
      setSelectedId(nextId);
      if (nextId) await loadDetail(nextId);
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function loadDetail(campaignId) {
    setError("");
    try {
      const response = await api.get(`/campaigns/${campaignId}`);
      setDetail(response.data);
      setSelectedId(campaignId);
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function closeCampaign() {
    if (!selectedId) return;
    setError("");
    try {
      await api.post(`/campaigns/${selectedId}/close`);
      await loadCampaigns();
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadCampaigns();
  }, []);

  const timelineData = useMemo(() => {
    const counts = {};
    for (const item of detail?.timeline || []) {
      const day = new Date(item.created_at).toLocaleDateString();
      counts[day] = (counts[day] || 0) + 1;
    }
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [detail]);

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <h1 className="text-2xl font-semibold text-white">Campaigns</h1>
          <p className="mt-1 text-sm text-slate-400">Correlated incidents grouped by sender, subject, domains, hashes, brands, and timing.</p>
        </div>
        <button className="btn-secondary" type="button" onClick={loadCampaigns}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </header>

      {error ? <Notice tone="error">{error}</Notice> : null}

      <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
        <section className="rounded-lg border border-line bg-panel p-4 shadow-glow">
          <h2 className="text-sm font-semibold text-slate-200">Campaign Queue</h2>
          <div className="mt-4 space-y-2">
            {campaigns.map((campaign) => (
              <button
                key={campaign.id}
                className={`w-full rounded-md border p-3 text-left transition ${
                  selectedId === campaign.id ? "border-cyan bg-cyan/10" : "border-line bg-panelSoft hover:border-cyan/40"
                }`}
                type="button"
                onClick={() => loadDetail(campaign.id)}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold text-white">{campaign.name}</p>
                    <p className="mt-1 text-xs text-slate-500">{campaign.primary_sender_domain || campaign.primary_url_domain || "No primary domain"}</p>
                  </div>
                  <Badge value={campaign.severity} />
                </div>
                <p className="mt-2 text-xs text-slate-400">{campaign.related_incident_count} related incidents / {campaign.status}</p>
              </button>
            ))}
            {!campaigns.length ? <p className="text-sm text-slate-500">No campaigns have been correlated yet.</p> : null}
          </div>
        </section>

        <div className="space-y-6">
          {detail ? (
            <>
              <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
                <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                  <div>
                    <p className="font-mono text-sm text-slate-500">Campaign #{detail.id}</p>
                    <h2 className="mt-1 text-xl font-semibold text-white">{detail.name}</h2>
                    <p className="mt-2 text-sm text-slate-400">{detail.label}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge value={detail.severity} />
                    <Badge value={detail.status} />
                    <button className="btn-secondary" type="button" onClick={closeCampaign}>Close campaign</button>
                  </div>
                </div>
                <dl className="mt-5 grid gap-4 md:grid-cols-4">
                  <Info label="Incidents" value={detail.related_incident_count} />
                  <Info label="Brand" value={detail.primary_brand || "Unknown"} />
                  <Info label="Sender domain" value={detail.primary_sender_domain || "Unknown"} />
                  <Info label="URL domain" value={detail.primary_url_domain || "Unknown"} />
                </dl>
              </section>

              <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
                <h2 className="text-sm font-semibold text-slate-200">Timeline</h2>
                <div className="mt-4 h-[240px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={timelineData}>
                      <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
                      <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#94a3b8" allowDecimals={false} />
                      <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
                      <Bar dataKey="value" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </section>

              <div className="grid gap-6 xl:grid-cols-2">
                <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
                  <h2 className="text-sm font-semibold text-slate-200">Related Incidents</h2>
                  <div className="mt-4 space-y-3">
                    {(detail.related_incidents || []).map((incident) => (
                      <Link key={incident.id} className="block rounded-md border border-line bg-panelSoft p-3 hover:border-cyan/40" to={`/incidents/${incident.id}`}>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="font-semibold text-white">#{incident.id} {incident.title}</p>
                            <p className="mt-1 text-xs text-slate-500">{incident.sender}</p>
                          </div>
                          <Badge value={incident.severity} />
                        </div>
                      </Link>
                    ))}
                  </div>
                </section>

                <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
                  <h2 className="text-sm font-semibold text-slate-200">Top IOCs and Brands</h2>
                  <div className="mt-4 space-y-3">
                    {(detail.top_iocs || []).map((ioc) => (
                      <div key={`${ioc.type}-${ioc.value}`} className="rounded-md border border-line bg-panelSoft p-3">
                        <p className="text-xs uppercase tracking-wide text-slate-500">{ioc.type} / seen {ioc.count}</p>
                        <p className="mt-1 break-words font-mono text-sm text-slate-100">{ioc.value}</p>
                      </div>
                    ))}
                    {(detail.brands || []).map((brand) => (
                      <div key={brand.name} className="flex items-center justify-between rounded-md border border-line bg-panelSoft p-3 text-sm">
                        <span className="text-slate-200">{brand.name}</span>
                        <span className="font-semibold text-cyan">{brand.value}</span>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </>
          ) : (
            <section className="rounded-lg border border-line bg-panel p-8 text-center shadow-glow">
              <GitBranch className="mx-auto text-slate-500" size={32} />
              <p className="mt-3 text-sm text-slate-400">Select a campaign to inspect correlation details.</p>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

function Info({ label, value }) {
  return (
    <div className="rounded-md border border-line bg-panelSoft p-3">
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 break-words text-sm font-semibold text-white">{value}</dd>
    </div>
  );
}
