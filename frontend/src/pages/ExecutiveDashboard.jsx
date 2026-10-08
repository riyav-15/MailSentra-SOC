import { Activity, AlertTriangle, Clock, ShieldCheck, Target, TrendingUp } from "lucide-react";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Notice from "../components/Notice";
import StatCard from "../components/StatCard";
import { api, apiError } from "../services/api";

export default function ExecutiveDashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/dashboard/executive").then((response) => setSummary(response.data)).catch((err) => setError(apiError(err)));
  }, []);

  const totals = summary?.totals || {};

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Executive Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">Operational risk, campaign activity, response timing, and verdict quality.</p>
      </header>

      {error ? <Notice tone="error">{error}</Notice> : null}

      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard icon={ShieldCheck} label="Campaigns" value={totals.campaigns || 0} />
        <StatCard icon={AlertTriangle} label="SLA breaches" value={totals.sla_breaches || 0} accent="text-danger" />
        <StatCard icon={Clock} label="Mean time to close" value={`${totals.mean_time_to_close_hours || 0}h`} accent="text-warning" />
        <StatCard icon={Target} label="True positive rate" value={`${totals.true_positive_rate || 0}%`} accent="text-success" />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <ChartPanel title="Reports Over Time">
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={summary?.reports_over_time || []}>
              <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
              <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
              <Line type="monotone" dataKey="value" stroke="#22d3ee" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel title="Campaigns By Severity">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={summary?.campaigns_by_severity || []}>
              <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
              <Bar dataKey="value" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel title="Top Targeted Brands">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={summary?.top_targeted_brands || []} layout="vertical" margin={{ left: 40 }}>
              <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
              <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" width={120} tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
              <Bar dataKey="value" fill="#22c55e" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel title="Top Sender Domains">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={summary?.top_sender_domains || []} layout="vertical" margin={{ left: 40 }}>
              <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
              <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" width={120} tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
              <Bar dataKey="value" fill="#60a5fa" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>
      </div>

      <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
        <div className="flex items-center gap-2">
          <Activity size={18} className="text-cyan" />
          <h2 className="text-sm font-semibold text-slate-200">Response Quality</h2>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-4">
          <Metric label="Reports" value={totals.reports || 0} />
          <Metric label="Incidents" value={totals.incidents || 0} />
          <Metric label="Avg triage time" value={`${totals.average_triage_time_hours || 0}h`} />
          <Metric label="False positive rate" value={`${totals.false_positive_rate || 0}%`} />
        </div>
      </section>

      <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
        <div className="flex items-center gap-2">
          <TrendingUp size={18} className="text-warning" />
          <h2 className="text-sm font-semibold text-slate-200">SLA Breaches</h2>
        </div>
        <div className="mt-4 space-y-3">
          {(summary?.sla_breaches || []).map((item) => (
            <div key={`${item.incident_id}-${item.sla_due_at}`} className="flex flex-col justify-between gap-2 rounded-md border border-line bg-panelSoft p-3 md:flex-row md:items-center">
              <div>
                <p className="font-semibold text-white">Incident #{item.incident_id}: {item.incident_title}</p>
                <p className="mt-1 text-xs text-slate-500">Due {new Date(item.sla_due_at).toLocaleString()}</p>
              </div>
              <span className="text-sm font-semibold text-warning">{item.priority}</span>
            </div>
          ))}
          {!summary?.sla_breaches?.length ? <p className="text-sm text-slate-500">No active SLA breaches.</p> : null}
        </div>
      </section>
    </div>
  );
}

function ChartPanel({ title, children }) {
  return (
    <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
      <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-md border border-line bg-panelSoft p-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-lg font-semibold text-white">{value}</p>
    </div>
  );
}
