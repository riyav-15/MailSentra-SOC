import { Activity, AlertTriangle, CheckCircle2, MailWarning } from "lucide-react";
import { useEffect, useState } from "react";
import Badge from "../components/Badge";
import DashboardCharts from "../components/DashboardCharts";
import Notice from "../components/Notice";
import StatCard from "../components/StatCard";
import { api, apiError } from "../services/api";

export default function SOCDashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/dashboard/soc").then((response) => setSummary(response.data)).catch((err) => setError(apiError(err)));
  }, []);

  const totals = summary?.totals || {};

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">SOC Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">Triage volume, high-risk cases, and detection performance.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={MailWarning} label="Reported emails" value={totals.reported_emails} />
        <StatCard icon={Activity} label="Open incidents" value={totals.open_incidents} accent="text-warning" />
        <StatCard icon={CheckCircle2} label="Closed incidents" value={totals.closed_incidents} accent="text-success" />
        <StatCard icon={AlertTriangle} label="High risk" value={totals.high_risk_incidents} accent="text-danger" />
      </div>
      <DashboardCharts summary={summary} />
      <section className="rounded-lg border border-line bg-panel p-4 shadow-glow">
        <h2 className="text-sm font-semibold text-slate-200">Recent Incidents</h2>
        <div className="mt-3 divide-y divide-line">
          {(summary?.recent_incidents || []).map((incident) => (
            <div key={incident.id} className="grid gap-2 py-3 md:grid-cols-[80px_1fr_120px_120px_80px]">
              <span className="font-mono text-slate-500">#{incident.id}</span>
              <span className="font-medium text-slate-100">{incident.title}</span>
              <Badge value={incident.status} />
              <Badge value={incident.severity} />
              <span className="text-right font-semibold text-cyan">{incident.risk_score}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
