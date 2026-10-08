import { Activity, AlertTriangle, Database, Users } from "lucide-react";
import { useEffect, useState } from "react";
import DashboardCharts from "../components/DashboardCharts";
import Notice from "../components/Notice";
import StatCard from "../components/StatCard";
import { api, apiError } from "../services/api";

export default function AdminDashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/dashboard/admin").then((response) => setSummary(response.data)).catch((err) => setError(apiError(err)));
  }, []);

  const totals = summary?.totals || {};

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Admin Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">Platform statistics, users, rules, reports, and audit activity.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Users} label="Users" value={totals.users} />
        <StatCard icon={Database} label="Reports" value={totals.reported_emails} accent="text-success" />
        <StatCard icon={Activity} label="Open incidents" value={totals.open_incidents} accent="text-warning" />
        <StatCard icon={AlertTriangle} label="High risk" value={totals.high_risk_incidents} accent="text-danger" />
      </div>
      <DashboardCharts summary={summary} />
    </div>
  );
}
