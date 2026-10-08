import { useEffect, useState } from "react";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/admin/audit-logs").then((response) => setLogs(response.data)).catch((err) => setError(apiError(err)));
  }, []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Audit Logs</h1>
        <p className="mt-1 text-sm text-slate-400">Security-relevant platform activity.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <section className="overflow-hidden rounded-lg border border-line bg-panel shadow-glow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-panelSoft/60">
                  <td className="px-4 py-3 text-slate-400">{new Date(log.created_at).toLocaleString()}</td>
                  <td className="px-4 py-3 font-mono text-slate-400">{log.user_id || "system"}</td>
                  <td className="px-4 py-3 font-semibold text-white">{log.action}</td>
                  <td className="px-4 py-3 text-slate-300">{log.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
