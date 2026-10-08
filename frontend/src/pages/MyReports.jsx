import { useEffect, useState } from "react";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

export default function MyReports() {
  const [reports, setReports] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/reports/my").then((response) => setReports(response.data)).catch((err) => setError(apiError(err)));
  }, []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">My Reports</h1>
        <p className="mt-1 text-sm text-slate-400">Submitted emails and final SOC verdicts.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <section className="overflow-hidden rounded-lg border border-line bg-panel shadow-glow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Verdict</th>
                <th className="px-4 py-3 text-right">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {reports.map((report) => (
                <tr key={report.id} className="hover:bg-panelSoft/60">
                  <td className="px-4 py-3 font-medium text-white">{report.subject}</td>
                  <td className="px-4 py-3 text-slate-300">{report.sender}</td>
                  <td className="px-4 py-3"><Badge value={report.incident?.status || "New"} /></td>
                  <td className="px-4 py-3"><Badge value={report.incident?.severity || "Low"} /></td>
                  <td className="px-4 py-3"><Badge value={report.incident?.verdict || "Pending Review"} /></td>
                  <td className="px-4 py-3 text-right font-semibold text-cyan">{report.incident?.risk_score ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
