import { UploadCloud } from "lucide-react";
import { useState } from "react";
import Badge from "../components/Badge";
import { api, apiError } from "../services/api";

const sampleText = `From: IT Security <security@example.com>
Reply-To: verify@secure-reset.example
Return-Path: bounce@mailer.example
Authentication-Results: mx.example; spf=fail smtp.mailfrom=mailer.example; dkim=fail; dmarc=fail
Subject: Urgent password reset required

Dear user,
Your account will be suspended. Reset your password immediately:
http://192.168.10.25/login`;

export default function SubmitReport() {
  const [form, setForm] = useState({
    subject: "Urgent password reset required",
    sender: "security@example.com",
    report_reason: "Unexpected password reset message.",
    raw_email_text: sampleText
  });
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    const data = new FormData();
    data.append("subject", form.subject);
    data.append("sender", form.sender);
    data.append("report_reason", form.report_reason);
    data.append("raw_email_text", form.raw_email_text);
    if (file) data.append("eml_file", file);

    try {
      const response = await api.post("/reports/submit", data);
      setResult(response.data);
    } catch (err) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Submit Suspicious Email</h1>
        <p className="mt-1 text-sm text-slate-400">Paste raw email content or upload a safe .eml or QR image sample for analysis.</p>
      </header>

      <div className="grid gap-6 xl:grid-cols-[1fr_360px]">
        <form onSubmit={handleSubmit} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
          {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-400/10 p-3 text-sm text-red-100">{error}</p> : null}
          <div className="grid gap-4 md:grid-cols-2">
            <label className="text-sm font-medium text-slate-300">
              Subject
              <input className="input mt-2" value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} />
            </label>
            <label className="text-sm font-medium text-slate-300">
              Sender email
              <input className="input mt-2" value={form.sender} onChange={(e) => setForm({ ...form, sender: e.target.value })} />
            </label>
          </div>
          <label className="mt-4 block text-sm font-medium text-slate-300">
            Reason for reporting
            <input className="input mt-2" value={form.report_reason} onChange={(e) => setForm({ ...form, report_reason: e.target.value })} />
          </label>
          <label className="mt-4 block text-sm font-medium text-slate-300">
            Raw email text
            <textarea className="input mt-2 min-h-[300px] font-mono text-xs" value={form.raw_email_text} onChange={(e) => setForm({ ...form, raw_email_text: e.target.value })} />
          </label>
          <label className="mt-4 flex cursor-pointer items-center justify-between rounded-md border border-dashed border-line bg-panelSoft p-4 text-sm text-slate-300">
            <span className="flex items-center gap-2"><UploadCloud size={18} /> {file?.name || "Upload .eml or QR image"}</span>
            <input className="hidden" type="file" accept=".eml,image/png,image/jpeg,image/webp,image/bmp" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          </label>
          <button className="btn-primary mt-5" disabled={loading} type="submit">{loading ? "Submitting..." : "Submit report"}</button>
        </form>

        <aside className="rounded-lg border border-line bg-panel p-5 shadow-glow">
          <h2 className="text-sm font-semibold text-slate-200">Analysis Result</h2>
          {result ? (
            <div className="mt-4 space-y-4">
              <div className="rounded-md border border-line bg-panelSoft p-4">
                <p className="text-sm text-slate-400">Risk score</p>
                <p className="mt-1 text-4xl font-semibold text-cyan">{result.risk_score}</p>
              </div>
              <Badge value={result.severity} />
              <Badge value={result.verdict_suggestion} />
              <p className="text-sm leading-6 text-slate-300">{result.recommended_action}</p>
              <div>
                <p className="mb-2 text-sm font-semibold text-slate-200">Triggered rules</p>
                <div className="space-y-2">
                  {(result.triggered_rules || []).map((rule) => (
                    <div key={`${rule.name}-${rule.evidence}`} className="rounded-md border border-line bg-panelSoft p-3 text-sm">
                      <p className="font-semibold text-white">{rule.name} <span className="text-cyan">+{rule.score_added}</span></p>
                      <p className="mt-1 text-slate-400">{rule.evidence}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <p className="mt-4 text-sm text-slate-400">Submitted reports become incidents automatically.</p>
          )}
        </aside>
      </div>
    </div>
  );
}
