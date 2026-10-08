import { Bot, Download, FileText, GitBranch, Map, MessageSquarePlus, Play, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Badge from "../components/Badge";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

const statuses = ["New", "In Review", "Escalated", "Closed"];
const severities = ["Low", "Medium", "High", "Critical"];
const verdicts = ["Safe", "Spam", "Suspicious", "Likely Phishing", "Confirmed Phishing", "Pending Review"];

export default function IncidentDetails() {
  const { incidentId } = useParams();
  const [incident, setIncident] = useState(null);
  const [enrichments, setEnrichments] = useState([]);
  const [playbookData, setPlaybookData] = useState({ templates: [], runs: [] });
  const [playbookTab, setPlaybookTab] = useState("templates");
  const [copilot, setCopilot] = useState(null);
  const [summaryDraft, setSummaryDraft] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  async function loadIncident() {
    try {
      const [incidentResponse, enrichmentResponse, playbookResponse] = await Promise.all([
        api.get(`/incidents/${incidentId}`),
        api.get(`/enterprise/incidents/${incidentId}/enrichment`),
        api.get(`/incidents/${incidentId}/playbooks`)
      ]);
      setIncident(incidentResponse.data);
      setEnrichments(enrichmentResponse.data);
      setPlaybookData(playbookResponse.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadIncident();
  }, [incidentId]);

  async function updateField(field, value) {
    setError("");
    try {
      await api.patch(`/incidents/${incidentId}/${field}`, { value });
      await loadIncident();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function addNote(event) {
    event.preventDefault();
    if (!note.trim()) return;
    setError("");
    try {
      await api.post(`/incidents/${incidentId}/notes`, { note });
      setNote("");
      await loadIncident();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function generateReport() {
    setError("");
    try {
      await api.post(`/incidents/${incidentId}/generate-report`);
      await loadIncident();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function enrichIncident() {
    setError("");
    try {
      const response = await api.post(`/enterprise/incidents/${incidentId}/enrich`);
      setEnrichments(response.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function updateBecChecklist(itemKey, completed) {
    setError("");
    try {
      await api.patch(`/incidents/${incidentId}/bec-checklist/${itemKey}`, { completed });
      await loadIncident();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function generateSocSummary() {
    setError("");
    try {
      const response = await api.post(`/incidents/${incidentId}/copilot-summary`);
      setCopilot(response.data);
      setSummaryDraft(formatCopilotSummary(response.data));
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function runPlaybook(templateId) {
    setError("");
    try {
      await api.post(`/incidents/${incidentId}/playbooks/run`, { template_id: templateId });
      const response = await api.get(`/incidents/${incidentId}/playbooks`);
      setPlaybookData(response.data);
      setPlaybookTab("runs");
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function downloadReport(reportId) {
    setError("");
    try {
      const response = await api.get(`/reports/${reportId}/download`, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `phishguard-incident-report-${reportId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(apiError(err));
    }
  }

  if (!incident) {
    return error ? <Notice tone="error">{error}</Notice> : <p className="text-slate-300">Loading incident...</p>;
  }

  const iocs = incident.iocs || [];
  const triggeredRules = incident.triggered_rules || [];
  const notes = incident.notes || [];
  const reports = incident.reports || [];
  const explanation = incident.analysis_explanation;
  const explanationRules = explanation?.triggered_rules || [];
  const evidenceItems = explanation?.evidence_items || [];
  const scoreBreakdown = explanation?.score_breakdown || [];
  const qrIndicators = iocs.filter((ioc) => ioc.type === "qr_payload");
  const brandEvidence = evidenceItems.filter((item) => ["brand_impersonation", "lookalike_domain", "qr_brand_mismatch"].includes(item.type));
  const becChecklist = incident.bec_checklist || [];
  const frameworkMappings = incident.framework_mappings || [];
  const nistLifecycle = incident.nist_lifecycle || [];
  const campaign = incident.campaign;

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div>
          <p className="font-mono text-sm text-slate-500">Incident #{incident.id}</p>
          <h1 className="mt-1 text-2xl font-semibold text-white">{incident.title}</h1>
          <p className="mt-1 text-sm text-slate-400">{incident.email_report.sender}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge value={incident.status} />
          <Badge value={incident.severity} />
          <Badge value={incident.verdict} />
          {campaign ? <span className="inline-flex items-center rounded-md border border-cyan/30 bg-cyan/10 px-2 py-1 text-xs font-semibold text-cyan">Campaign #{campaign.id}</span> : null}
          {qrIndicators.length ? <span className="inline-flex items-center rounded-md border border-orange-400/30 bg-orange-400/10 px-2 py-1 text-xs font-semibold text-orange-100">QR phishing indicator detected</span> : null}
          {incident.suspected_bec ? <span className="inline-flex items-center rounded-md border border-red-400/30 bg-red-400/10 px-2 py-1 text-xs font-semibold text-red-100">BEC suspected</span> : null}
        </div>
      </header>

      {error ? <Notice tone="error">{error}</Notice> : null}

      <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
        <aside className="space-y-4">
          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <p className="text-sm text-slate-400">Risk score</p>
            <p className="mt-1 text-5xl font-semibold text-cyan">{incident.risk_score}</p>
            <p className="mt-4 text-sm leading-6 text-slate-300">{incident.recommended_action}</p>
          </section>
          {campaign ? (
            <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
              <div className="flex items-center gap-2">
                <GitBranch size={16} className="text-cyan" />
                <h2 className="text-sm font-semibold text-slate-200">Campaign</h2>
              </div>
              <p className="mt-3 font-semibold text-white">{campaign.name}</p>
              <p className="mt-1 text-xs text-slate-500">{campaign.related_incident_count} related incidents / {campaign.status}</p>
              <dl className="mt-4 space-y-3">
                <Info label="Brand" value={campaign.primary_brand || "Unknown"} />
                <Info label="Sender domain" value={campaign.primary_sender_domain || "Unknown"} />
              </dl>
            </section>
          ) : null}
          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">Triage Controls</h2>
            <Control label="Status" value={incident.status} options={statuses} onChange={(value) => updateField("status", value)} />
            <Control label="Severity" value={incident.severity} options={severities} onChange={(value) => updateField("severity", value)} />
            <Control label="Verdict" value={incident.verdict} options={verdicts} onChange={(value) => updateField("verdict", value)} />
          </section>
          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">PDF Reports</h2>
            <button className="btn-primary mt-4 w-full" type="button" onClick={generateReport}>
              <FileText size={16} />
              Generate PDF
            </button>
            <div className="mt-4 space-y-2">
              {reports.map((report) => (
                <button key={report.id} className="btn-secondary w-full" type="button" onClick={() => downloadReport(report.id)}>
                  <Download size={16} />
                  Report #{report.id}
                </button>
              ))}
            </div>
          </section>
        </aside>

        <div className="space-y-6">
          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">Email Report</h2>
            <dl className="mt-4 grid gap-4 md:grid-cols-2">
              <Info label="Reporter" value={`${incident.reporter.name} (${incident.reporter.email})`} />
              <Info label="Subject" value={incident.email_report.subject} />
              <Info label="Sender" value={incident.email_report.sender} />
              <Info label="Reason" value={incident.email_report.report_reason} />
            </dl>
          </section>

          {incident.suspected_bec ? (
            <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
              <h2 className="text-sm font-semibold text-slate-200">BEC and Payment Fraud Workflow</h2>
              <dl className="mt-4 grid gap-4 md:grid-cols-2">
                <Info label="Financial risk type" value={incident.financial_risk_type || "Not classified"} />
                <Info label="Requested amount" value={incident.requested_amount || "Not found"} />
                <Info label="Impersonated person or vendor" value={incident.impersonated_person_or_vendor || "Not found"} />
                <Info label="Workflow status" value={`${becChecklist.filter((item) => item.completed).length}/${becChecklist.length} completed`} />
              </dl>
              <div className="mt-4 grid gap-2 md:grid-cols-2">
                {becChecklist.map((item) => (
                  <label key={item.item_key} className="flex items-center gap-3 rounded-md border border-line bg-panelSoft p-3 text-sm text-slate-300">
                    <input
                      className="h-4 w-4 accent-cyan"
                      type="checkbox"
                      checked={item.completed}
                      onChange={(event) => updateBecChecklist(item.item_key, event.target.checked)}
                    />
                    {item.label}
                  </label>
                ))}
              </div>
            </section>
          ) : null}

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">
              <div className="flex items-center gap-2">
                <Bot size={18} className="text-cyan" />
                <h2 className="text-sm font-semibold text-slate-200">SOC Copilot Summary</h2>
              </div>
              <button className="btn-secondary" type="button" onClick={generateSocSummary}>
                <Bot size={16} />
                Generate SOC Summary
              </button>
            </div>
            <div className="mt-4 rounded-md border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs font-semibold text-amber-100">
              Generated from untrusted email evidence. Analyst review required.
            </div>
            {copilot ? (
              <div className="mt-4 space-y-4">
                <textarea className="input min-h-[220px]" value={summaryDraft} onChange={(event) => setSummaryDraft(event.target.value)} />
                <div className="grid gap-3 md:grid-cols-2">
                  <ListBlock title="Suggested Next Steps" items={copilot.suggested_next_steps || []} />
                  <ListBlock title="Safety Notes" items={copilot.safety_notes || []} />
                </div>
                <p className="text-sm text-slate-400">{copilot.limitations_disclaimer}</p>
              </div>
            ) : (
              <p className="mt-4 text-sm text-slate-400">Generate a deterministic analyst draft without calling external AI services.</p>
            )}
          </section>

          {explanation ? (
            <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
              <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                <div>
                  <h2 className="text-sm font-semibold text-slate-200">Why this score?</h2>
                  <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">{explanation.explanation_summary}</p>
                </div>
                <div className="grid min-w-[240px] grid-cols-3 gap-2">
                  <Metric label="Score" value={`${explanation.risk_score}/100`} />
                  <Metric label="Severity" value={explanation.severity} />
                  <Metric label="Verdict" value={explanation.verdict_suggestion} />
                </div>
              </div>

              <div className="mt-5 rounded-md border border-line bg-panelSoft p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Score Contribution</p>
                <div className="mt-3 h-[260px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={scoreBreakdown} layout="vertical" margin={{ left: 36, right: 16 }}>
                      <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
                      <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
                      <YAxis type="category" dataKey="category" stroke="#94a3b8" width={130} tick={{ fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
                      <Bar dataKey="score" fill="#22d3ee" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="mt-5 grid gap-4 xl:grid-cols-2">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Triggered Rules</h3>
                  <div className="mt-3 space-y-3">
                    {explanationRules.map((rule, index) => (
                      <div key={`${rule.name}-${index}`} className="rounded-md border border-line bg-panelSoft p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="font-semibold text-white">{rule.name}</p>
                            <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{rule.category} / {rule.evidence_type}</p>
                          </div>
                          <span className="rounded-md border border-cyan/30 bg-cyan/10 px-2 py-1 text-sm font-semibold text-cyan">+{rule.score_impact}</span>
                        </div>
                        <p className="mt-2 break-words font-mono text-xs text-slate-300">{rule.matched_value}</p>
                        <p className="mt-2 text-sm text-slate-400">{rule.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Evidence Timeline</h3>
                  <div className="mt-3 space-y-3">
                    {evidenceItems.map((item, index) => (
                      <div key={`${item.rule_name}-${index}`} className="grid grid-cols-[28px_1fr] gap-3">
                        <div className="grid h-7 w-7 place-items-center rounded-md border border-line bg-[#07111d] text-xs font-semibold text-cyan">{index + 1}</div>
                        <div className="rounded-md border border-line bg-panelSoft p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="font-semibold text-white">{item.rule_name}</p>
                              <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{item.type}</p>
                            </div>
                            <span className="text-sm font-semibold text-cyan">+{item.score_impact}</span>
                          </div>
                          <p className="mt-2 break-words font-mono text-xs text-slate-300">{item.matched_value}</p>
                          <p className="mt-2 text-sm text-slate-400">{item.reason}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          ) : null}

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <div className="flex items-center gap-2">
              <Map size={18} className="text-cyan" />
              <h2 className="text-sm font-semibold text-slate-200">MITRE ATT&CK and NIST Mapping</h2>
            </div>
            <div className="mt-4 grid gap-3 xl:grid-cols-2">
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Framework Mappings</p>
                {frameworkMappings.map((item) => (
                  <div key={item.id} className="rounded-md border border-line bg-panelSoft p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-semibold text-white">{item.technique_id} {item.technique_name}</p>
                        <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{item.framework} / {item.tactic}</p>
                      </div>
                      <span className="text-sm font-semibold text-cyan">{item.confidence}%</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-400">{item.reason}</p>
                  </div>
                ))}
                {!frameworkMappings.length ? <p className="text-sm text-slate-500">No framework mappings are available for this incident yet.</p> : null}
              </div>
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">NIST Lifecycle</p>
                {nistLifecycle.map((item) => (
                  <div key={item.phase} className="rounded-md border border-line bg-panelSoft p-3">
                    <p className="font-semibold text-white">{item.phase}</p>
                    <p className="mt-1 text-sm text-slate-400">{item.recommended_work}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {brandEvidence.length ? (
            <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
              <h2 className="text-sm font-semibold text-slate-200">Brand Impersonation</h2>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {brandEvidence.map((item, index) => (
                  <div key={`${item.rule_name}-${index}`} className="rounded-md border border-line bg-panelSoft p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-semibold text-white">{item.rule_name}</p>
                        <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{item.type}</p>
                      </div>
                      <span className="text-sm font-semibold text-cyan">+{item.score_impact}</span>
                    </div>
                    <p className="mt-2 break-words font-mono text-xs text-slate-300">{item.matched_value}</p>
                    <p className="mt-2 text-sm text-slate-400">{item.reason}</p>
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">Indicators of Compromise</h2>
            {qrIndicators.length ? (
              <Notice>Payload extracted safely. Link was not visited.</Notice>
            ) : null}
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {iocs.map((ioc) => (
                <div key={ioc.id} className="rounded-md border border-line bg-panelSoft p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-500">{ioc.type} from {ioc.source}</p>
                  <p className="mt-1 break-words font-mono text-sm text-slate-100">{ioc.value}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <div className="flex items-center justify-between gap-4">
              <h2 className="text-sm font-semibold text-slate-200">Threat Enrichment</h2>
              <button className="btn-secondary" type="button" onClick={enrichIncident}>
                <ShieldCheck size={16} />
                Enrich
              </button>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {enrichments.map((item) => (
                <div key={item.id} className="rounded-md border border-line bg-panelSoft p-3">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-xs uppercase tracking-wide text-slate-500">{item.indicator_type}</p>
                    <Badge value={item.reputation === "Suspicious" ? "High" : item.reputation === "Unrated" ? "Medium" : "Low"} />
                  </div>
                  <p className="mt-2 break-words font-mono text-sm text-slate-100">{item.indicator_value}</p>
                  <p className="mt-2 text-xs text-slate-400">{item.provider} / {item.confidence}% confidence</p>
                  <p className="mt-2 text-sm text-slate-300">{item.details}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">
              <div className="flex items-center gap-2">
                <Play size={18} className="text-cyan" />
                <h2 className="text-sm font-semibold text-slate-200">Playbooks</h2>
              </div>
              <div className="inline-flex rounded-md border border-line bg-panelSoft p-1">
                <button
                  className={`rounded px-3 py-1.5 text-sm font-semibold ${playbookTab === "templates" ? "bg-cyan text-slate-950" : "text-slate-300"}`}
                  type="button"
                  onClick={() => setPlaybookTab("templates")}
                >
                  Templates
                </button>
                <button
                  className={`rounded px-3 py-1.5 text-sm font-semibold ${playbookTab === "runs" ? "bg-cyan text-slate-950" : "text-slate-300"}`}
                  type="button"
                  onClick={() => setPlaybookTab("runs")}
                >
                  Audit Trail
                </button>
              </div>
            </div>

            {playbookTab === "templates" ? (
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {(playbookData.templates || []).map((template) => (
                  <div key={template.id} className="rounded-md border border-line bg-panelSoft p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-semibold text-white">{template.name}</p>
                        <p className="mt-1 text-sm text-slate-400">{template.description}</p>
                      </div>
                      <button className="btn-secondary shrink-0" type="button" onClick={() => runPlaybook(template.id)}>
                        <Play size={14} />
                        Simulate
                      </button>
                    </div>
                    <p className="mt-2 text-xs uppercase tracking-wide text-slate-500">
                      {template.requires_integration_type ? `${template.requires_integration_type} integration optional` : "Internal workflow"}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4 space-y-3">
                {(playbookData.runs || []).map((run) => (
                  <div key={run.id} className="rounded-md border border-line bg-panelSoft p-3">
                    <div className="flex flex-col justify-between gap-2 md:flex-row md:items-center">
                      <div>
                        <p className="font-semibold text-white">{run.name}</p>
                        <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{run.status} / {run.mode}</p>
                      </div>
                      <span className="text-xs text-slate-500">{new Date(run.created_at).toLocaleString()}</span>
                    </div>
                    <div className="mt-3 space-y-2">
                      {(run.action_results || []).map((result, index) => (
                        <div key={`${run.id}-${index}`} className="rounded border border-line bg-[#07111d] p-3">
                          <p className="font-semibold text-slate-200">{result.action}</p>
                          <p className="mt-1 text-sm text-slate-400">{result.result}</p>
                          <p className="mt-1 text-xs text-slate-500">{result.integration_note}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {!playbookData.runs?.length ? <p className="text-sm text-slate-500">No simulated playbooks have been run yet.</p> : null}
              </div>
            )}
          </section>

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">Triggered Rules</h2>
            <div className="mt-4 space-y-3">
              {triggeredRules.map((rule) => (
                <div key={rule.id} className="rounded-md border border-line bg-panelSoft p-3">
                  <p className="font-semibold text-white">{rule.rule_name} <span className="text-cyan">+{rule.score_added}</span></p>
                  <p className="mt-1 text-sm text-slate-400">{rule.evidence}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <h2 className="text-sm font-semibold text-slate-200">Analyst Notes</h2>
            <form onSubmit={addNote} className="mt-4 flex gap-3">
              <input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add investigation note" />
              <button className="btn-primary" type="submit" aria-label="Add note">
                <MessageSquarePlus size={18} />
              </button>
            </form>
            <div className="mt-4 space-y-3">
              {notes.map((item) => (
                <div key={item.id} className="rounded-md border border-line bg-panelSoft p-3">
                  <p className="text-sm text-slate-200">{item.note}</p>
                  <p className="mt-2 text-xs text-slate-500">{item.analyst_name} - {new Date(item.created_at).toLocaleString()}</p>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function Control({ label, value, options, onChange }) {
  return (
    <label className="mt-4 block text-sm font-medium text-slate-300">
      {label}
      <select className="input mt-2" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>{option}</option>
        ))}
      </select>
    </label>
  );
}

function Info({ label, value }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 break-words text-sm text-slate-100">{value}</dd>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-md border border-line bg-panelSoft p-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-white">{value}</p>
    </div>
  );
}

function ListBlock({ title, items }) {
  return (
    <div className="rounded-md border border-line bg-panelSoft p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</p>
      <ul className="mt-2 space-y-2 text-sm text-slate-300">
        {items.map((item, index) => (
          <li key={`${item}-${index}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function formatCopilotSummary(summary) {
  return [
    "Analyst summary",
    summary.analyst_summary,
    "",
    "User-friendly explanation",
    summary.user_friendly_explanation,
    "",
    "Containment checklist",
    ...(summary.containment_checklist || []).map((item) => `- ${item}`),
    "",
    "Limitations",
    summary.limitations_disclaimer
  ].join("\n");
}
