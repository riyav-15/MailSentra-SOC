import { FileText, LockKeyhole, ShieldCheck, TriangleAlert } from "lucide-react";

export default function AboutPage() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">About PhishGuard SOC</h1>
        <p className="mt-1 text-sm text-slate-400">A defensive phishing operations platform for hosted SOC workflows and customer workspaces.</p>
      </header>
      <div className="grid gap-4 md:grid-cols-2">
        {[
          {
            icon: ShieldCheck,
            title: "Defensive analysis",
            text: "The platform analyzes user-submitted email text and metadata without sending mail, collecting credentials, opening links, or executing attachments."
          },
          {
            icon: FileText,
            title: "Incident reporting",
            text: "Every report becomes a structured case with extracted IOCs, triggered rules, SOC notes, status, severity, verdict, and PDF output."
          },
          {
            icon: LockKeyhole,
            title: "Role-based access",
            text: "Employees submit and view their own reports. Analysts triage incidents. Admins manage users, detection rules, reports, and audit logs."
          },
          {
            icon: TriangleAlert,
            title: "Enterprise operations",
            text: "Queues, SLAs, enrichment, SSO records, gateway integrations, campaign import, and SIEM exports support paid defensive service delivery."
          }
        ].map((item) => (
          <section key={item.title} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <item.icon className="text-cyan" size={24} />
            <h2 className="mt-4 text-lg font-semibold text-white">{item.title}</h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">{item.text}</p>
          </section>
        ))}
      </div>
      <section className="rounded-lg border border-line bg-panel p-5 shadow-glow">
        <h2 className="text-lg font-semibold text-white">Security Disclaimer</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          PhishGuard SOC is for authorized defensive analysis only. It does not create phishing pages, send phishing messages, collect credentials, execute files, or attack external systems.
        </p>
      </section>
    </div>
  );
}
