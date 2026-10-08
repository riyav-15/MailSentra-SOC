import { ArrowRight, Building2, Clock3, Database, FileSearch, LockKeyhole, Radar, ShieldCheck, Users } from "lucide-react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const features = [
  ["Threat enrichment", "Local defensive reputation for domains, URLs, IPs, and attachment hashes.", Database],
  ["SLA queues", "Priority routing, campaign labels, ownership, and breach visibility.", Clock3],
  ["Enterprise identity", "SSO configuration records for OIDC and SAML customer tenants.", Users],
  ["Gateway intake", "Reporting-button integration points for Microsoft 365 and Google Workspace.", FileSearch],
  ["SIEM export", "JSON, webhook, and syslog export queues for SOC pipelines.", Radar],
  ["Evidence reports", "Investigation notes, IOCs, verdicts, and PDF incident records.", LockKeyhole]
];

const plans = [
  ["Starter", "$49", "Small teams validating suspicious email workflows."],
  ["SOC Team", "$149", "Queue SLAs, enrichment, integrations, and incident reporting."],
  ["Enterprise", "Custom", "SSO, gateway intake, SIEM export, support, and deployment help."]
];

export default function LandingPage() {
  const { user } = useAuth();
  const home = user?.role === "admin" ? "/admin" : user?.role === "analyst" ? "/soc" : "/employee";

  return (
    <main className="min-h-screen bg-surface text-slate-100">
      <section className="soc-grid px-5 py-6">
        <nav className="mx-auto flex max-w-7xl items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-md bg-cyan p-2 text-slate-950">
              <ShieldCheck size={24} />
            </div>
            <span className="text-lg font-semibold">PhishGuard SOC</span>
          </div>
          <div className="flex gap-2">
            <Link className="btn-secondary" to="/login">Login</Link>
            <Link className="btn-primary" to={user ? home : "/register"}>{user ? "Open Console" : "Start Trial"}</Link>
          </div>
        </nav>

        <div className="mx-auto grid max-w-7xl items-center gap-10 py-14 lg:grid-cols-[0.9fr_1.1fr]">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-cyan">Commercial phishing defense platform</p>
            <h1 className="mt-4 max-w-3xl text-5xl font-semibold text-white sm:text-6xl">PhishGuard SOC</h1>
            <p className="mt-5 max-w-2xl text-lg leading-8 text-slate-300">
              Launch a paid defensive security service for suspicious email reporting, SOC triage, threat enrichment, SLA operations, and customer-ready reporting.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link className="btn-primary" to={user ? home : "/register"}>
                Start trial
                <ArrowRight size={18} />
              </Link>
              <Link className="btn-secondary" to="/login">Customer login</Link>
            </div>
            <div className="mt-8 grid max-w-xl grid-cols-3 gap-3">
              {[
                ["99.9%", "hosting target"],
                ["8h", "default high SLA"],
                ["3", "export formats"]
              ].map((item) => (
                <div key={item[1]} className="rounded-md border border-line bg-panel/80 p-3">
                  <p className="text-2xl font-semibold text-white">{item[0]}</p>
                  <p className="text-xs uppercase tracking-wide text-slate-500">{item[1]}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-line bg-panel p-4 shadow-glow">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Revenue Console Preview</p>
                <p className="text-xs text-slate-500">SOC Team workspace</p>
              </div>
              <span className="rounded-md border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-xs font-semibold text-emerald-100">Active tenant</span>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {[
                { label: "Reports", value: "12.4k", icon: FileSearch, color: "text-cyan" },
                { label: "MRR", value: "$8.6k", icon: Building2, color: "text-success" },
                { label: "SLA risk", value: "4", icon: Radar, color: "text-warning" }
              ].map((item) => (
                <div key={item.label} className="rounded-md border border-line bg-panelSoft p-4">
                  <item.icon className={item.color} size={22} />
                  <p className="mt-4 text-2xl font-semibold text-white">{item.value}</p>
                  <p className="text-sm text-slate-400">{item.label}</p>
                </div>
              ))}
            </div>
            <div className="mt-4 rounded-md border border-line bg-[#07111d] p-4">
              <div className="mb-3 flex items-center justify-between text-sm">
                <span className="font-semibold text-white">Enterprise queue</span>
                <span className="text-cyan">Enrichment active</span>
              </div>
              {[
                ["INC-2042", "Microsoft credential lure", "Critical", "92"],
                ["INC-2038", "Vendor payment change", "High", "76"],
                ["INC-2035", "DocuSign impersonation", "Medium", "54"]
              ].map((row) => (
                <div key={row[0]} className="grid grid-cols-[90px_1fr_80px_48px] gap-3 border-t border-line py-3 text-sm">
                  <span className="font-mono text-slate-400">{row[0]}</span>
                  <span className="truncate text-slate-200">{row[1]}</span>
                  <span className="text-slate-300">{row[2]}</span>
                  <span className="text-right font-semibold text-cyan">{row[3]}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="border-t border-line bg-[#07111d] px-5 py-12">
        <div className="mx-auto max-w-7xl">
          <h2 className="text-2xl font-semibold text-white">Built for paid defensive operations</h2>
          <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {features.map(([title, copy, Icon]) => (
              <article key={title} className="rounded-lg border border-line bg-panel p-5">
                <Icon className="text-cyan" size={22} />
                <h3 className="mt-4 font-semibold text-white">{title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">{copy}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-line px-5 py-12">
        <div className="mx-auto max-w-7xl">
          <h2 className="text-2xl font-semibold text-white">Pricing model</h2>
          <div className="mt-6 grid gap-4 lg:grid-cols-3">
            {plans.map(([name, price, copy]) => (
              <article key={name} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
                <p className="text-sm font-semibold uppercase tracking-wide text-cyan">{name}</p>
                <p className="mt-3 text-4xl font-semibold text-white">{price}</p>
                <p className="mt-3 min-h-[48px] text-sm leading-6 text-slate-400">{copy}</p>
                <Link className="btn-primary mt-5 w-full" to={user ? home : "/register"}>Choose plan</Link>
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
