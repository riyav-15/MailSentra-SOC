const variants = {
  Low: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  Medium: "border-yellow-400/30 bg-yellow-400/10 text-yellow-100",
  High: "border-orange-400/30 bg-orange-400/10 text-orange-100",
  Critical: "border-red-400/30 bg-red-400/10 text-red-100",
  New: "border-cyan/30 bg-cyan/10 text-cyan",
  "In Review": "border-blue-400/30 bg-blue-400/10 text-blue-100",
  Escalated: "border-orange-400/30 bg-orange-400/10 text-orange-100",
  Closed: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  Safe: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  Spam: "border-yellow-400/30 bg-yellow-400/10 text-yellow-100",
  Suspicious: "border-orange-400/30 bg-orange-400/10 text-orange-100",
  "Likely Phishing": "border-red-400/30 bg-red-400/10 text-red-100",
  "Confirmed Phishing": "border-red-500/40 bg-red-500/15 text-red-100"
};

export default function Badge({ value }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-semibold ${variants[value] || variants.New}`}>
      {value}
    </span>
  );
}
