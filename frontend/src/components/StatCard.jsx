export default function StatCard({ icon: Icon, label, value, accent = "text-cyan" }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4 shadow-glow">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</p>
          <p className="mt-2 text-3xl font-semibold text-slate-50">{value ?? 0}</p>
        </div>
        {Icon ? (
          <div className={`rounded-md border border-line bg-panelSoft p-3 ${accent}`}>
            <Icon size={22} />
          </div>
        ) : null}
      </div>
    </div>
  );
}
