import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const colors = ["#22d3ee", "#22c55e", "#f59e0b", "#ef4444", "#60a5fa", "#a78bfa"];

export default function DashboardCharts({ summary }) {
  const severity = summary?.by_severity || [];
  const status = summary?.by_status || [];
  const rules = summary?.top_triggered_rules || [];
  const brands = summary?.top_impersonated_brands || [];

  return (
    <div className="grid gap-4 xl:grid-cols-2 2xl:grid-cols-4">
      <ChartPanel title="Severity Mix">
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie data={severity} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}>
              {severity.map((_, index) => (
                <Cell key={index} fill={colors[index % colors.length]} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
          </PieChart>
        </ResponsiveContainer>
      </ChartPanel>

      <ChartPanel title="Status Volume">
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={status}>
            <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
            <XAxis dataKey="name" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" allowDecimals={false} />
            <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
            <Bar dataKey="value" fill="#22d3ee" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartPanel>

      <ChartPanel title="Top Triggered Rules">
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={rules} layout="vertical" margin={{ left: 40 }}>
            <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
            <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
            <YAxis type="category" dataKey="name" stroke="#94a3b8" width={120} tick={{ fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
            <Bar dataKey="value" fill="#22c55e" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartPanel>

      <ChartPanel title="Top Impersonated Brands">
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={brands} layout="vertical" margin={{ left: 40 }}>
            <CartesianGrid stroke="#1f334c" strokeDasharray="3 3" />
            <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
            <YAxis type="category" dataKey="name" stroke="#94a3b8" width={120} tick={{ fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "#0d1728", border: "1px solid #1f334c", color: "#fff" }} />
            <Bar dataKey="value" fill="#f59e0b" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </ChartPanel>
    </div>
  );
}

function ChartPanel({ title, children }) {
  return (
    <section className="rounded-lg border border-line bg-panel p-4 shadow-glow">
      <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
      <div className="mt-3">{children}</div>
    </section>
  );
}
