import { Save } from "lucide-react";
import { useEffect, useState } from "react";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

export default function RuleManagement() {
  const [rules, setRules] = useState([]);
  const [error, setError] = useState("");

  async function loadRules() {
    try {
      const response = await api.get("/admin/rules");
      setRules(response.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadRules();
  }, []);

  async function patchRule(ruleId, payload) {
    setError("");
    try {
      await api.patch(`/admin/rules/${ruleId}`, payload);
      await loadRules();
    } catch (err) {
      setError(apiError(err));
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Detection Rules</h1>
        <p className="mt-1 text-sm text-slate-400">Enable, disable, and tune rule weights for future submissions.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <section className="overflow-hidden rounded-lg border border-line bg-panel shadow-glow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Enabled</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Weight</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.map((rule) => (
                <RuleRow key={rule.id} rule={rule} patchRule={patchRule} />
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function RuleRow({ rule, patchRule }) {
  const [weight, setWeight] = useState(rule.severity_weight);

  return (
    <tr className="hover:bg-panelSoft/60">
      <td className="px-4 py-3">
        <input
          className="h-5 w-5 accent-cyan"
          type="checkbox"
          checked={rule.enabled}
          onChange={(event) => patchRule(rule.id, { enabled: event.target.checked })}
          aria-label={`Toggle ${rule.name}`}
        />
      </td>
      <td className="px-4 py-3 font-semibold text-white">{rule.name}</td>
      <td className="px-4 py-3 text-slate-400">{rule.description}</td>
      <td className="px-4 py-3">
        <input className="input max-w-[110px]" type="number" min="0" max="40" value={weight} onChange={(event) => setWeight(event.target.value)} />
      </td>
      <td className="px-4 py-3">
        <button className="btn-secondary" type="button" onClick={() => patchRule(rule.id, { severity_weight: Number(weight) })}>
          <Save size={16} />
          Save
        </button>
      </td>
    </tr>
  );
}
