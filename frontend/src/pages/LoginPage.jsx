import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { apiError } from "../services/api";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "admin@phishguard.local", password: "AdminPass123!" });
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    try {
      const user = await login(form.email, form.password);
      navigate(user.role === "admin" ? "/admin" : user.role === "analyst" ? "/soc" : "/employee");
    } catch (err) {
      setError(apiError(err));
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-surface p-5">
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-lg border border-line bg-panel p-6 shadow-glow">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-md bg-cyan p-2 text-slate-950">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-white">PhishGuard SOC</h1>
            <p className="text-sm text-slate-400">Secure console login</p>
          </div>
        </div>
        {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-400/10 p-3 text-sm text-red-100">{error}</p> : null}
        <label className="text-sm font-medium text-slate-300">
          Email
          <input className="input mt-2" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </label>
        <label className="mt-4 block text-sm font-medium text-slate-300">
          Password
          <input className="input mt-2" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </label>
        <button className="btn-primary mt-6 w-full" type="submit">Login</button>
        <p className="mt-4 text-center text-sm text-slate-400">
          Need an employee account? <Link className="text-cyan hover:underline" to="/register">Register</Link>
        </p>
      </form>
    </main>
  );
}
