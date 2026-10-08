import { ShieldPlus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { apiError } from "../services/api";

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await register(form);
      setMessage("Employee account created. You can log in now.");
      setTimeout(() => navigate("/login"), 700);
    } catch (err) {
      setError(apiError(err));
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-surface p-5">
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-lg border border-line bg-panel p-6 shadow-glow">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-md bg-cyan p-2 text-slate-950">
            <ShieldPlus size={22} />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-white">Create employee account</h1>
            <p className="text-sm text-slate-400">Reports are routed to SOC analysts.</p>
          </div>
        </div>
        {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-400/10 p-3 text-sm text-red-100">{error}</p> : null}
        {message ? <p className="mb-4 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-100">{message}</p> : null}
        <label className="text-sm font-medium text-slate-300">
          Name
          <input className="input mt-2" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </label>
        <label className="mt-4 block text-sm font-medium text-slate-300">
          Email
          <input className="input mt-2" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </label>
        <label className="mt-4 block text-sm font-medium text-slate-300">
          Password
          <input className="input mt-2" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </label>
        <button className="btn-primary mt-6 w-full" type="submit">Register</button>
        <p className="mt-4 text-center text-sm text-slate-400">
          Already registered? <Link className="text-cyan hover:underline" to="/login">Login</Link>
        </p>
      </form>
    </main>
  );
}
