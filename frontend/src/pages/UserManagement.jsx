import { useEffect, useState } from "react";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

const roles = ["employee", "analyst", "admin"];

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");

  async function loadUsers() {
    try {
      const response = await api.get("/admin/users");
      setUsers(response.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function updateRole(userId, role) {
    setError("");
    try {
      await api.patch(`/admin/users/${userId}/role`, { role });
      await loadUsers();
    } catch (err) {
      setError(apiError(err));
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">User Management</h1>
        <p className="mt-1 text-sm text-slate-400">Manage employee, analyst, and admin access.</p>
      </header>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <section className="overflow-hidden rounded-lg border border-line bg-panel shadow-glow">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-panelSoft text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Email</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {users.map((user) => (
                <tr key={user.id} className="hover:bg-panelSoft/60">
                  <td className="px-4 py-3 font-medium text-white">{user.name}</td>
                  <td className="px-4 py-3 text-slate-300">{user.email}</td>
                  <td className="px-4 py-3">
                    <select className="input max-w-[160px]" value={user.role} onChange={(event) => updateRole(user.id, event.target.value)}>
                      {roles.map((role) => <option key={role} value={role}>{role}</option>)}
                    </select>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{new Date(user.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
