import {
  Activity,
  ClipboardList,
  FileArchive,
  FileSearch,
  GitBranch,
  Home,
  Info,
  ListChecks,
  LogOut,
  Radar,
  ScrollText,
  Settings,
  ShieldCheck,
  Users
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const navByRole = {
  employee: [
    { to: "/employee", label: "Dashboard", icon: Home },
    { to: "/submit", label: "Submit Email", icon: FileSearch },
    { to: "/my-reports", label: "My Reports", icon: ClipboardList },
    { to: "/about", label: "About", icon: Info }
  ],
  analyst: [
    { to: "/soc", label: "SOC Dashboard", icon: Radar },
    { to: "/enterprise", label: "Enterprise Ops", icon: ShieldCheck },
    { to: "/campaigns", label: "Campaigns", icon: GitBranch },
    { to: "/incidents", label: "Incidents", icon: ListChecks },
    { to: "/about", label: "About", icon: Info }
  ],
  admin: [
    { to: "/admin", label: "Admin Dashboard", icon: Activity },
    { to: "/admin/executive", label: "Executive", icon: Radar },
    { to: "/incidents", label: "Incidents", icon: ListChecks },
    { to: "/campaigns", label: "Campaigns", icon: GitBranch },
    { to: "/admin/users", label: "Users", icon: Users },
    { to: "/admin/rules", label: "Rules", icon: Settings },
    { to: "/admin/brands", label: "Brands", icon: ShieldCheck },
    { to: "/enterprise", label: "Enterprise Ops", icon: ShieldCheck },
    { to: "/admin/integrations", label: "Integrations", icon: Settings },
    { to: "/admin/reports", label: "Reports", icon: FileArchive },
    { to: "/admin/audit-logs", label: "Audit Logs", icon: ScrollText },
    { to: "/about", label: "About", icon: Info }
  ]
};

export default function Layout({ children }) {
  const { user, logout } = useAuth();
  const navItems = navByRole[user?.role] || navByRole.employee;

  return (
    <div className="min-h-screen bg-surface text-slate-100">
      <div className="grid min-h-screen lg:grid-cols-[260px_1fr]">
        <aside className="border-r border-line bg-[#060d18]/95 px-4 py-5">
          <div className="flex items-center gap-3 px-2">
            <div className="rounded-md bg-cyan p-2 text-slate-950">
              <ShieldCheck size={24} />
            </div>
            <div>
              <p className="text-lg font-semibold text-white">PhishGuard SOC</p>
              <p className="text-xs uppercase tracking-wide text-slate-500">Defensive Triage</p>
            </div>
          </div>

          <nav className="mt-8 grid gap-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition ${
                    isActive ? "bg-cyan/10 text-cyan" : "text-slate-400 hover:bg-panelSoft hover:text-slate-100"
                  }`
                }
              >
                <item.icon size={18} />
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className="soc-grid min-w-0">
          <header className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-[#060d18]/90 px-5 py-3 backdrop-blur">
            <div>
              <p className="text-sm font-semibold text-white">{user?.name}</p>
              <p className="text-xs uppercase tracking-wide text-slate-500">{user?.role}</p>
            </div>
            <button className="btn-secondary" onClick={logout} type="button">
              <LogOut size={16} />
              Logout
            </button>
          </header>
          <div className="p-4 sm:p-6 lg:p-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
