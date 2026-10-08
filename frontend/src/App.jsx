import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import { useAuth } from "./context/AuthContext";
import AboutPage from "./pages/AboutPage";
import AdminDashboard from "./pages/AdminDashboard";
import AuditLogsPage from "./pages/AuditLogsPage";
import BrandWatchlistPage from "./pages/BrandWatchlistPage";
import CampaignsPage from "./pages/CampaignsPage";
import EmployeeDashboard from "./pages/EmployeeDashboard";
import EnterpriseOperations from "./pages/EnterpriseOperations";
import ExecutiveDashboard from "./pages/ExecutiveDashboard";
import IncidentDetails from "./pages/IncidentDetails";
import IncidentList from "./pages/IncidentList";
import IntegrationsPage from "./pages/IntegrationsPage";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import MyReports from "./pages/MyReports";
import RegisterPage from "./pages/RegisterPage";
import ReportsPage from "./pages/ReportsPage";
import RuleManagement from "./pages/RuleManagement";
import SOCDashboard from "./pages/SOCDashboard";
import SubmitReport from "./pages/SubmitReport";
import UserManagement from "./pages/UserManagement";

function RoleHome() {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (user.role === "admin") return <Navigate to="/admin" replace />;
  if (user.role === "analyst") return <Navigate to="/soc" replace />;
  return <Navigate to="/employee" replace />;
}

function AppShell({ roles, children }) {
  return (
    <ProtectedRoute roles={roles}>
      <Layout>{children}</Layout>
    </ProtectedRoute>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/home" element={<RoleHome />} />

      <Route path="/employee" element={<AppShell roles={["employee"]}><EmployeeDashboard /></AppShell>} />
      <Route path="/submit" element={<AppShell roles={["employee"]}><SubmitReport /></AppShell>} />
      <Route path="/my-reports" element={<AppShell roles={["employee"]}><MyReports /></AppShell>} />

      <Route path="/soc" element={<AppShell roles={["analyst", "admin"]}><SOCDashboard /></AppShell>} />
      <Route path="/enterprise" element={<AppShell roles={["analyst", "admin"]}><EnterpriseOperations /></AppShell>} />
      <Route path="/campaigns" element={<AppShell roles={["analyst", "admin"]}><CampaignsPage /></AppShell>} />
      <Route path="/incidents" element={<AppShell roles={["analyst", "admin"]}><IncidentList /></AppShell>} />
      <Route path="/incidents/:incidentId" element={<AppShell roles={["analyst", "admin"]}><IncidentDetails /></AppShell>} />

      <Route path="/admin" element={<AppShell roles={["admin"]}><AdminDashboard /></AppShell>} />
      <Route path="/admin/executive" element={<AppShell roles={["admin"]}><ExecutiveDashboard /></AppShell>} />
      <Route path="/admin/users" element={<AppShell roles={["admin"]}><UserManagement /></AppShell>} />
      <Route path="/admin/rules" element={<AppShell roles={["admin"]}><RuleManagement /></AppShell>} />
      <Route path="/admin/brands" element={<AppShell roles={["admin"]}><BrandWatchlistPage /></AppShell>} />
      <Route path="/admin/integrations" element={<AppShell roles={["admin"]}><IntegrationsPage /></AppShell>} />
      <Route path="/admin/reports" element={<AppShell roles={["admin"]}><ReportsPage /></AppShell>} />
      <Route path="/admin/audit-logs" element={<AppShell roles={["admin"]}><AuditLogsPage /></AppShell>} />

      <Route path="/about" element={<AppShell roles={["employee", "analyst", "admin"]}><AboutPage /></AppShell>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
