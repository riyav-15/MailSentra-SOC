import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ roles, children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="min-h-screen bg-surface p-8 text-slate-300">Loading session...</div>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (roles && !roles.includes(user.role)) {
    const fallback = user.role === "admin" ? "/admin" : user.role === "analyst" ? "/soc" : "/employee";
    return <Navigate to={fallback} replace />;
  }

  return children;
}
