import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem("phishguard_user");
    if (!stored) return null;
    try {
      return JSON.parse(stored);
    } catch {
      localStorage.removeItem("phishguard_user");
      localStorage.removeItem("phishguard_token");
      return null;
    }
  });
  const [loading, setLoading] = useState(Boolean(localStorage.getItem("phishguard_token")));

  useEffect(() => {
    async function refreshUser() {
      const token = localStorage.getItem("phishguard_token");
      if (!token) {
        localStorage.removeItem("phishguard_user");
        setUser(null);
        setLoading(false);
        return;
      }
      try {
        const response = await api.get("/auth/me");
        setUser(response.data);
        localStorage.setItem("phishguard_user", JSON.stringify(response.data));
      } catch {
        localStorage.removeItem("phishguard_token");
        localStorage.removeItem("phishguard_user");
        setUser(null);
      } finally {
        setLoading(false);
      }
    }
    refreshUser();
  }, []);

  async function login(email, password) {
    const response = await api.post("/auth/login", { email, password });
    localStorage.setItem("phishguard_token", response.data.access_token);
    localStorage.setItem("phishguard_user", JSON.stringify(response.data.user));
    setUser(response.data.user);
    return response.data.user;
  }

  async function register(payload) {
    const response = await api.post("/auth/register", payload);
    return response.data;
  }

  function logout() {
    localStorage.removeItem("phishguard_token");
    localStorage.removeItem("phishguard_user");
    setUser(null);
  }

  const value = useMemo(() => ({ user, loading, login, register, logout }), [user, loading]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
