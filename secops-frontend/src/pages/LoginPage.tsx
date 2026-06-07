import { useState } from "react";
import { Shield, AlertCircle, Eye, EyeOff, Lock, User } from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { useLocation } from "wouter";

export default function LoginPage() {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { login, isLoading } = useAuthStore();
  const [, setLocation] = useLocation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login(identifier, password);
      setLocation("/");
    } catch (err: any) {
      setError(err?.response?.data?.error ?? "Login failed. Check your credentials.");
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-card border border-border/50 mb-4 shadow-lg">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-2xl font-bold text-foreground">SecOps Console</h1>
          <p className="text-muted-foreground text-sm mt-1">SOC Platform — Secure Sign In</p>
        </div>

        <div className="bg-card border border-border rounded-2xl p-8 shadow-xl">
          <h2 className="text-lg font-semibold text-foreground mb-6">Sign in to your account</h2>

          {error && (
            <div className="flex items-start gap-3 bg-destructive/10 border border-destructive/30 rounded-lg px-4 py-3 mb-5">
              <AlertCircle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
              <p className="text-sm text-destructive">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-sm font-medium text-foreground block mb-1.5">
                Username or Email
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className="w-full bg-background border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
                  placeholder="admin or admin@secops.local"
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-foreground block mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-background border border-border rounded-lg pl-10 pr-10 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-primary hover:bg-primary/90 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold rounded-lg py-2.5 transition-colors mt-2"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : "Sign In"}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-border/50">
            <p className="text-xs text-muted-foreground text-center mb-3">Demo Credentials</p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: "Admin",        color: "text-red-400",    user: "admin",  pass: "Admin@SecOps1!" },
                { label: "SOC Manager",  color: "text-purple-400", user: "morgan", pass: "Manager@1234!" },
                { label: "Det. Engineer",color: "text-amber-400",  user: "elena",  pass: "Engineer@1234!" },
                { label: "SOC L2",       color: "text-primary",    user: "alice",  pass: "Analyst@1234!" },
                { label: "SOC L1",       color: "text-green-400",  user: "bob",    pass: "Analyst@1234!" },
                { label: "Viewer",       color: "text-muted-foreground", user: "viewer", pass: "Viewer@1234!" },
              ].map(({ label, color, user, pass }) => (
                <button
                  key={user}
                  type="button"
                  onClick={() => { setIdentifier(user); setPassword(pass); }}
                  className="text-left px-3 py-2 bg-background border border-border/50 hover:border-primary/50 rounded-lg transition-colors group"
                >
                  <div className={`text-xs font-medium ${color}`}>{label}</div>
                  <div className="text-xs text-muted-foreground">{user}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground mt-6">
          SecOps Console · SOC Platform · Confidential
        </p>
      </div>
    </div>
  );
}
