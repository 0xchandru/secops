import { Switch, Route, Router as WouterRouter, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useEffect } from "react";
import { useAuthStore } from "@/store/authStore";
import type { Permission } from "@/store/authStore";
import { ErrorBoundary } from "@/components/ErrorBoundary";

// Pages
import { MainLayout } from "@/components/layout/MainLayout";
import DashboardPage from "@/pages/DashboardPage";
import LogsExplorerPage from "@/pages/LogsExplorerPage";
import AlertQueuePage from "@/pages/AlertQueuePage";
import AlertDetailPage from "@/pages/AlertDetailPage";
import DetectionRulesPage from "@/pages/DetectionRulesPage";
import RuleBuilderPage from "@/pages/RuleBuilderPage";
import MitreAttackPage from "@/pages/MitreAttackPage";
import LogIngestionPage from "@/pages/LogIngestionPage";
import SettingsPage from "@/pages/SettingsPage";
import LoginPage from "@/pages/LoginPage";
import UserManagementPage from "@/pages/UserManagementPage";
import AuditLogPage from "@/pages/AuditLogPage";
import AssetsPage from "@/pages/AssetsPage";
import NotFound from "@/pages/not-found";

const queryClient = new QueryClient();

function ProtectedRoute({ component: Component, permission }: { component: React.ComponentType; permission?: Permission }) {
  const { isAuthenticated, isInitialized, can } = useAuthStore();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (isInitialized && !isAuthenticated) {
      setLocation("/login");
    }
  }, [isAuthenticated, isInitialized, setLocation]);

  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) return null;

  if (permission && !can(permission)) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground flex-col gap-2">
        <p className="font-medium">Access Denied</p>
        <p className="text-sm">Your role does not have permission to view this page.</p>
      </div>
    );
  }
  return <Component />;
}

function AuthInit({ children }: { children: React.ReactNode }) {
  const restoreSession = useAuthStore((s) => s.restoreSession);
  const isInitialized = useAuthStore((s) => s.isInitialized);
  useEffect(() => {
    if (!isInitialized) {
      restoreSession();
    }
  }, [restoreSession, isInitialized]);
  return <>{children}</>;
}

function Router() {
  const { isAuthenticated, isInitialized } = useAuthStore();

  return (
    <Switch>
      <Route path="/login" component={LoginPage} />
      {isInitialized && isAuthenticated ? (
        <MainLayout>
          <ErrorBoundary>
          <Switch>
            <Route path="/" component={() => <ProtectedRoute component={DashboardPage} />} />
            <Route path="/logs" component={() => <ProtectedRoute component={LogsExplorerPage} />} />
            <Route path="/alerts" component={() => <ProtectedRoute component={AlertQueuePage} />} />
            <Route path="/alerts/:id" component={() => <ProtectedRoute component={AlertDetailPage} />} />
            <Route path="/rules" component={() => <ProtectedRoute component={DetectionRulesPage} />} />
            <Route path="/rules/new" component={() => <ProtectedRoute component={RuleBuilderPage} permission="rules:write" />} />
            <Route path="/rules/:id/edit" component={() => <ProtectedRoute component={RuleBuilderPage} permission="rules:write" />} />
            <Route path="/mitre" component={() => <ProtectedRoute component={MitreAttackPage} />} />
            <Route path="/ingestion" component={() => <ProtectedRoute component={LogIngestionPage} permission="ingest:write" />} />
            <Route path="/settings" component={() => <ProtectedRoute component={SettingsPage} />} />
            <Route path="/users" component={() => <ProtectedRoute component={UserManagementPage} permission="users:manage" />} />
            <Route path="/audit" component={() => <ProtectedRoute component={AuditLogPage} permission="audit:view" />} />
            <Route path="/assets" component={() => <ProtectedRoute component={AssetsPage} />} />
            <Route component={NotFound} />
          </Switch>
          </ErrorBoundary>
        </MainLayout>
      ) : (
        <>
          <Route path="/" component={() => <ProtectedRoute component={DashboardPage} />} />
          <Route component={() => <ProtectedRoute component={DashboardPage} />} />
        </>
      )}
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <AuthInit>
            <Router />
          </AuthInit>
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
