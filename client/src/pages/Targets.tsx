import AppLayout from "@/components/AppLayout";
import ToolPicker from "@/components/ToolPicker";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { useState } from "react";
import { useLocation } from "wouter";
import {
  Plus, Target, Edit2, Trash2, Play, Clock, ExternalLink, Lock, Settings2,
} from "lucide-react";
import { LIGHT_DEFAULT_TOOLS } from "@shared/scanTools";

function StatusDot({ isActive }: { isActive: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${isActive ? "bg-emerald-400" : "bg-slate-500"}`} />
  );
}

interface TargetFormData {
  name: string;
  url: string;
  repoUrl: string;
  repoBranch: string;
  repoRef: string;
  repoSubpath: string;
  openapiUrl: string;
  manifestPath: string;
  description: string;
  tags: string;
  scanFrequency: "manual" | "daily" | "weekly" | "monthly";
  environment: string;
}

const defaultForm: TargetFormData = {
  name: "",
  url: "",
  repoUrl: "",
  repoBranch: "",
  repoRef: "",
  repoSubpath: "",
  openapiUrl: "",
  manifestPath: "",
  description: "",
  tags: "",
  scanFrequency: "manual",
  environment: "production",
};

interface AuthProfileForm {
  name: string;
  type: "none" | "bearer" | "basic" | "cookie";
  token: string;
  username: string;
  password: string;
  cookie?: string;
  privilegeRank: number;
}

interface AuthScanForm {
  loginUrl: string;
  username: string;
  password: string;
  usernameField: string;
  passwordField: string;
  loginMethod: "form" | "json" | "trpc";
  scanMode: "light" | "full";
  saveToTarget: boolean;
  verticalEscalation: boolean;
  horizontalEscalation: boolean;
  sessionExpiry: boolean;
  tokenReuse: boolean;
  profiles: AuthProfileForm[];
}

const defaultAuthForm: AuthScanForm = {
  loginUrl: "",
  username: "",
  password: "",
  usernameField: "email",
  passwordField: "password",
  loginMethod: "trpc",
  scanMode: "full",
  saveToTarget: true,
  verticalEscalation: true,
  horizontalEscalation: true,
  sessionExpiry: false,
  tokenReuse: true,
  profiles: [],
};

export default function Targets() {
  const [, navigate] = useLocation();
  const utils = trpc.useUtils();
  const { data: targets, isLoading } = trpc.targets.list.useQuery();
  const createMutation = trpc.targets.create.useMutation({
    onSuccess: () => {
      utils.targets.list.invalidate();
      toast.success("Target created successfully");
      setShowCreate(false);
      setForm(defaultForm);
    },
    onError: (e) => toast.error(e.message),
  });
  const updateMutation = trpc.targets.update.useMutation({
    onSuccess: () => {
      utils.targets.list.invalidate();
      toast.success("Target updated");
      setEditTarget(null);
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteMutation = trpc.targets.delete.useMutation({
    onSuccess: () => {
      utils.targets.list.invalidate();
      toast.success("Target deleted");
    },
    onError: (e) => toast.error(e.message),
  });
  const startScanMutation = trpc.scans.start.useMutation({
    onSuccess: (data) => {
      toast.success("Scan started!");
      setAuthScanTarget(null);
      navigate(`/scans/${data.scanId}`);
    },
    onError: (e) => toast.error(e.message),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState<any>(null);
  const [form, setForm] = useState<TargetFormData>(defaultForm);
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [authScanTarget, setAuthScanTarget] = useState<any>(null);
  const [authForm, setAuthForm] = useState<AuthScanForm>(defaultAuthForm);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [customScanTarget, setCustomScanTarget] = useState<any>(null);
  const [customTools, setCustomTools] = useState<string[]>([...LIGHT_DEFAULT_TOOLS]);
  const [customMode, setCustomMode] = useState<"light" | "full">("light");

  function openEdit(t: any) {
    setEditTarget(t);
    setForm({
      name: t.name,
      url: t.url,
      repoUrl: t.repoUrl || "",
      repoBranch: (t as any).repoBranch || "",
      repoRef: (t as any).repoRef || "",
      repoSubpath: (t as any).repoSubpath || "",
      openapiUrl: t.openapiUrl || "",
      manifestPath: t.manifestPath || "",
      description: t.description || "",
      tags: t.tags || "",
      scanFrequency: t.scanFrequency,
      environment: (t as any).environment || "production",
    });
  }

  function openAuthScan(t: any) {
    setAuthScanTarget(t);
    const saved = (t.authConfig?.loginCredentials ?? null) as {
      loginUrl?: string;
      username?: string;
      password?: string;
      usernameField?: string;
      passwordField?: string;
      loginMethod?: "form" | "json" | "trpc";
    } | null;
    const tests = t.authConfig?.authTests ?? {};
    const base = t.url.replace(/\/$/, "");
    const defaultLoginUrl = `${base}/api/trpc/auth.login`;
    setAuthForm({
      ...defaultAuthForm,
      loginUrl: saved?.loginUrl || defaultLoginUrl,
      username: saved?.username || "",
      password: saved?.password || "",
      usernameField: saved?.usernameField || "email",
      passwordField: saved?.passwordField || "password",
      loginMethod: saved?.loginMethod || "trpc",
      verticalEscalation: tests.verticalEscalation ?? true,
      horizontalEscalation: tests.horizontalEscalation ?? true,
      sessionExpiry: tests.sessionExpiry ?? false,
      tokenReuse: tests.tokenReuse ?? true,
      profiles: Array.isArray(t.authConfig?.authProfiles)
        ? t.authConfig.authProfiles.map((p: any) => ({
            name: p.name || "",
            type: p.type || "bearer",
            token: p.token || "",
            username: p.username || "",
            password: p.password || "",
            cookie: p.cookie || "",
            privilegeRank: p.privilegeRank ?? 2,
          }))
        : [],
    });
    setShowAdvanced(Boolean(saved?.usernameField && saved.usernameField !== "email"));
  }

  function handleSubmit() {
    if (!form.name || !form.url) {
      toast.error("Name and URL are required");
      return;
    }
    const payload = {
      ...form,
      repoUrl: form.repoUrl || undefined,
      repoBranch: form.repoBranch || undefined,
      repoRef: form.repoRef || undefined,
      repoSubpath: form.repoSubpath || undefined,
      openapiUrl: form.openapiUrl || undefined,
      manifestPath: form.manifestPath || undefined,
      environment: form.environment || "production",
    };
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, ...payload });
    } else {
      createMutation.mutate(payload);
    }
  }

  function handleAuthScan() {
    if (!authForm.username || !authForm.password) {
      toast.error("Username and password are required");
      return;
    }
    if (!authForm.loginUrl) {
      toast.error("Login URL is required");
      return;
    }
    const authProfiles = authForm.profiles
      .filter((p) => p.name.trim())
      .map((p) => ({
        name: p.name,
        type: p.type,
        token: p.token || undefined,
        username: p.username || undefined,
        password: p.password || undefined,
        cookie: p.cookie || undefined,
        privilegeRank: p.privilegeRank,
      }));
    const authTests = {
      verticalEscalation: authForm.verticalEscalation,
      horizontalEscalation: authForm.horizontalEscalation,
      sessionExpiry: authForm.sessionExpiry,
      tokenReuse: authForm.tokenReuse,
    };
    const loginCredentials = {
      loginUrl: authForm.loginUrl,
      username: authForm.username,
      password: authForm.password,
      usernameField: authForm.usernameField || "username",
      passwordField: authForm.passwordField || "password",
      loginMethod: authForm.loginMethod,
    };

    if (authForm.saveToTarget) {
      updateMutation.mutate({
        id: authScanTarget.id,
        authConfig: { authProfiles, authTests, loginCredentials },
      });
    }

    startScanMutation.mutate({
      targetId: authScanTarget.id,
      tools: [...LIGHT_DEFAULT_TOOLS, "auth-roles"],
      scanMode: authForm.scanMode,
      authProfiles: authProfiles.length ? authProfiles : undefined,
      authTests,
      loginCredentials,
      useTargetAuthConfig: false,
    });
  }

  return (
    <AppLayout title="Targets">
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-foreground">Targets</h2>
            <p className="text-sm text-muted-foreground mt-0.5">Manage the web applications you want to test</p>
          </div>
          <Button
            size="sm"
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            onClick={() => { setForm(defaultForm); setShowCreate(true); }}
          >
            <Plus className="w-3.5 h-3.5" /> Add Target
          </Button>
        </div>

        {isLoading ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-card border border-border rounded-xl p-5 animate-pulse">
                <div className="h-4 bg-muted rounded w-3/4 mb-3" />
                <div className="h-3 bg-muted rounded w-full mb-2" />
                <div className="h-3 bg-muted rounded w-1/2" />
              </div>
            ))}
          </div>
        ) : !targets || targets.length === 0 ? (
          <div className="bg-card border border-border rounded-xl p-12 text-center">
            <Target className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No targets yet</h3>
            <p className="text-muted-foreground text-sm mb-6">Add your first web application target to start running security scans.</p>
            <Button
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
              onClick={() => { setForm(defaultForm); setShowCreate(true); }}
            >
              <Plus className="w-3.5 h-3.5" /> Add Your First Target
            </Button>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {targets.map((t: any) => (
              <div key={t.id} className="bg-card border border-border rounded-xl p-5 hover:border-border/80 transition-colors flex flex-col">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <StatusDot isActive={t.isActive} />
                    <h3 className="font-semibold text-foreground truncate">{t.name}</h3>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <button
                      onClick={() => openEdit(t)}
                      className="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                      title="Edit"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(t.id)}
                      className="p-1.5 rounded text-muted-foreground hover:text-red-400 hover:bg-red-900/20 transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <a
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1 mb-2 truncate"
                >
                  <ExternalLink className="w-3 h-3 shrink-0" />
                  {t.url}
                </a>

                {t.description && (
                  <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{t.description}</p>
                )}

                <div className="flex items-center gap-2 mb-4 flex-wrap">
                  {t.tags && t.tags.split(",").map((tag: string) => (
                    <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-accent text-muted-foreground border border-border/50">
                      {tag.trim()}
                    </span>
                  ))}
                  <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/30 text-blue-400 border border-blue-800/30 flex items-center gap-1">
                    <Clock className="w-2.5 h-2.5" />
                    {t.scanFrequency}
                  </span>
                </div>

                {t.lastScannedAt && (
                  <div className="text-xs text-muted-foreground mb-4">
                    Last scanned: {new Date(t.lastScannedAt).toLocaleDateString()}
                  </div>
                )}

                <div className="mt-auto pt-3 border-t border-border/50 space-y-2">
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      className="flex-1 bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                      onClick={() =>
                        startScanMutation.mutate({
                          targetId: t.id,
                          tools: [...LIGHT_DEFAULT_TOOLS],
                          scanMode: "light",
                          manifestPath: t.manifestPath || undefined,
                        })
                      }
                      disabled={startScanMutation.isPending}
                      title="Quick scan (~1 min): headers, auth, SQLi, XSS, recon"
                    >
                      <Play className="w-3.5 h-3.5" />
                      {startScanMutation.isPending ? "Starting..." : "Light Scan"}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="flex-1 border-amber-500/50 text-amber-600 hover:bg-amber-500/10 hover:text-amber-500 gap-1.5"
                      onClick={() =>
                        startScanMutation.mutate({
                          targetId: t.id,
                          tools: [...LIGHT_DEFAULT_TOOLS],
                          scanMode: "full",
                          manifestPath: t.manifestPath || undefined,
                        })
                      }
                      disabled={startScanMutation.isPending}
                      title="Full pen test: extended payloads, CORS, traversal, Nikto/Nuclei/ZAP"
                    >
                      <Play className="w-3.5 h-3.5" />
                      Full Scan
                    </Button>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full border-border text-foreground gap-1.5"
                    onClick={() => {
                      setCustomScanTarget(t);
                      setCustomTools([...LIGHT_DEFAULT_TOOLS]);
                      setCustomMode("light");
                    }}
                    disabled={startScanMutation.isPending}
                  >
                    <Settings2 className="w-3.5 h-3.5" />
                    Custom Tools
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full border-cyan-500/50 text-cyan-500 hover:bg-cyan-500/10 hover:text-cyan-400 gap-1.5"
                    onClick={() => openAuthScan(t)}
                    disabled={startScanMutation.isPending}
                    title="Run a scan with login credentials for authenticated testing"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    Authenticated Scan
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="w-full text-muted-foreground hover:text-foreground"
                    onClick={() => navigate(`/scans?targetId=${t.id}`)}
                  >
                    History
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create/Edit Dialog */}
      <Dialog open={showCreate || !!editTarget} onOpenChange={(o) => { if (!o) { setShowCreate(false); setEditTarget(null); } }}>
        <DialogContent className="bg-card border-border text-foreground max-w-md">
          <DialogHeader>
            <DialogTitle>{editTarget ? "Edit Target" : "Add New Target"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Name *</Label>
              <Input
                placeholder="My Application"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">URL *</Label>
              <Input
                placeholder="https://example.com"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Repository URL <span className="text-muted-foreground font-normal">(for SAST)</span></Label>
              <Input
                placeholder="https://github.com/org/repo.git"
                value={form.repoUrl}
                onChange={(e) => setForm({ ...form, repoUrl: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
              <p className="text-xs text-muted-foreground mt-1">Git HTTPS URL for Semgrep/SCA/secrets. For private repos, add a token under Integrations → GitHub clone token.</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <Label className="text-foreground text-sm mb-1.5 block">Branch</Label>
                <Input placeholder="main" value={form.repoBranch} onChange={(e) => setForm({ ...form, repoBranch: e.target.value })} className="bg-input border-border text-foreground placeholder:text-muted-foreground" />
              </div>
              <div>
                <Label className="text-foreground text-sm mb-1.5 block">Ref / tag</Label>
                <Input placeholder="v1.2.3" value={form.repoRef} onChange={(e) => setForm({ ...form, repoRef: e.target.value })} className="bg-input border-border text-foreground placeholder:text-muted-foreground" />
              </div>
              <div>
                <Label className="text-foreground text-sm mb-1.5 block">Subpath</Label>
                <Input placeholder="gravitee-apim-rest-api" value={form.repoSubpath} onChange={(e) => setForm({ ...form, repoSubpath: e.target.value })} className="bg-input border-border text-foreground placeholder:text-muted-foreground" />
              </div>
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">OpenAPI URL <span className="text-muted-foreground font-normal">(API inventory)</span></Label>
              <Input
                placeholder="https://example.com/openapi.json"
                value={form.openapiUrl}
                onChange={(e) => setForm({ ...form, openapiUrl: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">SCA manifest <span className="text-muted-foreground font-normal">(optional staged basename)</span></Label>
              <Input
                placeholder="package-lock.json (or leave blank to scan cloned repo)"
                value={form.manifestPath}
                onChange={(e) => setForm({ ...form, manifestPath: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
              <p className="text-xs text-muted-foreground mt-1">With a Repository URL, SCA discovers lockfiles in the clone automatically.</p>
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Description</Label>
              <Input
                placeholder="Brief description of the application"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Tags (comma-separated)</Label>
              <Input
                placeholder="production, api, public"
                value={form.tags}
                onChange={(e) => setForm({ ...form, tags: e.target.value })}
                className="bg-input border-border text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Scan Frequency <span className="text-muted-foreground font-normal">(informational — use Schedules to run)</span></Label>
              <div>
                <Label className="text-sm">Environment</Label>
                <Select value={form.environment} onValueChange={(v: any) => setForm({ ...form, environment: v })}>
                  <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="development">Development</SelectItem>
                    <SelectItem value="staging">Staging</SelectItem>
                    <SelectItem value="production">Production</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Select value={form.scanFrequency} onValueChange={(v: any) => setForm({ ...form, scanFrequency: v })}>
                <SelectTrigger className="bg-input border-border text-foreground">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value="manual">Manual only</SelectItem>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-border text-foreground" onClick={() => { setShowCreate(false); setEditTarget(null); }}>
              Cancel
            </Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90"
              onClick={handleSubmit}
              disabled={createMutation.isPending || updateMutation.isPending}
            >
              {editTarget ? "Save Changes" : "Add Target"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Custom tools scan */}
      <Dialog open={!!customScanTarget} onOpenChange={(o) => { if (!o) setCustomScanTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Custom Scan — {customScanTarget?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label className="text-sm mb-1.5 block">Mode</Label>
              <Select value={customMode} onValueChange={(v: "light" | "full") => setCustomMode(v)}>
                <SelectTrigger className="bg-input border-border text-foreground">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="full">Full (adds advanced tools automatically)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <ToolPicker selected={customTools} onChange={setCustomTools} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCustomScanTarget(null)}>Cancel</Button>
            <Button
              onClick={() => {
                if (!customScanTarget || customTools.length === 0) return;
                startScanMutation.mutate({
                  targetId: customScanTarget.id,
                  tools: customTools,
                  scanMode: customMode,
                  manifestPath: customScanTarget.manifestPath || undefined,
                });
                setCustomScanTarget(null);
              }}
              disabled={startScanMutation.isPending}
            >
              Start Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Authenticated Scan Dialog */}
      <Dialog open={!!authScanTarget} onOpenChange={(o) => { if (!o) setAuthScanTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-500" />
              Authenticated / Multi-Role Scan
            </DialogTitle>
          </DialogHeader>
          {authScanTarget && (
            <div className="space-y-4 py-2">
              <div className="text-xs text-muted-foreground bg-accent/50 rounded-lg px-3 py-2">
                Target: <span className="text-foreground font-medium">{authScanTarget.name}</span>
                <span className="text-muted-foreground ml-1">({authScanTarget.url})</span>
              </div>

              <div>
                <Label className="text-foreground text-sm mb-1.5 block">Login URL *</Label>
                <Input
                  placeholder="https://example.com/api/trpc/auth.login"
                  value={authForm.loginUrl}
                  onChange={(e) => setAuthForm({ ...authForm, loginUrl: e.target.value })}
                  className="bg-input border-border text-foreground placeholder:text-muted-foreground"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Use the API login endpoint (not the SPA homepage). For Gravitee Info / Ghoststrike-style apps: <code className="text-[11px]">…/api/trpc/auth.login</code>
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-foreground text-sm mb-1.5 block">Email / Username *</Label>
                  <Input
                    placeholder="pen-test-user@example.com"
                    value={authForm.username}
                    onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                    className="bg-input border-border text-foreground placeholder:text-muted-foreground"
                    autoComplete="off"
                  />
                </div>
                <div>
                  <Label className="text-foreground text-sm mb-1.5 block">Password *</Label>
                  <Input
                    type="password"
                    placeholder="••••••••"
                    value={authForm.password}
                    onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                    className="bg-input border-border text-foreground placeholder:text-muted-foreground"
                    autoComplete="off"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-foreground text-sm mb-1.5 block">Scan Mode</Label>
                  <Select value={authForm.scanMode} onValueChange={(v: any) => setAuthForm({ ...authForm, scanMode: v })}>
                    <SelectTrigger className="bg-input border-border text-foreground">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-card border-border text-foreground">
                      <SelectItem value="light">Light</SelectItem>
                      <SelectItem value="full">Full</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-foreground text-sm mb-1.5 block">Login Method</Label>
                  <Select
                    value={authForm.loginMethod}
                    onValueChange={(v: "form" | "json" | "trpc") =>
                      setAuthForm({
                        ...authForm,
                        loginMethod: v,
                        usernameField: v === "trpc" ? (authForm.usernameField || "email") : authForm.usernameField,
                      })
                    }
                  >
                    <SelectTrigger className="bg-input border-border text-foreground">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-card border-border text-foreground">
                      <SelectItem value="trpc">tRPC (JSON envelope)</SelectItem>
                      <SelectItem value="json">JSON (flat API)</SelectItem>
                      <SelectItem value="form">Form POST</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <Label className="text-foreground text-sm">Advanced field names</Label>
                <Switch checked={showAdvanced} onCheckedChange={setShowAdvanced} />
              </div>

              {showAdvanced && (
                <div className="grid grid-cols-2 gap-3 border border-border/50 rounded-lg p-3 bg-accent/30">
                  <div>
                    <Label className="text-muted-foreground text-xs mb-1 block">Username Field</Label>
                    <Input
                      placeholder="email"
                      value={authForm.usernameField}
                      onChange={(e) => setAuthForm({ ...authForm, usernameField: e.target.value })}
                      className="bg-input border-border text-foreground placeholder:text-muted-foreground text-sm h-8"
                    />
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs mb-1 block">Password Field</Label>
                    <Input
                      placeholder="password"
                      value={authForm.passwordField}
                      onChange={(e) => setAuthForm({ ...authForm, passwordField: e.target.value })}
                      className="bg-input border-border text-foreground placeholder:text-muted-foreground text-sm h-8"
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2 border border-border/50 rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <Label className="text-sm text-foreground">Extra auth profiles (multi-role)</Label>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      setAuthForm({
                        ...authForm,
                        profiles: [
                          ...authForm.profiles,
                          { name: "standard_user", type: "bearer", token: "", username: "", password: "", privilegeRank: 2 },
                        ],
                      })
                    }
                  >
                    Add profile
                  </Button>
                </div>
                {authForm.profiles.map((p, idx) => (
                  <div key={idx} className="grid grid-cols-2 gap-2 border-t border-border/40 pt-2">
                    <Input
                      placeholder="name"
                      value={p.name}
                      onChange={(e) => {
                        const profiles = [...authForm.profiles];
                        profiles[idx] = { ...p, name: e.target.value };
                        setAuthForm({ ...authForm, profiles });
                      }}
                      className="bg-input border-border text-sm h-8"
                    />
                    <Select
                      value={p.type}
                      onValueChange={(v: any) => {
                        const profiles = [...authForm.profiles];
                        profiles[idx] = { ...p, type: v };
                        setAuthForm({ ...authForm, profiles });
                      }}
                    >
                      <SelectTrigger className="bg-input border-border h-8 text-sm"><SelectValue /></SelectTrigger>
                      <SelectContent className="bg-card border-border">
                        <SelectItem value="bearer">Bearer</SelectItem>
                        <SelectItem value="basic">Basic</SelectItem>
                        <SelectItem value="cookie">Cookie session</SelectItem>
                        <SelectItem value="none">None</SelectItem>
                      </SelectContent>
                    </Select>
                    {p.type === "bearer" ? (
                      <Input
                        placeholder="token"
                        value={p.token}
                        onChange={(e) => {
                          const profiles = [...authForm.profiles];
                          profiles[idx] = { ...p, token: e.target.value };
                          setAuthForm({ ...authForm, profiles });
                        }}
                        className="bg-input border-border text-sm h-8 col-span-2"
                      />
                    ) : p.type === "basic" ? (
                      <>
                        <Input placeholder="username" value={p.username} onChange={(e) => {
                          const profiles = [...authForm.profiles];
                          profiles[idx] = { ...p, username: e.target.value };
                          setAuthForm({ ...authForm, profiles });
                        }} className="bg-input border-border text-sm h-8" />
                        <Input placeholder="password" type="password" value={p.password} onChange={(e) => {
                          const profiles = [...authForm.profiles];
                          profiles[idx] = { ...p, password: e.target.value };
                          setAuthForm({ ...authForm, profiles });
                        }} className="bg-input border-border text-sm h-8" />
                      </>
                    ) : p.type === "cookie" ? (
                      <Input
                        placeholder="session=abc; other=xyz"
                        value={(p as any).cookie || ""}
                        onChange={(e) => {
                          const profiles = [...authForm.profiles];
                          profiles[idx] = { ...p, cookie: e.target.value } as any;
                          setAuthForm({ ...authForm, profiles });
                        }}
                        className="bg-input border-border text-sm h-8 col-span-2"
                      />
                    ) : null}
                    <div className="col-span-2 flex items-center gap-2">
                      <Label className="text-xs text-muted-foreground">Rank 0–4</Label>
                      <Input
                        type="number"
                        min={0}
                        max={4}
                        value={p.privilegeRank}
                        onChange={(e) => {
                          const profiles = [...authForm.profiles];
                          profiles[idx] = { ...p, privilegeRank: Number(e.target.value) };
                          setAuthForm({ ...authForm, profiles });
                        }}
                        className="bg-input border-border text-sm h-8 w-20"
                      />
                      <Button type="button" size="sm" variant="ghost" className="text-red-400" onClick={() => {
                        setAuthForm({ ...authForm, profiles: authForm.profiles.filter((_, i) => i !== idx) });
                      }}>Remove</Button>
                    </div>
                  </div>
                ))}
                <div className="grid grid-cols-2 gap-2 text-xs pt-2">
                  {[
                    ["verticalEscalation", "Vertical escalation"],
                    ["horizontalEscalation", "Horizontal / IDOR"],
                    ["tokenReuse", "Token reuse after logout"],
                    ["sessionExpiry", "Session cache checks"],
                  ].map(([key, label]) => (
                    <label key={key} className="flex items-center gap-2 text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={(authForm as any)[key]}
                        onChange={(e) => setAuthForm({ ...authForm, [key]: e.target.checked } as AuthScanForm)}
                      />
                      {label}
                    </label>
                  ))}
                </div>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={authForm.saveToTarget}
                    onChange={(e) => setAuthForm({ ...authForm, saveToTarget: e.target.checked })}
                  />
                  Save auth config on target (for schedules)
                </label>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" className="border-border text-foreground" onClick={() => setAuthScanTarget(null)}>
              Cancel
            </Button>
            <Button
              className="bg-cyan-600 text-white hover:bg-cyan-700 gap-1.5"
              onClick={handleAuthScan}
              disabled={startScanMutation.isPending}
            >
              <Lock className="w-3.5 h-3.5" />
              {startScanMutation.isPending ? "Starting..." : "Start Authenticated Scan"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <Dialog open={deleteConfirm !== null} onOpenChange={(o) => { if (!o) setDeleteConfirm(null); }}>
        <DialogContent className="bg-card border-border text-foreground max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete Target</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground py-2">
            Are you sure you want to delete this target? All associated scans and reports will remain but the target will be removed.
          </p>
          <DialogFooter>
            <Button variant="outline" className="border-border text-foreground" onClick={() => setDeleteConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (deleteConfirm) {
                  deleteMutation.mutate({ id: deleteConfirm });
                  setDeleteConfirm(null);
                }
              }}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppLayout>
  );
}
