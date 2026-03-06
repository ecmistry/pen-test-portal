import AppLayout from "@/components/AppLayout";
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
  Plus, Target, Edit2, Trash2, Play, Clock, ExternalLink, Lock,
} from "lucide-react";

function StatusDot({ isActive }: { isActive: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${isActive ? "bg-emerald-400" : "bg-slate-500"}`} />
  );
}

interface TargetFormData {
  name: string;
  url: string;
  description: string;
  tags: string;
  scanFrequency: "manual" | "daily" | "weekly" | "monthly";
}

const defaultForm: TargetFormData = {
  name: "",
  url: "",
  description: "",
  tags: "",
  scanFrequency: "manual",
};

interface AuthScanForm {
  loginUrl: string;
  username: string;
  password: string;
  usernameField: string;
  passwordField: string;
  loginMethod: "form" | "json";
  scanMode: "light" | "full";
}

const defaultAuthForm: AuthScanForm = {
  loginUrl: "",
  username: "",
  password: "",
  usernameField: "username",
  passwordField: "password",
  loginMethod: "json",
  scanMode: "full",
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

  function openEdit(t: any) {
    setEditTarget(t);
    setForm({
      name: t.name,
      url: t.url,
      description: t.description || "",
      tags: t.tags || "",
      scanFrequency: t.scanFrequency,
    });
  }

  function openAuthScan(t: any) {
    setAuthScanTarget(t);
    setAuthForm({
      ...defaultAuthForm,
      loginUrl: t.url.replace(/\/$/, ""),
    });
    setShowAdvanced(false);
  }

  function handleSubmit() {
    if (!form.name || !form.url) {
      toast.error("Name and URL are required");
      return;
    }
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, ...form });
    } else {
      createMutation.mutate(form);
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
    startScanMutation.mutate({
      targetId: authScanTarget.id,
      tools: ["headers", "auth", "sqli", "xss", "recon"],
      scanMode: authForm.scanMode,
      loginCredentials: {
        loginUrl: authForm.loginUrl,
        username: authForm.username,
        password: authForm.password,
        usernameField: authForm.usernameField || "username",
        passwordField: authForm.passwordField || "password",
        loginMethod: authForm.loginMethod,
      },
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
                          tools: ["headers", "auth", "sqli", "xss", "recon"],
                          scanMode: "light",
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
                          tools: ["headers", "auth", "sqli", "xss", "recon"],
                          scanMode: "full",
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
              <Label className="text-foreground text-sm mb-1.5 block">Scan Frequency</Label>
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

      {/* Authenticated Scan Dialog */}
      <Dialog open={!!authScanTarget} onOpenChange={(o) => { if (!o) setAuthScanTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-500" />
              Authenticated Scan
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
                  placeholder="https://example.com/login"
                  value={authForm.loginUrl}
                  onChange={(e) => setAuthForm({ ...authForm, loginUrl: e.target.value })}
                  className="bg-input border-border text-foreground placeholder:text-muted-foreground"
                />
                <p className="text-xs text-muted-foreground mt-1">The URL where the login form or API endpoint is located</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-foreground text-sm mb-1.5 block">Username *</Label>
                  <Input
                    placeholder="admin"
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
                  <Select value={authForm.loginMethod} onValueChange={(v: any) => setAuthForm({ ...authForm, loginMethod: v })}>
                    <SelectTrigger className="bg-input border-border text-foreground">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-card border-border text-foreground">
                      <SelectItem value="json">JSON (API)</SelectItem>
                      <SelectItem value="form">Form POST</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <Label className="text-foreground text-sm">Advanced Options</Label>
                <Switch checked={showAdvanced} onCheckedChange={setShowAdvanced} />
              </div>

              {showAdvanced && (
                <div className="grid grid-cols-2 gap-3 border border-border/50 rounded-lg p-3 bg-accent/30">
                  <div>
                    <Label className="text-muted-foreground text-xs mb-1 block">Username Field</Label>
                    <Input
                      placeholder="username"
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
                  <p className="col-span-2 text-xs text-muted-foreground">
                    Field names used in the login request body (e.g. "email" instead of "username")
                  </p>
                </div>
              )}
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
