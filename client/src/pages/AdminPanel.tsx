import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { useLocation } from "wouter";
import { useState } from "react";
import {
  Users, Shield, Zap, Target, FileText, AlertTriangle, Loader2, Lock, BarChart3, RefreshCw,
} from "lucide-react";
import { Input } from "@/components/ui/input";

export default function AdminPanel() {
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const utils = trpc.useUtils();

  const { data: adminStats, isLoading: statsLoading } = trpc.admin.globalStats.useQuery();
  const { data: users, isLoading: usersLoading } = trpc.admin.users.useQuery();
  const { data: allScans } = trpc.admin.allScans.useQuery({ limit: 20 });
  const { data: queueStats } = trpc.admin.scanQueueStats.useQuery(undefined, {
    refetchInterval: 5000,
  });
  const { data: orgs } = trpc.orgs.list.useQuery();
  const { data: auditEvents } = trpc.orgs.audit.useQuery({ limit: 30 });
  const [newOrgName, setNewOrgName] = useState("");
  const [newOrgSlug, setNewOrgSlug] = useState("");
  const createOrgMutation = trpc.orgs.create.useMutation({
    onSuccess: () => {
      utils.orgs.list.invalidate();
      setNewOrgName("");
      setNewOrgSlug("");
      toast.success("Organization created");
    },
    onError: (e) => toast.error(e.message),
  });
  const assignOrgMutation = trpc.orgs.assignUser.useMutation({
    onSuccess: () => {
      utils.admin.users.invalidate();
      toast.success("User org updated");
    },
    onError: (e) => toast.error(e.message),
  });

  const updateRoleMutation = trpc.admin.updateUserRole.useMutation({
    onSuccess: () => {
      utils.admin.users.invalidate();
      toast.success("User role updated");
    },
    onError: (e) => toast.error(e.message),
  });

  const updateCapabilitiesMutation = trpc.admin.updateScanCapabilities.useMutation({
    onSuccess: (data) => {
      utils.admin.getScanCapabilitiesStatus.invalidate();
      const parts = [];
      if (data.payloads?.sqli) parts.push(`${data.payloads.sqli} SQLi payloads`);
      if (data.payloads?.xss) parts.push(`${data.payloads.xss} XSS payloads`);
      if (data.nuclei?.updated) parts.push("Nuclei templates");
      if (data.kev?.count) parts.push(`${data.kev.count} CISA KEV`);
      if (data.epss?.count) parts.push(`${data.epss.count} EPSS`);
      if (data.trivyDb?.updated) parts.push("Trivy DB");
      if (data.nvdWarm?.fetched) parts.push(`NVD +${data.nvdWarm.fetched}`);
      toast.success(parts.length ? `Updated: ${parts.join(", ")}` : "Pen test capabilities updated");
    },
    onError: (e) => toast.error(e.message),
  });

  const { data: capabilitiesStatus } = trpc.admin.getScanCapabilitiesStatus.useQuery();

  if (user?.role !== "admin") {
    return (
      <AppLayout title="Access Denied">
        <div className="flex flex-col items-center justify-center py-24 gap-4 text-muted-foreground">
          <Lock className="w-12 h-12 opacity-40" />
          <p className="text-lg font-semibold text-foreground">Admin Access Required</p>
          <p className="text-sm">You do not have permission to view this page.</p>
          <Button size="sm" variant="outline" className="border-border text-foreground" onClick={() => navigate("/dashboard")}>
            Back to Dashboard
          </Button>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout title="Admin Panel">
      <div className="p-6 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-foreground">Admin Panel</h2>
            <p className="text-sm text-muted-foreground mt-0.5">System-wide overview and user management</p>
          </div>
          <Button
            onClick={() => updateCapabilitiesMutation.mutate()}
            disabled={updateCapabilitiesMutation.isPending}
            variant="outline"
            className="border-border text-foreground shrink-0"
          >
            {updateCapabilitiesMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-2" />
            )}
            Update Pen Test Capabilities
          </Button>
        </div>

        {(capabilitiesStatus?.lastUpdated || capabilitiesStatus?.autoUpdate || capabilitiesStatus?.vulnIntel) && (
          <div className="text-xs text-muted-foreground space-y-1">
            {capabilitiesStatus?.lastUpdated && (
              <div>
                Last intel refresh: {new Date(capabilitiesStatus.lastUpdated).toLocaleString()}
                {capabilitiesStatus.payloads && (
                  <> · {capabilitiesStatus.payloads.sqli?.length ?? 0} SQLi / {capabilitiesStatus.payloads.xss?.length ?? 0} XSS payloads</>
                )}
              </div>
            )}
            {capabilitiesStatus?.vulnIntel && (
              <div>
                Threat intel cache: {capabilitiesStatus.vulnIntel.kevCount ?? 0} CISA KEV ·{" "}
                {capabilitiesStatus.vulnIntel.epssCount ?? 0} EPSS ·{" "}
                {capabilitiesStatus.vulnIntel.nvdCacheCount ?? 0} NVD cached
              </div>
            )}
            {capabilitiesStatus?.autoUpdate && (
              <div>
                Daily auto-update:{" "}
                {capabilitiesStatus.autoUpdate.enabled
                  ? `enabled (cron ${capabilitiesStatus.autoUpdate.cron || "0 0 3 * * *"} ${capabilitiesStatus.autoUpdate.timezone || "UTC"})`
                  : "disabled"}
                {capabilitiesStatus.autoUpdate.lastRunAt && (
                  <> · last run {new Date(capabilitiesStatus.autoUpdate.lastRunAt).toLocaleString()} ({capabilitiesStatus.autoUpdate.lastTrigger})</>
                )}
              </div>
            )}
          </div>
        )}

        {/* System stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Total Targets", value: statsLoading ? "—" : adminStats?.totalTargets ?? 0, icon: Target, color: "text-emerald-400", bg: "bg-emerald-900/20 border-emerald-800/30" },
            { label: "Total Scans", value: statsLoading ? "—" : adminStats?.totalScans ?? 0, icon: Zap, color: "text-purple-400", bg: "bg-purple-900/20 border-purple-800/30" },
            { label: "Scans (30d)", value: statsLoading ? "—" : adminStats?.recentScans ?? 0, icon: BarChart3, color: "text-blue-400", bg: "bg-blue-900/20 border-blue-800/30" },
            { label: "Open Findings", value: statsLoading ? "—" : adminStats?.openFindings ?? 0, icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-900/20 border-yellow-800/30" },
          ].map((s) => (
            <div key={s.label} className={`rounded-xl border p-5 ${s.bg}`}>
              <s.icon className={`w-5 h-5 ${s.color} mb-3`} />
              <div className="text-2xl font-bold text-foreground">{String(s.value)}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>

        <div className="bg-card border border-border rounded-xl px-5 py-4 flex flex-wrap items-center gap-6">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Scan queue</h3>
          </div>
          <div className="text-sm text-muted-foreground">
            Active: <span className="text-foreground font-medium">{queueStats?.active ?? "—"}</span>
          </div>
          <div className="text-sm text-muted-foreground">
            Waiting: <span className="text-foreground font-medium">{queueStats?.waiting ?? "—"}</span>
          </div>
          <div className="text-sm text-muted-foreground">
            Max concurrent: <span className="text-foreground font-medium">{queueStats?.maxConcurrent ?? "—"}</span>
          </div>
        </div>

        {/* User management */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-border/50">
            <Users className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">User Management</h3>
          </div>
          {usersLoading ? (
            <div className="flex items-center justify-center py-8 gap-2 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading users...
            </div>
          ) : !users || users.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground text-sm">No users found.</div>
          ) : (
            <div className="divide-y divide-border/50">
              {users.map((u: any) => (
                <div key={u.id} className="flex items-center gap-4 px-5 py-3.5">
                  <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                    <span className="text-xs font-semibold text-primary">
                      {(u.name || u.email || "U").charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-foreground">{u.name || "—"}</div>
                    <div className="text-xs text-muted-foreground">{u.email || u.openId}</div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs text-muted-foreground">
                      Joined {new Date(u.createdAt).toLocaleDateString()}
                    </span>
                    <select
                      value={u.role}
                      onChange={(e) => updateRoleMutation.mutate({ userId: u.id, role: e.target.value as "user" | "admin" })}
                      disabled={u.id === user?.id}
                      className="text-xs bg-input border border-border rounded px-2 py-1 text-foreground disabled:opacity-50"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                    <select
                      value={u.orgId ?? ""}
                      onChange={(e) => {
                        const orgId = Number(e.target.value);
                        if (orgId) assignOrgMutation.mutate({ userId: u.id, orgId, orgRole: (u.orgRole || "member") as any });
                      }}
                      className="text-xs bg-input border border-border rounded px-2 py-1 text-foreground max-w-[140px]"
                    >
                      <option value="">Org…</option>
                      {(orgs ?? []).map((o) => (
                        <option key={o.id} value={o.id}>{o.name}</option>
                      ))}
                    </select>
                    <select
                      value={u.orgRole || "member"}
                      onChange={(e) => {
                        if (!u.orgId) return toast.error("Assign an org first");
                        assignOrgMutation.mutate({
                          userId: u.id,
                          orgId: u.orgId,
                          orgRole: e.target.value as any,
                        });
                      }}
                      className="text-xs bg-input border border-border rounded px-2 py-1 text-foreground max-w-[120px]"
                    >
                      <option value="org_admin">Org admin</option>
                      <option value="member">Member</option>
                      <option value="viewer">Viewer</option>
                      <option value="auditor">Auditor</option>
                    </select>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-card border border-border rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-foreground">Organizations</h3>
          <div className="flex flex-wrap gap-2 items-end">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Name</div>
              <Input value={newOrgName} onChange={(e) => setNewOrgName(e.target.value)} className="h-9" />
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Slug</div>
              <Input
                value={newOrgSlug}
                onChange={(e) => setNewOrgSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                className="h-9"
                placeholder="acme-corp"
              />
            </div>
            <Button
              size="sm"
              disabled={!newOrgName || !newOrgSlug || createOrgMutation.isPending}
              onClick={() => createOrgMutation.mutate({ name: newOrgName, slug: newOrgSlug })}
            >
              Create org
            </Button>
          </div>
          <div className="text-xs text-muted-foreground">
            {(orgs ?? []).map((o) => `${o.name} (${o.slug})`).join(" · ") || "No orgs"}
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-border/50">
            <h3 className="text-sm font-semibold text-foreground">Audit trail</h3>
          </div>
          <div className="divide-y divide-border/50 max-h-64 overflow-y-auto">
            {(auditEvents ?? []).map((ev) => (
              <div key={ev.id} className="px-5 py-2.5 text-xs flex gap-3">
                <span className="text-muted-foreground shrink-0 w-36">
                  {new Date(ev.createdAt).toLocaleString()}
                </span>
                <span className="text-foreground font-medium">{ev.action}</span>
                <span className="text-muted-foreground truncate">
                  {ev.resourceType}/{ev.resourceId}
                </span>
              </div>
            ))}
            {!auditEvents?.length && (
              <div className="py-6 text-center text-muted-foreground text-sm">No audit events yet.</div>
            )}
          </div>
        </div>

        {/* Recent scans across all users */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-border/50">
            <BarChart3 className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Recent Scans (All Users)</h3>
          </div>
          {!allScans || allScans.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground text-sm">No scans yet.</div>
          ) : (
            <div className="divide-y divide-border/50">
              {allScans.slice(0, 20).map((scan: any) => (
                <div key={scan.id} className="flex items-center gap-4 px-5 py-3.5">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-foreground">Scan #{scan.id} — Target #{scan.targetId}</div>
                    <div className="text-xs text-muted-foreground">{new Date(scan.createdAt).toLocaleString()} · {scan.tools}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`status-${scan.status}`}>{scan.status.toUpperCase()}</span>
                    {scan.securityScore != null && (
                      <span className={`text-sm font-bold ${scan.securityScore >= 80 ? "text-emerald-400" : scan.securityScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                        {scan.securityScore}/100
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
