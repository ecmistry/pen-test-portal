import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle,
  Clock,
  Play,
  Shield,
  Target,
  TrendingUp,
  Zap,
} from "lucide-react";
import { Link, useLocation } from "wouter";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import { Button } from "@/components/ui/button";

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge-${severity}`}>{severity.toUpperCase()}</span>;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-${status}`}>{status.toUpperCase()}</span>;
}

function ScoreRing({ score }: { score: number | null | undefined }) {
  const s = score ?? 0;
  const color = s >= 80 ? "#34d399" : s >= 60 ? "#fbbf24" : "#f87171";
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-20 h-20">
        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="32" fill="none" stroke="currentColor" strokeWidth="6" className="text-border" />
          <circle
            cx="40" cy="40" r="32" fill="none"
            stroke={color} strokeWidth="6"
            strokeDasharray={`${(s / 100) * 201} 201`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-lg font-bold text-foreground">{s}</span>
        </div>
      </div>
      <span className="text-xs text-muted-foreground mt-1">Security Score</span>
    </div>
  );
}

export default function Dashboard() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { data: stats, isLoading: statsLoading } = trpc.dashboard.stats.useQuery();
  const { data: trends } = trpc.dashboard.trends.useQuery({ days: 30 });
  const { data: recentScans } = trpc.dashboard.recentScans.useQuery();
  const { data: recentFindings } = trpc.scans.recentFindings.useQuery();

  const trendData = (trends || []).map((t: any) => ({
    date: t.date,
    scans: Number(t.total),
    score: t.avgScore ? Math.round(Number(t.avgScore)) : null,
  }));

  const severityData = recentFindings
    ? (() => {
        const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        recentFindings.forEach((r: any) => {
          const sev = r.finding?.severity;
          if (sev && counts[sev] !== undefined) counts[sev]++;
        });
        return Object.entries(counts).map(([name, value]) => ({ name, value }));
      })()
    : [];

  const severityColors: Record<string, string> = {
    critical: "#f87171",
    high: "#fb923c",
    medium: "#fbbf24",
    low: "#60a5fa",
    info: "#94a3b8",
  };

  return (
    <AppLayout title="Dashboard">
      <div className="p-6 space-y-6">
        {/* Welcome */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-foreground">
              Welcome back, {user?.name?.split(" ")[0] || "there"}
            </h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              Here's your security overview for the last 30 days
            </p>
          </div>
          <Button
            size="sm"
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            onClick={() => navigate("/targets")}
          >
            <Play className="w-3.5 h-3.5" /> New Scan
          </Button>
        </div>

        {/* Stats cards */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          {[
            {
              label: "Targets",
              value: statsLoading ? "—" : stats?.totalTargets ?? 0,
              icon: Target,
              color: "text-blue-400",
              bg: "bg-blue-900/20 border-blue-800/30",
              href: "/targets",
            },
            {
              label: "Total Scans",
              value: statsLoading ? "—" : stats?.totalScans ?? 0,
              icon: Zap,
              color: "text-emerald-400",
              bg: "bg-emerald-900/20 border-emerald-800/30",
              href: "/scans",
            },
            {
              label: "Scans (30d)",
              value: statsLoading ? "—" : stats?.recentScans ?? 0,
              icon: TrendingUp,
              color: "text-purple-400",
              bg: "bg-purple-900/20 border-purple-800/30",
              href: "/scans",
            },
            {
              label: "Open Findings",
              value: statsLoading ? "—" : stats?.openFindings ?? 0,
              icon: AlertTriangle,
              color: "text-yellow-400",
              bg: "bg-yellow-900/20 border-yellow-800/30",
              href: "/scans",
            },
            {
              label: "Critical",
              value: statsLoading ? "—" : stats?.criticalFindings ?? 0,
              icon: Shield,
              color: "text-red-400",
              bg: "bg-red-900/20 border-red-800/30",
              href: "/scans",
            },
          ].map((s) => (
            <Link
              key={s.label}
              href={s.href}
              className={`block rounded-xl border p-4 ${s.bg} hover:border-opacity-60 transition-colors cursor-pointer`}
            >
              <div className="flex items-start justify-between mb-3">
                <s.icon className={`w-5 h-5 ${s.color}`} />
              </div>
              <div className="text-2xl font-bold text-foreground">{String(s.value)}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </Link>
          ))}
        </div>

        {/* Charts row */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Scan trend */}
          <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <BarChart3 className="w-4 h-4 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Scan Activity (30 days)</h3>
            </div>
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={trendData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.22 0.01 240)" />
                  <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ background: "oklch(0.14 0.01 240)", border: "1px solid oklch(0.22 0.01 240)", borderRadius: "8px", color: "#e2e8f0" }}
                    labelStyle={{ color: "#94a3b8", fontSize: 11 }}
                  />
                  <Area type="monotone" dataKey="scans" stroke="#34d399" fill="url(#scanGrad)" strokeWidth={2} dot={false} name="Scans" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center text-muted-foreground text-sm">
                No scan data yet. Run your first scan to see trends.
              </div>
            )}
          </div>

          {/* Severity distribution */}
          <div className="bg-card border border-border rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <h3 className="text-sm font-semibold text-foreground">Finding Severity</h3>
            </div>
            {severityData.some((d) => d.value > 0) ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={severityData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.22 0.01 240)" />
                  <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ background: "oklch(0.14 0.01 240)", border: "1px solid oklch(0.22 0.01 240)", borderRadius: "8px", color: "#e2e8f0" }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]} name="Findings">
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={severityColors[entry.name] || "#94a3b8"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center text-muted-foreground text-sm">
                No findings yet.
              </div>
            )}
          </div>
        </div>

        {/* Recent scans */}
        <div className="bg-card border border-border rounded-xl">
          <div className="flex items-center justify-between px-5 py-4 border-b border-border/50">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Recent Scans</h3>
            </div>
            <Link href="/scans" className="text-xs text-primary hover:text-primary/80 transition-colors">
              View all →
            </Link>
          </div>
          <div className="divide-y divide-border/50">
            {!recentScans || recentScans.length === 0 ? (
              <div className="px-5 py-8 text-center text-muted-foreground text-sm">
                No scans yet. <Link href="/targets" className="text-primary hover:underline">Add a target</Link> to get started.
              </div>
            ) : (
              recentScans.slice(0, 8).map((scan: any) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center gap-4 px-5 py-3.5 hover:bg-accent/30 transition-colors cursor-pointer"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground truncate">Scan #{scan.id}</span>
                      <StatusBadge status={scan.status} />
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {new Date(scan.createdAt).toLocaleString()} · {scan.tools}
                    </div>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    {scan.securityScore != null && (
                      <div className="text-right">
                        <div className={`text-sm font-bold ${scan.securityScore >= 80 ? "text-emerald-400" : scan.securityScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                          {scan.securityScore}/100
                        </div>
                        <div className="text-xs text-muted-foreground">Score</div>
                      </div>
                    )}
                    {scan.totalFindings != null && scan.totalFindings > 0 && (
                      <div className="text-right">
                        <div className="text-sm font-bold text-foreground">{scan.totalFindings}</div>
                        <div className="text-xs text-muted-foreground">Findings</div>
                      </div>
                    )}
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Recent findings */}
        {recentFindings && recentFindings.length > 0 && (
          <div className="bg-card border border-border rounded-xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border/50">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-foreground">Recent Findings</h3>
              </div>
            </div>
            <div className="divide-y divide-border/50">
              {recentFindings.slice(0, 6).map((r: any) => (
                <Link
                  key={r.finding.id}
                  href={`/scans/${r.finding.scanId}`}
                  className="flex items-center gap-4 px-5 py-3.5 hover:bg-accent/30 transition-colors cursor-pointer"
                >
                  <SeverityBadge severity={r.finding.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-foreground truncate">{r.finding.title}</div>
                    <div className="text-xs text-muted-foreground">{r.finding.category} · Scan #{r.finding.scanId}</div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
