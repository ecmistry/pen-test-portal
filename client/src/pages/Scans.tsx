import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Link, useSearch } from "wouter";
import { Zap, Shield, AlertTriangle, Clock, CheckCircle, XCircle, Loader2 } from "lucide-react";

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-${status}`}>{status.toUpperCase()}</span>;
}

function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return null;
  return <span className={`badge-${level}`}>{level.toUpperCase()}</span>;
}

export default function Scans() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const targetId = params.get("targetId") ? Number(params.get("targetId")) : undefined;

  const { data: scans, isLoading } = trpc.scans.list.useQuery({ targetId, limit: 100 });

  return (
    <AppLayout title="Scan History">
      <div className="p-6 space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-foreground">Scan History</h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            {targetId ? `Showing scans for target #${targetId}` : "All security scans across your targets"}
          </p>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-0 px-5 py-3 border-b border-border/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div className="pr-4">ID</div>
            <div>Target / Tools</div>
            <div className="px-4">Status</div>
            <div className="px-4">Score</div>
            <div className="px-4">Findings</div>
            <div className="pl-4">Date</div>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12 gap-2 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading scans...
            </div>
          ) : !scans || scans.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Zap className="w-8 h-8 mx-auto mb-3 opacity-40" />
              <p className="text-sm">No scans found. Go to <Link href="/targets" className="text-primary hover:underline">Targets</Link> to start a scan.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {scans.map((scan: any) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-0 px-5 py-3.5 hover:bg-accent/30 transition-colors cursor-pointer items-center"
                >
                  <div className="pr-4 text-sm font-mono text-muted-foreground">#{scan.id}</div>
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground">Target #{scan.targetId}</div>
                    <div className="text-xs text-muted-foreground truncate">{scan.tools}</div>
                  </div>
                  <div className="px-4">
                    <StatusBadge status={scan.status} />
                  </div>
                  <div className="px-4 text-right">
                    {scan.securityScore != null ? (
                      <span className={`text-sm font-bold ${scan.securityScore >= 80 ? "text-emerald-400" : scan.securityScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                        {scan.securityScore}
                      </span>
                    ) : (
                      <span className="text-muted-foreground text-sm">—</span>
                    )}
                  </div>
                  <div className="px-4 text-right">
                    {scan.totalFindings != null && scan.totalFindings > 0 ? (
                      <div className="flex items-center gap-1 justify-end">
                        {scan.criticalCount > 0 && <span className="badge-critical">{scan.criticalCount}</span>}
                        {scan.highCount > 0 && <span className="badge-high">{scan.highCount}</span>}
                        {scan.mediumCount > 0 && <span className="badge-medium">{scan.mediumCount}</span>}
                      </div>
                    ) : (
                      <span className="text-muted-foreground text-sm">—</span>
                    )}
                  </div>
                  <div className="pl-4 text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(scan.createdAt).toLocaleDateString()}
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
