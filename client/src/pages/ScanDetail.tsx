import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { useEffect, useRef, useState } from "react";
import { useParams, useLocation, Link } from "wouter";
import {
  AlertTriangle, CheckCircle, Clock, ExternalLink, FileText, Loader2, RefreshCw, Shield, XCircle, ChevronDown, ChevronUp,
} from "lucide-react";

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-${status}`}>{status.toUpperCase()}</span>;
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge-${severity}`}>{severity.toUpperCase()}</span>;
}

function CvssBadge({ score }: { score: string | null | undefined }) {
  if (!score) return null;
  const n = Number(score);
  const color = n >= 9.0 ? "text-red-400 bg-red-950/50 border-red-800/40"
    : n >= 7.0 ? "text-orange-400 bg-orange-950/50 border-orange-800/40"
    : n >= 4.0 ? "text-yellow-400 bg-yellow-950/50 border-yellow-800/40"
    : "text-blue-400 bg-blue-950/50 border-blue-800/40";
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-mono font-semibold px-1.5 py-0.5 rounded border ${color}`}>
      {n.toFixed(1)}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string | null | undefined }) {
  if (!priority) return null;
  const colors: Record<string, string> = {
    P1: "text-red-300 bg-red-950/40",
    P2: "text-orange-300 bg-orange-950/40",
    P3: "text-yellow-300 bg-yellow-950/40",
    P4: "text-slate-300 bg-slate-950/40",
  };
  return (
    <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${colors[priority] ?? "text-slate-300 bg-slate-950/40"}`}>
      {priority}
    </span>
  );
}

function ScoreDisplay({ score, riskLevel }: { score: number | null | undefined; riskLevel: string | null | undefined }) {
  const s = score ?? 0;
  const color = s >= 80 ? "text-emerald-400" : s >= 60 ? "text-yellow-400" : "text-red-400";
  return (
    <div className="flex items-center gap-3">
      <div className={`text-4xl font-bold ${color}`}>{s}<span className="text-lg text-muted-foreground">/100</span></div>
      {riskLevel && <span className={`badge-${riskLevel}`}>{riskLevel.toUpperCase()} RISK</span>}
    </div>
  );
}

export default function ScanDetail() {
  const params = useParams<{ id: string }>();
  const scanId = Number(params.id);
  const [, navigate] = useLocation();
  const logEndRef = useRef<HTMLDivElement>(null);
  const [showAllLogs, setShowAllLogs] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);

  const { data: scan, isLoading, refetch } = trpc.scans.get.useQuery({ id: scanId });
  const { data: logs, refetch: refetchLogs } = trpc.scans.logs.useQuery({ scanId }, { enabled: !!scan });
  const { data: findings } = trpc.scans.findings.useQuery({ scanId }, { enabled: scan?.status === "completed" || scan?.status === "failed" });
  const { data: report } = trpc.reports.getByScan.useQuery({ scanId }, { enabled: scan?.status === "completed" });
  const generateReport = trpc.reports.generate.useMutation({
    onSuccess: () => {
      toast.success("Report generated!");
      navigate(`/reports/${scanId}`);
    },
    onError: (e) => toast.error(e.message),
  });
  const updateFinding = trpc.scans.updateFinding.useMutation({
    onSuccess: () => {
      trpc.useUtils().scans.findings.invalidate({ scanId });
      toast.success("Finding status updated");
    },
  });

  // Auto-poll while scan is running
  useEffect(() => {
    if (!scan) return;
    if (scan.status === "running" || scan.status === "queued") {
      const interval = setInterval(() => {
        refetch();
        refetchLogs();
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [scan?.status]);

  // Auto-scroll logs
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs?.length]);

  const isRunning = scan?.status === "running" || scan?.status === "queued";
  const displayedLogs = showAllLogs ? logs : logs?.slice(-50);

  function logClass(level: string) {
    switch (level) {
      case "success": return "log-success";
      case "warn": return "log-warn";
      case "error": return "log-error";
      case "debug": return "log-debug";
      default: return "log-info";
    }
  }

  if (isLoading) {
    return (
      <AppLayout title="Scan Details">
        <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />
          Loading scan...
        </div>
      </AppLayout>
    );
  }

  if (!scan) {
    return (
      <AppLayout title="Scan Not Found">
        <div className="p-6 text-center text-muted-foreground">Scan not found.</div>
      </AppLayout>
    );
  }

  const bySeverity = {
    critical: findings?.filter((f: any) => f.severity === "critical") || [],
    high: findings?.filter((f: any) => f.severity === "high") || [],
    medium: findings?.filter((f: any) => f.severity === "medium") || [],
    low: findings?.filter((f: any) => f.severity === "low") || [],
    info: findings?.filter((f: any) => f.severity === "info") || [],
  };

  return (
    <AppLayout title={`Scan #${scanId}`}>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h2 className="text-xl font-semibold text-foreground">Scan #{scanId}</h2>
              <StatusBadge status={scan.status} />
              {isRunning && <Loader2 className="w-4 h-4 animate-spin text-blue-400" />}
            </div>
            <div className="text-sm text-muted-foreground">
              Target #{scan.targetId} · {(scan as { scanMode?: string }).scanMode === "full" ? "Full" : "Light"} · Tools: {scan.tools} · {scan.triggeredBy === "schedule" ? "Scheduled" : "Manual"}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              Started: {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "—"}
              {scan.completedAt && ` · Completed: ${new Date(scan.completedAt).toLocaleString()}`}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {isRunning && (
              <Button size="sm" variant="outline" className="border-border text-foreground gap-1.5" onClick={() => { refetch(); refetchLogs(); }}>
                <RefreshCw className="w-3.5 h-3.5" /> Refresh
              </Button>
            )}
            {scan.status === "completed" && !report && (
              <Button
                size="sm"
                className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                onClick={() => generateReport.mutate({ scanId })}
                disabled={generateReport.isPending}
              >
                <FileText className="w-3.5 h-3.5" />
                {generateReport.isPending ? "Generating..." : "Generate Report"}
              </Button>
            )}
            {report && (
              <Link href={`/reports/${scanId}`}>
                <span className="inline-flex items-center justify-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90">
                  <FileText className="w-3.5 h-3.5" /> View Report
                </span>
              </Link>
            )}
          </div>
        </div>

        {/* Score summary */}
        {scan.status === "completed" && (
          <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
            <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5">
              <div className="text-xs text-muted-foreground mb-2">Security Score</div>
              <ScoreDisplay score={scan.securityScore} riskLevel={scan.riskLevel} />
            </div>
            {[
              { label: "Critical", count: scan.criticalCount, cls: "text-red-400" },
              { label: "High", count: scan.highCount, cls: "text-orange-400" },
              { label: "Medium", count: scan.mediumCount, cls: "text-yellow-400" },
              { label: "Low", count: scan.lowCount, cls: "text-blue-400" },
              { label: "Info", count: scan.infoCount, cls: "text-slate-400" },
            ].map((s) => (
              <div key={s.label} className="bg-card border border-border rounded-xl p-5">
                <div className="text-xs text-muted-foreground mb-2">{s.label}</div>
                <div className={`text-2xl font-bold ${s.cls}`}>{s.count ?? 0}</div>
              </div>
            ))}
          </div>
        )}

        {/* "Still working" indicator when scan is running */}
        {isRunning && (
          <div className="flex items-center gap-3 rounded-xl border border-blue-800/50 bg-blue-950/30 px-4 py-3 text-blue-200">
            <Loader2 className="w-5 h-5 shrink-0 animate-spin" />
            <div>
              <p className="font-medium">Scan in progress</p>
              <p className="text-sm text-blue-300/90">
                Some steps (e.g. Nikto, Nuclei, ZAP) can take 2–5 minutes with no new log lines. The page will update automatically.
              </p>
            </div>
          </div>
        )}

        {/* Live log terminal */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-border/50">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-blue-400 scanning" : scan.status === "completed" ? "bg-emerald-400" : "bg-red-400"}`} />
              <span className="text-sm font-semibold text-foreground">Scan Output</span>
              {logs && <span className="text-xs text-muted-foreground">({logs.length} lines)</span>}
              {isRunning && logs && logs.length > 0 && (
                <span className="text-xs text-muted-foreground">· updating every 2s</span>
              )}
            </div>
            {logs && logs.length > 50 && (
              <button
                className="text-xs text-primary hover:text-primary/80 transition-colors"
                onClick={() => setShowAllLogs(!showAllLogs)}
              >
                {showAllLogs ? "Show recent" : "Show all"}
              </button>
            )}
          </div>
          <div className="terminal max-h-80 overflow-y-auto p-4">
            {!logs || logs.length === 0 ? (
              <span className="text-muted-foreground">Waiting for scan output...</span>
            ) : (
              <>
                {!showAllLogs && logs.length > 50 && (
                  <div className="text-slate-500 mb-2">... {logs.length - 50} earlier lines hidden ...</div>
                )}
                {displayedLogs?.map((log: any) => (
                  <div key={log.id} className={`${logClass(log.level)} leading-relaxed`}>
                    <span className="text-slate-600 select-none">{new Date(log.createdAt).toLocaleTimeString()} </span>
                    {log.message}
                  </div>
                ))}
              </>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Findings */}
        {findings && findings.length > 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              Findings ({findings.length})
            </h3>
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
              const group = bySeverity[sev];
              if (group.length === 0) return null;
              return (
                <div key={sev} className="bg-card border border-border rounded-xl overflow-hidden">
                  <div className={`px-5 py-3 border-b border-border/50 flex items-center gap-2`}>
                    <SeverityBadge severity={sev} />
                    <span className="text-sm font-medium text-foreground">{group.length} finding{group.length > 1 ? "s" : ""}</span>
                  </div>
                  <div className="divide-y divide-border/50">
                    {group.map((f: any) => (
                      <div key={f.id} className="px-5 py-4">
                        <div
                          className="flex items-start justify-between gap-4 cursor-pointer"
                          onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                        >
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-medium text-foreground">{f.title}</span>
                              <CvssBadge score={f.cvssScore} />
                              <PriorityBadge priority={f.remediationPriority} />
                            </div>
                            <div className="text-xs text-muted-foreground mt-0.5">
                              {f.category}{f.cweId ? ` · ${f.cweId}` : ""}{f.owaspCategory ? ` · ${f.owaspCategory}` : ""}
                              {f.remediationComplexity ? ` · ${f.remediationComplexity} complexity` : ""}
                            </div>
                            {(f.affectedComponent || f.affectedUrl) && (
                              <div className="text-xs text-cyan-400/80 mt-0.5 truncate">
                                {f.affectedComponent && <span className="font-medium">{f.affectedComponent}</span>}
                                {f.affectedComponent && f.affectedUrl && <span className="text-muted-foreground"> — </span>}
                                {f.affectedUrl && <code className="text-cyan-400/60">{f.affectedUrl}</code>}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <select
                              value={f.status}
                              onChange={(e) => {
                                e.stopPropagation();
                                updateFinding.mutate({ findingId: f.id, status: e.target.value as any });
                              }}
                              className="text-xs bg-input border border-border rounded px-2 py-1 text-foreground"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <option value="open">Open</option>
                              <option value="acknowledged">Acknowledged</option>
                              <option value="resolved">Resolved</option>
                              <option value="false_positive">False Positive</option>
                            </select>
                            {expandedFinding === f.id ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                          </div>
                        </div>
                        {expandedFinding === f.id && (
                          <div className="mt-4 space-y-3 text-sm">
                            {/* CVSS & metadata row */}
                            {(f.cvssVector || f.attackTechniques || f.iso27001Controls) && (
                              <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted-foreground bg-black/20 rounded-lg p-3">
                                {f.cvssVector && (
                                  <div><span className="font-medium text-foreground/70">CVSS:</span> <code className="text-foreground/60">{f.cvssVector}</code></div>
                                )}
                                {f.attackTechniques && Array.isArray(f.attackTechniques) && f.attackTechniques.length > 0 && (
                                  <div className="flex items-center gap-1">
                                    <span className="font-medium text-foreground/70">ATT&CK:</span>
                                    {f.attackTechniques.map((t: any) => (
                                      <a key={t.techniqueId} href={`https://attack.mitre.org/techniques/${t.techniqueId}/`} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 inline-flex items-center gap-0.5">
                                        {t.techniqueId} <ExternalLink className="w-3 h-3" />
                                      </a>
                                    ))}
                                  </div>
                                )}
                                {f.iso27001Controls && Array.isArray(f.iso27001Controls) && f.iso27001Controls.length > 0 && (
                                  <div><span className="font-medium text-foreground/70">ISO 27001:</span> {f.iso27001Controls.join(", ")}</div>
                                )}
                              </div>
                            )}
                            {(f.affectedUrl || f.affectedComponent) && (
                              <div className="bg-cyan-950/30 border border-cyan-900/30 rounded-lg p-3">
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">Affected Location</div>
                                <div className="space-y-1">
                                  {f.affectedComponent && (
                                    <div className="flex items-center gap-2 text-xs">
                                      <span className="text-muted-foreground w-20 shrink-0">Component:</span>
                                      <span className="text-cyan-400 font-medium">{f.affectedComponent}</span>
                                    </div>
                                  )}
                                  {f.affectedUrl && (
                                    <div className="flex items-center gap-2 text-xs">
                                      <span className="text-muted-foreground w-20 shrink-0">URL:</span>
                                      <code className="text-cyan-300/80 font-mono break-all">{f.affectedUrl}</code>
                                    </div>
                                  )}
                                  {f.sourceFile && (
                                    <div className="flex items-center gap-2 text-xs">
                                      <span className="text-muted-foreground w-20 shrink-0">Source:</span>
                                      <code className="text-amber-400 font-mono">{f.sourceFile}{f.sourceLine ? `:${f.sourceLine}` : ""}</code>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}
                            {f.sourceSnippet && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Source Code</div>
                                <pre className="text-xs bg-black/50 text-amber-300/90 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre leading-relaxed">{f.sourceSnippet}</pre>
                              </div>
                            )}
                            {f.description && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Description</div>
                                <p className="text-foreground/80">{f.description}</p>
                              </div>
                            )}
                            {/* Business Impact */}
                            {f.businessImpact && typeof f.businessImpact === "object" && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Business Impact</div>
                                <div className="grid grid-cols-4 gap-2 mt-1">
                                  {(["financial", "operational", "reputational", "legal"] as const).map((dim) => {
                                    const val = (f.businessImpact as any)[dim];
                                    const c = val === "High" || val === "Critical" ? "text-red-400" : val === "Medium" ? "text-yellow-400" : "text-blue-400";
                                    return (
                                      <div key={dim} className="bg-black/30 rounded p-2 text-center">
                                        <div className="text-[10px] text-muted-foreground uppercase">{dim}</div>
                                        <div className={`text-xs font-semibold ${c}`}>{val}</div>
                                      </div>
                                    );
                                  })}
                                </div>
                                {(f.businessImpact as any).rationale && (
                                  <p className="text-xs text-muted-foreground mt-1.5 italic">{(f.businessImpact as any).rationale}</p>
                                )}
                              </div>
                            )}
                            {f.evidence && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Evidence</div>
                                <pre className="text-xs bg-black/40 text-green-400 rounded p-3 overflow-x-auto font-mono">{f.evidence}</pre>
                              </div>
                            )}
                            {f.recommendation && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Recommendation</div>
                                <p className="text-emerald-400/90">{f.recommendation}</p>
                              </div>
                            )}
                            {f.poc && typeof f.poc === "object" && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Proof of Concept</div>
                                {(f.poc as any).curlCommand && (
                                  <div className="mb-2">
                                    <div className="text-[10px] text-muted-foreground mb-0.5">curl command</div>
                                    <pre className="text-xs bg-black/40 text-amber-400 rounded p-2 overflow-x-auto font-mono">{(f.poc as any).curlCommand}</pre>
                                  </div>
                                )}
                                {(f.poc as any).requestRaw && (
                                  <div className="mb-2">
                                    <div className="text-[10px] text-muted-foreground mb-0.5">Raw HTTP request</div>
                                    <pre className="text-xs bg-black/40 text-slate-300 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap">{(f.poc as any).requestRaw}</pre>
                                  </div>
                                )}
                                {(f.poc as any).responseSnippet && (
                                  <div className="mb-2">
                                    <div className="text-[10px] text-muted-foreground mb-0.5">Response snippet</div>
                                    <pre className="text-xs bg-black/40 text-green-400 rounded p-2 overflow-x-auto font-mono">{(f.poc as any).responseSnippet}</pre>
                                  </div>
                                )}
                                {(f.poc as any).reproductionSteps && Array.isArray((f.poc as any).reproductionSteps) && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground mb-0.5">Reproduction steps</div>
                                    <ul className="text-xs text-foreground/80 space-y-0.5">
                                      {(f.poc as any).reproductionSteps.map((s: string, i: number) => (
                                        <li key={i}>{s}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Attack Scenarios */}
        {scan.status === "completed" && (scan as any).scenarios && Array.isArray((scan as any).scenarios) && (scan as any).scenarios.length > 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-400" />
              Attack Scenarios ({(scan as any).scenarios.length})
            </h3>
            <div className="bg-card border border-border rounded-xl overflow-hidden divide-y divide-border/50">
              {(scan as any).scenarios.map((s: any) => (
                <div key={s.id} className="px-5 py-4">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-xs font-mono text-muted-foreground">{s.id}</span>
                    <span className="text-sm font-medium text-foreground">{s.title}</span>
                    <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${s.impact === "High" ? "text-red-300 bg-red-950/40" : s.impact === "Medium" ? "text-yellow-300 bg-yellow-950/40" : "text-blue-300 bg-blue-950/40"}`}>
                      {s.impact} Impact
                    </span>
                    <span className={`text-xs px-1.5 py-0.5 rounded ${s.likelihood === "High" ? "text-red-300 bg-red-950/30" : s.likelihood === "Medium" ? "text-yellow-300 bg-yellow-950/30" : "text-blue-300 bg-blue-950/30"}`}>
                      {s.likelihood} Likelihood
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mb-2">Objective: {s.objective}</p>
                  <div className="flex flex-wrap gap-2">
                    {s.steps.map((step: any, i: number) => (
                      <div key={i} className="flex items-center gap-1.5 text-xs">
                        <span className="w-5 h-5 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-[10px]">{i + 1}</span>
                        <span className="text-foreground/80">{step.findingTitle}</span>
                        {i < s.steps.length - 1 && <span className="text-muted-foreground mx-1">→</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Trend Analysis */}
        {scan.status === "completed" && (scan as any).trendSummary && typeof (scan as any).trendSummary === "object" && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-400" />
              Trend Analysis
            </h3>
            <div className="bg-card border border-border rounded-xl p-5">
              <p className="text-sm text-muted-foreground mb-3">
                Compared against scan #{(scan as any).trendSummary.previousScanId} ({(scan as any).trendSummary.previousScanDate})
              </p>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="bg-black/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">{(scan as any).trendSummary.newFindings}</div>
                  <div className="text-xs text-muted-foreground">New</div>
                </div>
                <div className="bg-black/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{(scan as any).trendSummary.resolvedFindings}</div>
                  <div className="text-xs text-muted-foreground">Resolved</div>
                </div>
                <div className="bg-black/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{(scan as any).trendSummary.persistingFindings}</div>
                  <div className="text-xs text-muted-foreground">Persisting</div>
                </div>
              </div>
              {(scan as any).trendSummary.newItems?.length > 0 && (
                <div className="mb-2">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">New Findings</div>
                  {(scan as any).trendSummary.newItems.map((t: string, i: number) => (
                    <div key={i} className="text-xs text-red-400/80">+ {t}</div>
                  ))}
                </div>
              )}
              {(scan as any).trendSummary.resolvedItems?.length > 0 && (
                <div className="mb-2">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Resolved</div>
                  {(scan as any).trendSummary.resolvedItems.map((t: string, i: number) => (
                    <div key={i} className="text-xs text-emerald-400/80">- {t}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {scan.status === "completed" && findings && findings.length === 0 && (
          <div className="bg-emerald-900/20 border border-emerald-800/30 rounded-xl p-8 text-center">
            <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-emerald-400 mb-1">No Vulnerabilities Detected</h3>
            <p className="text-sm text-muted-foreground">The target passed all security checks for the selected test categories.</p>
          </div>
        )}

        {scan.status === "failed" && (
          <div className="bg-red-900/20 border border-red-800/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <XCircle className="w-5 h-5 text-red-400" />
              <h3 className="font-semibold text-red-400">Scan Failed</h3>
            </div>
            <p className="text-sm text-muted-foreground">{scan.errorMessage || "An unexpected error occurred during the scan."}</p>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
