import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Link } from "wouter";
import { FileText, Loader2, Shield } from "lucide-react";

export default function Reports() {
  const { data: reports, isLoading } = trpc.reports.list.useQuery();

  return (
    <AppLayout title="Reports">
      <div className="p-6 space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-foreground">Security Reports</h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            Generated penetration test reports with compliance-ready formatting
          </p>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="grid grid-cols-[1fr_auto_auto] gap-0 px-5 py-3 border-b border-border/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div>Report Title</div>
            <div className="px-4">Generated</div>
            <div className="pl-4">Actions</div>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12 gap-2 text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading reports...
            </div>
          ) : !reports || reports.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <FileText className="w-8 h-8 mx-auto mb-3 opacity-40" />
              <p className="text-sm">No reports yet. Complete a scan and generate a report to see it here.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {reports.map((report: any) => (
                <div key={report.id} className="grid grid-cols-[1fr_auto_auto] gap-0 px-5 py-4 items-center hover:bg-accent/20 transition-colors">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">{report.title}</div>
                    {report.executiveSummary && (
                      <div className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{report.executiveSummary}</div>
                    )}
                  </div>
                  <div className="px-4 text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(report.generatedAt).toLocaleDateString()}
                  </div>
                  <div className="pl-4">
                    <Link
                      href={`/reports/${report.scanId}`}
                      className="text-xs text-primary hover:text-primary/80 transition-colors flex items-center gap-1"
                    >
                      <FileText className="w-3 h-3" /> View
                    </Link>
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
