import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Loader2, ShieldCheck } from "lucide-react";

export default function Compliance() {
  const { data, isLoading } = trpc.compliance.coverage.useQuery();

  return (
    <AppLayout title="Compliance & Coverage">
      <div className="p-6 space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <ShieldCheck className="w-5 h-5" /> Compliance & Coverage
          </h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            OWASP mapping, open findings, waiver count, and scanner tool usage across your org.
          </p>
        </div>

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground py-12">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Open findings", value: data?.openFindings ?? 0 },
                { label: "Active waivers", value: data?.waiverCount ?? 0 },
                { label: "MTTR (days)", value: data?.mttrDays != null ? data.mttrDays.toFixed(1) : "—" },
                { label: "OWASP categories", value: data?.byOwasp?.length ?? 0 },
              ].map((s) => (
                <div key={s.label} className="rounded-xl border border-border bg-card p-4">
                  <div className="text-2xl font-bold text-foreground">{s.value}</div>
                  <div className="text-xs text-muted-foreground mt-1">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="grid lg:grid-cols-2 gap-4">
              <section className="rounded-xl border border-border bg-card p-4">
                <h3 className="text-sm font-semibold mb-3">Open findings by OWASP</h3>
                <div className="space-y-2">
                  {(data?.byOwasp ?? []).map((r) => (
                    <div key={r.label} className="flex justify-between text-sm gap-3">
                      <span className="text-foreground/90 truncate">{r.label}</span>
                      <span className="text-muted-foreground shrink-0">{r.count}</span>
                    </div>
                  ))}
                  {!data?.byOwasp?.length && (
                    <p className="text-xs text-muted-foreground">No open findings mapped yet.</p>
                  )}
                </div>
              </section>

              <section className="rounded-xl border border-border bg-card p-4">
                <h3 className="text-sm font-semibold mb-3">By severity</h3>
                <div className="space-y-2">
                  {(data?.bySeverity ?? []).map((r) => (
                    <div key={r.label} className="flex justify-between text-sm gap-3">
                      <span className={`badge-${r.label}`}>{r.label}</span>
                      <span className="text-muted-foreground">{r.count}</span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-xl border border-border bg-card p-4 lg:col-span-2">
                <h3 className="text-sm font-semibold mb-3">Scanner tool coverage (completed scans)</h3>
                <div className="flex flex-wrap gap-2">
                  {(data?.toolCoverage ?? []).map((r) => (
                    <span
                      key={r.tool}
                      className="text-xs border border-border rounded-md px-2 py-1 text-foreground"
                    >
                      {r.tool} · {r.scans}
                    </span>
                  ))}
                  {!data?.toolCoverage?.length && (
                    <p className="text-xs text-muted-foreground">No completed scans yet.</p>
                  )}
                </div>
              </section>
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
