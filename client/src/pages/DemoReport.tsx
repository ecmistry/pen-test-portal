import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { Download, FileText, Loader2, ArrowLeft, Code, FileDown } from "lucide-react";
import { Link } from "wouter";
import { Streamdown } from "streamdown";

function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadPdfFromBase64(pdfBase64: string, filename: string) {
  const binary = atob(pdfBase64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
  const blob = new Blob([arr], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function DemoReportLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <nav className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container flex items-center justify-between h-16">
          <Link href="/" className="flex items-center gap-3">
            <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="h-8 w-auto object-contain" />
            <span className="font-semibold text-foreground tracking-tight">Ghoststrike</span>
          </Link>
          <div className="flex items-center gap-2">
            <Button type="button" variant="ghost" size="sm" asChild>
              <Link href="/">Home</Link>
            </Button>
            <Button type="button" variant="outline" size="sm" className="border-border" asChild>
              <Link href="/login">Sign In</Link>
            </Button>
            <Button type="button" size="sm" className="bg-primary text-primary-foreground" asChild>
              <Link href="/login">Get Started</Link>
            </Button>
          </div>
        </div>
      </nav>
      <main className="container max-w-4xl mx-auto py-8 px-4">{children}</main>
    </div>
  );
}

export default function DemoReport() {
  const { data: reportData, isLoading } = trpc.reports.getDemoReport.useQuery();
  const { refetch: fetchPdf, isFetching: isPdfLoading } = trpc.reports.getDemoReportPdf.useQuery(undefined, {
    enabled: false,
  });

  if (isLoading) {
    return (
      <DemoReportLayout>
        <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />
          Loading demo report...
        </div>
      </DemoReportLayout>
    );
  }

  if (!reportData) {
    return (
      <DemoReportLayout>
        <div className="p-6 text-center text-muted-foreground">
          <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p>Unable to load demo report. Please try again later.</p>
          <Link href="/">
            <Button variant="outline" size="sm" className="mt-4">
              <ArrowLeft className="w-3.5 h-3.5 mr-1.5" /> Back to Home
            </Button>
          </Link>
        </div>
      </DemoReportLayout>
    );
  }

  function handleDownloadMd() {
    if (!reportData?.markdown) return;
    downloadFile(reportData.markdown, "ghoststrike-demo-report.md", "text/markdown");
  }

  function handleDownloadJson() {
    if (!reportData?.json) return;
    downloadFile(JSON.stringify(reportData.json, null, 2), "ghoststrike-demo-report.json", "application/json");
  }

  async function handleDownloadPdf() {
    const result = await fetchPdf();
    if (result.data?.pdfBase64) {
      downloadPdfFromBase64(result.data.pdfBase64, "ghoststrike-demo-report.pdf");
    }
  }

  return (
    <DemoReportLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <Link
              href="/"
              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 mb-2 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" /> Back to Home
            </Link>
            <p className="text-xs text-muted-foreground mb-1">Sample report — no login required</p>
            <h2 className="text-xl font-semibold text-foreground">{reportData.title}</h2>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="outline"
              className="border-border text-foreground hover:bg-accent gap-1.5"
              onClick={handleDownloadPdf}
              disabled={isPdfLoading}
            >
              {isPdfLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <FileDown className="w-3.5 h-3.5" />
              )}{" "}
              PDF
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="border-border text-foreground hover:bg-accent gap-1.5"
              onClick={handleDownloadMd}
            >
              <Download className="w-3.5 h-3.5" /> Markdown
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="border-border text-foreground hover:bg-accent gap-1.5"
              onClick={handleDownloadJson}
            >
              <Code className="w-3.5 h-3.5" /> JSON
            </Button>
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-8">
          <div
            className="prose prose-invert prose-sm max-w-none
            prose-headings:text-foreground prose-headings:font-semibold
            prose-h1:text-2xl prose-h1:border-b prose-h1:border-border prose-h1:pb-3
            prose-h2:text-xl prose-h2:mt-8 prose-h2:mb-4
            prose-h3:text-base prose-h3:mt-6 prose-h3:mb-3
            prose-h4:text-sm prose-h4:mt-4 prose-h4:mb-2
            prose-p:text-foreground/80 prose-p:leading-relaxed
            prose-a:text-primary prose-a:no-underline hover:prose-a:underline
            prose-strong:text-foreground prose-strong:font-semibold
            prose-code:text-emerald-400 prose-code:bg-black/40 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs
            prose-pre:bg-black/60 prose-pre:border prose-pre:border-border prose-pre:rounded-lg
            prose-table:border-collapse prose-th:border prose-th:border-border prose-th:bg-muted prose-th:px-3 prose-th:py-2 prose-th:text-left prose-th:text-xs prose-th:font-semibold prose-th:text-muted-foreground prose-th:uppercase prose-th:tracking-wider
            prose-td:border prose-td:border-border prose-td:px-3 prose-td:py-2 prose-td:text-sm prose-td:text-foreground/80
            prose-hr:border-border prose-hr:my-8
            prose-li:text-foreground/80 prose-li:leading-relaxed
            prose-blockquote:border-l-primary prose-blockquote:text-muted-foreground
          "
          >
            <Streamdown>{reportData.markdown ?? ""}</Streamdown>
          </div>
        </div>
      </div>
    </DemoReportLayout>
  );
}
