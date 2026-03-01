import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { useParams, Link } from "wouter";
import { Download, FileText, Loader2, ArrowLeft, Code, FileDown } from "lucide-react";
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

export default function ReportView() {
  const params = useParams<{ scanId: string }>();
  const scanId = Number(params.scanId);

  const { data: reportData, isLoading } = trpc.reports.getMarkdown.useQuery({ scanId });
  const { data: jsonData } = trpc.reports.getJSON.useQuery({ scanId });
  const { refetch: fetchPdf, isFetching: isPdfLoading } = trpc.reports.getPDF.useQuery(
    { scanId },
    { enabled: false }
  );

  if (isLoading) {
    return (
      <AppLayout title="Report">
        <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />
          Loading report...
        </div>
      </AppLayout>
    );
  }

  if (!reportData) {
    return (
      <AppLayout title="Report Not Found">
        <div className="p-6 text-center">
          <FileText className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground mb-4">Report not found. Go back to the scan and generate a report first.</p>
          <Link href={`/scans/${scanId}`}>
            <span className="inline-flex items-center justify-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium border border-border bg-transparent hover:bg-accent">
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Scan
            </span>
          </Link>
        </div>
      </AppLayout>
    );
  }

  function handleDownloadMd() {
    if (!reportData?.markdown) return;
    const filename = `pentest-report-scan-${scanId}.md`;
    downloadFile(reportData.markdown, filename, "text/markdown");
  }

  function handleDownloadJson() {
    if (!jsonData?.json) return;
    const filename = `pentest-report-scan-${scanId}.json`;
    downloadFile(JSON.stringify(jsonData.json, null, 2), filename, "application/json");
  }

  async function handleDownloadPdf() {
    const result = await fetchPdf();
    if (result.data?.pdfBase64) {
      downloadPdfFromBase64(result.data.pdfBase64, `pentest-report-scan-${scanId}.pdf`);
    }
  }

  return (
    <AppLayout title="Security Report">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <Link
              href={`/scans/${scanId}`}
              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 mb-2 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" /> Back to Scan #{scanId}
            </Link>
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
              disabled={!jsonData}
            >
              <Code className="w-3.5 h-3.5" /> JSON
            </Button>
          </div>
        </div>

        {/* Report content */}
        <div className="bg-card border border-border rounded-xl p-8">
          <div className="prose prose-invert prose-sm max-w-none
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
          ">
            <Streamdown>{reportData.markdown || ""}</Streamdown>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
