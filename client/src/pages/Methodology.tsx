import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { Download, FileText, Loader2 } from "lucide-react";
import { Link } from "wouter";
import { Streamdown } from "streamdown";
import AppLayout from "@/components/AppLayout";

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

function DocsHeader({ showNavHome }: { showNavHome?: boolean }) {
  const whyPdf = trpc.system.getWhyGhoststrikePdf.useQuery(undefined, { enabled: false });
  const overviewPdf = trpc.system.getOverviewPdf.useQuery(undefined, { enabled: false });

  async function downloadWhy() {
    const result = await whyPdf.refetch();
    if (result.data?.pdfBase64) {
      downloadPdfFromBase64(
        result.data.pdfBase64,
        result.data.filename || "why-ghoststrike-is-useful.pdf"
      );
    }
  }

  async function downloadOverview() {
    const result = await overviewPdf.refetch();
    if (result.data?.pdfBase64) {
      downloadPdfFromBase64(
        result.data.pdfBase64,
        result.data.filename || "ghoststrike-portal-overview.pdf"
      );
    }
  }

  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          {showNavHome ? "Scan methodology & documentation" : "Documentation"}
        </h1>
        <p className="text-muted-foreground mt-1">
          How Ghoststrike tests your applications, which tools and sources it uses, and which standards we follow.
          Download the short “Why Ghoststrike is useful” brief for stakeholders, or the full portal overview PDF.
        </p>
      </div>
      <div className="flex flex-col sm:flex-row gap-2 shrink-0">
        <Button
          variant="default"
          size="sm"
          onClick={downloadWhy}
          disabled={whyPdf.isFetching}
          className="gap-2"
        >
          {whyPdf.isFetching ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Download className="w-4 h-4" />
          )}
          Why Ghoststrike is useful (PDF)
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={downloadOverview}
          disabled={overviewPdf.isFetching}
          className="gap-2"
        >
          {overviewPdf.isFetching ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Download className="w-4 h-4" />
          )}
          Full portal overview (PDF)
        </Button>
      </div>
    </div>
  );
}

function MethodologyContent() {
  const { data: markdown, isLoading, error } = trpc.system.getMethodology.useQuery();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading methodology...
      </div>
    );
  }

  if (error || !markdown) {
    return (
      <div className="p-6 text-center text-muted-foreground">
        <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
        <p>Unable to load methodology document. Please try again later.</p>
      </div>
    );
  }

  return (
    <div className="prose prose-invert prose-sm max-w-none dark:prose-invert">
      <Streamdown>{markdown}</Streamdown>
    </div>
  );
}

export default function Methodology() {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isAuthenticated) {
    return (
      <AppLayout title="Methodology & docs">
        <div className="p-6 max-w-4xl mx-auto">
          <DocsHeader />
          <MethodologyContent />
        </div>
      </AppLayout>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <nav className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container flex items-center justify-between h-16">
          <Link href="/" className="flex items-center gap-3">
            <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="h-8 w-auto object-contain" />
            <span className="font-semibold text-foreground tracking-tight">Ghoststrike</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link href="/">
              <Button variant="ghost" size="sm">Home</Button>
            </Link>
            <Link href="/login">
              <Button size="sm" className="bg-primary text-primary-foreground">Sign In</Button>
            </Link>
          </div>
        </div>
      </nav>
      <main className="container max-w-4xl mx-auto py-8 px-4">
        <DocsHeader showNavHome />
        <MethodologyContent />
      </main>
    </div>
  );
}
