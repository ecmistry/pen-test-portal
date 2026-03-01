import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { getLoginUrl } from "@/const";
import { FileText, Loader2 } from "lucide-react";
import { Link } from "wouter";
import { Streamdown } from "streamdown";
import AppLayout from "@/components/AppLayout";

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
      <AppLayout title="Scan methodology">
        <div className="p-6 max-w-4xl mx-auto">
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
            <Button size="sm" className="bg-primary text-primary-foreground" onClick={() => { window.location.href = getLoginUrl(); }}>
              Sign In
            </Button>
          </div>
        </div>
      </nav>
      <main className="container max-w-4xl mx-auto py-8 px-4">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-foreground">Scan methodology & documentation</h1>
          <p className="text-muted-foreground mt-1">
            How Ghoststrike tests your applications and which standards we follow.
          </p>
        </div>
        <MethodologyContent />
      </main>
    </div>
  );
}
