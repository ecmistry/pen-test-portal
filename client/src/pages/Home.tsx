import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Zap, BarChart3, Clock, Lock, Shield, AlertTriangle, CheckCircle, ArrowRight } from "lucide-react";
import { useEffect } from "react";
import { useLocation, Link } from "wouter";

export default function Home() {
  const { user, loading, isAuthenticated } = useAuth();
  const [, navigate] = useLocation();

  useEffect(() => {
    if (!loading && isAuthenticated) {
      navigate("/dashboard");
    }
  }, [loading, isAuthenticated, navigate]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex items-center gap-3 text-muted-foreground">
          <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="w-8 h-8 animate-pulse object-contain" />
          <span>Loading Ghoststrike...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <nav className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="h-8 w-auto object-contain" />
            <span className="font-semibold text-foreground tracking-tight">Ghoststrike</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-border"
              asChild
            >
              <Link href="/login">Sign In</Link>
            </Button>
            <Button
              type="button"
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90"
              asChild
            >
              <Link href="/login">Get Started</Link>
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />
        <div className="absolute top-20 right-20 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />
        <div className="container py-24 lg:py-32">
          <div className="max-w-3xl">
            <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="h-32 w-auto object-contain mb-8" />
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
              <Zap className="w-3.5 h-3.5" />
              Automated Weekly Penetration Testing
            </div>
            <h1 className="text-4xl lg:text-6xl font-bold tracking-tight text-foreground mb-6 leading-tight">
              Continuous Security Testing{" "}
              <span className="text-primary">for Modern Applications</span>
            </h1>
            <p className="text-lg text-muted-foreground mb-10 leading-relaxed max-w-2xl">
              Move beyond annual pen tests. Schedule automated security assessments that run weekly, detect new vulnerabilities as your application evolves, and generate compliance-ready reports aligned with OWASP Top 10, PTES, and NIST standards.
            </p>
            <div className="flex flex-wrap gap-4">
              <Button
                type="button"
                size="lg"
                className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
                asChild
              >
                <Link href="/login">Get Started <ArrowRight className="w-4 h-4" /></Link>
              </Button>
              <Button
                type="button"
                variant="outline"
                size="lg"
                className="border-border text-foreground hover:bg-accent gap-2"
                asChild
              >
                <Link href="/login">
                  <BarChart3 className="w-4 h-4" />
                  View Demo Report
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section className="border-y border-border/50 bg-card/30">
        <div className="container py-8">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {[
              { label: "Security Tests", value: "8+", sub: "Built-in test categories" },
              { label: "Scan Frequency", value: "Daily", sub: "Up to daily scheduling" },
              { label: "Standards", value: "4", sub: "OWASP, PTES, NIST, CWE" },
              { label: "Export Formats", value: "3", sub: "PDF, Markdown, JSON" },
            ].map((stat) => (
              <div key={stat.label} className="text-center">
                <div className="text-3xl font-bold text-primary mb-1">{stat.value}</div>
                <div className="text-sm font-medium text-foreground">{stat.label}</div>
                <div className="text-xs text-muted-foreground">{stat.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="container py-24">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold text-foreground mb-4">Enterprise-Grade Security Testing</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Comprehensive automated testing across the full OWASP Top 10 attack surface, with real-time progress tracking and actionable remediation guidance.
          </p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            {
              icon: Shield,
              title: "OWASP Top 10 Coverage",
              desc: "Automated tests for injection, broken auth, XSS, security misconfigurations, and more — aligned with the latest OWASP Top 10:2021.",
              color: "text-emerald-400",
              bg: "bg-emerald-900/20 border-emerald-800/30",
            },
            {
              icon: Clock,
              title: "Scheduled Pen Tests",
              desc: "Set weekly, daily, or custom cron schedules. Never miss a vulnerability introduced by a deployment again.",
              color: "text-blue-400",
              bg: "bg-blue-900/20 border-blue-800/30",
            },
            {
              icon: Zap,
              title: "Multi-Tool Integration",
              desc: "Integrates with OWASP ZAP, Nikto, and Nuclei alongside built-in security header, auth, SQLi, and XSS scanners.",
              color: "text-yellow-400",
              bg: "bg-yellow-900/20 border-yellow-800/30",
            },
            {
              icon: BarChart3,
              title: "Vulnerability Trends",
              desc: "Track your security posture over time with score trends, severity distributions, and scan history dashboards.",
              color: "text-purple-400",
              bg: "bg-purple-900/20 border-purple-800/30",
            },
            {
              icon: Lock,
              title: "Role-Based Access",
              desc: "Separate user and admin roles. Users manage their own targets; admins have full visibility across all scans and users.",
              color: "text-pink-400",
              bg: "bg-pink-900/20 border-pink-800/30",
            },
            {
              icon: AlertTriangle,
              title: "Compliance Reports",
              desc: "Generate reports with OWASP, PTES, NIST SP 800-115, and CWE references. Export as PDF, Markdown, or JSON.",
              color: "text-orange-400",
              bg: "bg-orange-900/20 border-orange-800/30",
            },
          ].map((f) => (
            <div key={f.title} className={`rounded-xl border p-6 ${f.bg} hover:border-opacity-60 transition-colors`}>
              <div className={`w-10 h-10 rounded-lg bg-current/10 flex items-center justify-center mb-4`}>
                <f.icon className={`w-5 h-5 ${f.color}`} />
              </div>
              <h3 className="font-semibold text-foreground mb-2">{f.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Scan categories */}
      <section className="border-t border-border/50 bg-card/20">
        <div className="container py-20">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-bold text-foreground mb-6">What Gets Tested</h2>
              <p className="text-muted-foreground mb-8">
                Each scan runs a configurable set of security tests, from quick header checks to deep vulnerability scanning with industry-standard tools.
              </p>
              <div className="space-y-3">
                {[
                  { name: "Security Headers", desc: "CSP, HSTS, X-Frame-Options, Referrer-Policy", severity: "High" },
                  { name: "Authentication", desc: "Brute force, account enumeration, session management", severity: "High" },
                  { name: "SQL Injection", desc: "Parameterised query validation, error-based detection", severity: "Critical" },
                  { name: "Cross-Site Scripting", desc: "Reflected, stored, and DOM-based XSS vectors", severity: "High" },
                  { name: "Intelligence Gathering", desc: "Sensitive file exposure, technology fingerprinting", severity: "Medium" },
                  { name: "Nikto / Nuclei / ZAP", desc: "Full web server and application vulnerability scanning", severity: "Variable" },
                ].map((t) => (
                  <div key={t.name} className="flex items-start gap-3 p-3 rounded-lg bg-card/50 border border-border/50">
                    <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-foreground">{t.name}</span>
                        <span className="text-xs text-muted-foreground">— {t.desc}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-card border border-border rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-xs text-muted-foreground ml-2 font-mono">scan-output.log</span>
              </div>
              <div className="font-mono text-xs space-y-1">
                <div className="text-slate-500">=== Ghoststrike Scan Started ===</div>
                <div className="text-slate-300">Target: https://example.com</div>
                <div className="text-slate-300">Tools: headers, auth, sqli, xss</div>
                <div className="text-slate-500 mt-2">─── Starting HEADERS scan ───</div>
                <div className="text-yellow-400">⚠ MISSING: Content-Security-Policy</div>
                <div className="text-yellow-400">⚠ MISSING: Strict-Transport-Security</div>
                <div className="text-emerald-400">✓ PRESENT: X-Content-Type-Options: nosniff</div>
                <div className="text-slate-500 mt-2">─── Starting AUTH scan ───</div>
                <div className="text-red-400">✗ No brute force protection detected</div>
                <div className="text-emerald-400">✓ Account enumeration protection: PASS</div>
                <div className="text-slate-500 mt-2">─── Starting SQLI scan ───</div>
                <div className="text-emerald-400">✓ No SQL injection vulnerabilities detected</div>
                <div className="text-slate-500 mt-2">─── Starting XSS scan ───</div>
                <div className="text-emerald-400">✓ No reflected XSS vulnerabilities detected</div>
                <div className="text-slate-500 mt-2">=== Scan Complete ===</div>
                <div className="text-emerald-400">Security Score: 72/100 | Risk: MEDIUM</div>
                <div className="text-slate-300">Total Findings: 3 (Critical: 0, High: 1, Medium: 2)</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-border/50">
        <div className="container py-20 text-center">
          <h2 className="text-3xl font-bold text-foreground mb-4">Ready to Automate Your Security Testing?</h2>
          <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
            Sign in to add your first target and run a comprehensive penetration test in minutes.
          </p>
          <Button
            type="button"
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            asChild
          >
            <Link href="/login">Start Testing <ArrowRight className="w-4 h-4" /></Link>
          </Button>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 bg-card/20">
        <div className="container py-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <img src="/ghoststrike-logo.png" alt="Ghoststrike" className="h-4 w-auto object-contain" />
            <span>Ghoststrike — Automated Security Assessment Platform</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/methodology" className="hover:text-foreground transition-colors">Scan methodology</Link>
            <span>OWASP · PTES · NIST · CWE</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
