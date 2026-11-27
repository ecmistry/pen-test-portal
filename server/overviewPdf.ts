/**
 * Portal Overview PDF — stakeholder-ready documentation of what Ghoststrike does,
 * which scan sources/tools it uses, and how assessments are delivered.
 * Content mirrors docs/GHOSTSTRIKE_OVERVIEW.md.
 */

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

const PAGE_W = 210;
const MARGIN = 14;
const LINE_H = 6;

export function generateOverviewPdf(generatedAt: Date = new Date()): Buffer {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  let y = 18;

  const ensureSpace = (needed = 20) => {
    if (y + needed > 280) {
      doc.addPage();
      y = 18;
    }
  };

  const addHeading = (text: string, fontSize = 14) => {
    ensureSpace(14);
    doc.setFontSize(fontSize);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(20, 20, 20);
    doc.text(text, MARGIN, y);
    y += LINE_H + 2;
  };

  const addSubheading = (text: string) => {
    ensureSpace(12);
    doc.setFontSize(11);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(40, 40, 40);
    doc.text(text, MARGIN, y);
    y += LINE_H;
  };

  const addParagraph = (text: string) => {
    ensureSpace(12);
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(30, 30, 30);
    const lines = doc.splitTextToSize(text, PAGE_W - 2 * MARGIN);
    doc.text(lines, MARGIN, y);
    y += lines.length * 5 + 3;
  };

  const addBullets = (items: string[]) => {
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(30, 30, 30);
    for (const item of items) {
      ensureSpace(10);
      const lines = doc.splitTextToSize(`•  ${item}`, PAGE_W - 2 * MARGIN);
      doc.text(lines, MARGIN, y);
      y += lines.length * 5 + 1;
    }
    y += 2;
  };

  const addTable = (head: string[], body: string[][], headColor: [number, number, number] = [30, 64, 120]) => {
    ensureSpace(24);
    autoTable(doc, {
      startY: y,
      head: [head],
      body,
      margin: { left: MARGIN, right: MARGIN },
      theme: "grid",
      headStyles: { fillColor: headColor, fontSize: 8, cellPadding: 2 },
      bodyStyles: { fontSize: 8, cellPadding: 2 },
      styles: { overflow: "linebreak" },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  };

  // Cover / title band
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, PAGE_W, 42, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.text("Ghoststrike", MARGIN, 18);
  doc.setFontSize(12);
  doc.setFont("helvetica", "normal");
  doc.text("Automated Penetration Testing Platform — Overview & Instructions", MARGIN, 28);
  doc.setFontSize(9);
  doc.text(`Generated: ${generatedAt.toUTCString()}  |  ghoststrike.tech`, MARGIN, 36);
  doc.setTextColor(0, 0, 0);
  y = 52;

  // 1. Overview
  addHeading("1. What Ghoststrike Does", 13);
  addParagraph(
    "Ghoststrike is an automated penetration testing portal that combines Dynamic Application Security Testing (DAST) and Static Application Security Testing (SAST) to assess web applications. It scans live applications over HTTP and analyses source code in Git repositories, linking findings to URLs, components, and exact source file locations."
  );
  addParagraph(
    "Reports are aligned with industry standards including OWASP Top 10:2021, PTES, NIST SP 800-115, CWE Top 25, CVSSv3.1, MITRE ATT&CK, OWASP API Security Top 10:2023, and ISO/IEC 27001."
  );

  // 2. How it works
  addHeading("2. How It Works", 13);
  addSubheading("Targets");
  addParagraph(
    "A target is an application to scan. Each target has a name, a live URL (for DAST), an optional Git repository URL (for SAST via Semgrep), plus description, tags, and scan frequency for scheduling."
  );
  addSubheading("Scan modes");
  addTable(
    ["Mode", "Scope", "Duration"],
    [
      ["Light", "Fast check — headers, auth, SQLi, XSS, recon with reduced payloads", "< 1 minute"],
      [
        "Full",
        "Complete assessment — 28+ built-in modules plus Nikto, Nuclei, Wapiti, ZAP, and SAST if a repo URL is configured",
        "Several minutes",
      ],
    ]
  );

  // 3. DAST
  addHeading("3. DAST — Dynamic Application Security Testing", 13);
  addParagraph(
    "DAST tests the running application by sending HTTP requests and analysing responses. Ghoststrike includes 24+ built-in DAST modules that run without external tool dependencies."
  );
  addSubheading("Core checks (Light + Full)");
  addTable(
    ["Module", "What it tests"],
    [
      ["Headers", "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy"],
      ["Auth", "Brute-force protection, account enumeration, session/cookie handling"],
      ["SQLi", "SQL injection via error-based and behavioural probes (PayloadsAllTheThings)"],
      ["XSS", "Reflected cross-site scripting including polyglot payloads"],
      ["Recon", "Sensitive file exposure (.env, .git, /.aws/credentials), fingerprinting, SPA FP filtering"],
    ]
  );
  addSubheading("Extended checks (Full mode)");
  addTable(
    ["Module", "What it tests"],
    [
      ["CORS", "Permissive or origin-reflecting CORS policies"],
      ["Directory Traversal", "Path traversal (../etc/passwd and encoded variants)"],
      ["Config / HTTP Methods", "OPTIONS, TRACE, PUT, DELETE, CONNECT — risky methods"],
      ["TLS/SSL", "Certificate validation, protocols, ciphers (optional testssl.sh)"],
      ["Business Logic", "Debug endpoints, CSRF, mass assignment, stack traces"],
      ["GraphQL", "Endpoint detection, introspection, batch abuse, injection"],
      ["SSRF", "URL/redirect/callback parameter injection"],
      ["AI Prompt Injection", "Jailbreak / guardrail bypass probes on LLM endpoints"],
      ["Secret Exposure", "API secrets plus AWS AKIA/ASIA keys; optional canary key-prefix tagging"],
      ["URL Normalisation Bypass", "Encoding, double-slash, dot-segment ACL bypass tricks"],
      ["Insecure HTTP Client", "trustAll, verifyHost false, H2C, rejectUnauthorized"],
      ["JWT Security", "alg:none, expired token acceptance, weak HMAC"],
      ["Cookie Security", "HttpOnly, Secure, SameSite validation"],
      ["HTTP Request Smuggling", "CL.TE and TE.CL desync probes"],
      ["CRLF Injection", "Header injection via CR/LF in query parameters"],
      ["Open Redirect", "Unvalidated redirects on auth / OAuth / SSO paths"],
      ["Prototype Pollution", "__proto__ / constructor.prototype injection"],
    ]
  );
  addSubheading("External DAST tools (Full mode, optional)");
  addTable(
    ["Tool", "Source / what it adds"],
    [
      ["Nikto", "Web server misconfigurations, outdated software, default files"],
      ["Nuclei", "Project Discovery community templates — CVEs, misconfigs, exposures"],
      ["Wapiti", "Black-box crawler: SQLi, XSS, XXE, file disclosure"],
      ["OWASP ZAP", "Session-aware crawling and authenticated DAST baseline"],
    ]
  );

  // 4. SAST
  addHeading("4. SAST — Static Application Security Testing", 13);
  addParagraph(
    "When a target has a Repository URL, full-mode scans clone the Git repo (shallow) and run Semgrep with --config auto (thousands of community security rules). Findings include source file path, line number, code snippet with markers, CWE/OWASP mapping, confidence, and rule references."
  );
  addSubheading("What SAST detects");
  addBullets([
    "Injection — eval/exec, SQL concatenation, template/command injection",
    "Cryptographic issues — weak algorithms, hardcoded keys, insecure random",
    "Authentication — hardcoded credentials, missing auth checks",
    "Input validation — missing sanitisation, path traversal, XSS sinks",
    "Configuration — debug mode, insecure defaults, CORS misconfig in code",
    "Languages — JavaScript/TypeScript, Python, Java, Go, Ruby, PHP, C#, Kotlin, Rust, and more",
  ]);

  // 5. Authenticated scanning
  addHeading("5. Authenticated Scanning", 13);
  addParagraph(
    "Ghoststrike supports Bearer tokens, HTTP Basic credentials, and form/JSON login with session cookie capture. Authenticated scans cover post-login pages, protected APIs, and admin panels, and can tag findings as pre-auth or post-auth."
  );
  addSubheading("Multi-role testing");
  addBullets([
    "Vertical privilege escalation — can a low-privilege user reach admin endpoints?",
    "Horizontal privilege escalation (IDOR) — can one user access another user's resources?",
    "Session expiry — does the server enforce session timeouts?",
  ]);

  // 6. SCA & payload sources
  addHeading("6. SCA & Capability Sources", 13);
  addParagraph(
    "Software Composition Analysis runs via OSV-Scanner or Trivy when dependency manifests are available (e.g. package.json, requirements.txt, pom.xml), identifying known CVEs in third-party libraries."
  );
  addSubheading("How security intelligence stays current");
  addParagraph(
    "A daily in-process cron runs at 03:00 UTC (0 0 3 * * *) to refresh vulnerability and payload intelligence. Admins can also trigger an immediate refresh from the Admin panel. Findings that reference CVEs are enriched with CISA KEV, EPSS, NVD CVSS (when cached), and Exploit-DB search links."
  );
  addTable(
    ["Source", "How Ghoststrike uses it"],
    [
      ["Built-in modules", "Headers, auth, CORS, traversal, recon, and other engine logic shipped with releases"],
      ["PayloadsAllTheThings", "SQLi/XSS payload lists; refreshed daily at 03:00 UTC and via Admin"],
      ["Nuclei templates", "Project Discovery CVE/misconfig templates; daily update at 03:00 UTC"],
      ["CISA KEV", "Known-exploited CVE catalog; daily sync; bumps remediation to P1"],
      ["FIRST.org EPSS", "Exploit probability scores; daily download; confidence + evidence"],
      ["NVD", "Official CVE description/CVSS; KEV warm-cache daily; optional on-scan fetch"],
      ["Trivy / OSV", "Dependency CVEs; Trivy DB refreshed daily; OSV queried live at SCA time"],
      ["Semgrep rules", "Fetched from the Semgrep registry on each SAST scan"],
      ["External tools", "Nikto/ZAP/Nuclei binaries — installed on the scan server; operator-updated"],
    ]
  );

  // 7. Reporting
  addHeading("7. Reporting & Finding Enrichment", 13);
  addParagraph(
    "Every scan produces a professional report exportable as PDF (stakeholder A4), Markdown (in-app / docs workflows), and JSON (CI/CD and integrations). Structure covers document control, scope, executive summary, test coverage, findings summary, detailed findings, recommendations, and standards compliance."
  );
  addSubheading("Each finding is enriched with");
  addBullets([
    "CVSSv3.1 score and vector",
    "CWE ID, OWASP category, MITRE ATT&CK techniques, ISO 27001 controls",
    "Remediation priority (P1–P4) and complexity",
    "Business impact statement in plain language",
    "Evidence (HTTP responses/payloads for DAST; file/line/snippet for SAST)",
  ]);

  // 8. Quality & limitations
  addHeading("8. False Positive Reduction", 13);
  addBullets([
    "SPA detection — suppresses false 'file found' alerts from SPA fallbacks",
    "Content validation — verifies expected file content, not generic HTML shells",
    "Nikto legacy filtering — suppresses outdated CGI probe noise",
    "CSP interpretation — avoids flagging alternate but valid CSP directive forms",
    "Semgrep confidence filtering — includes WARNING/ERROR severity only",
  ]);

  addHeading("9. Getting Started", 13);
  addBullets([
    "Create a target with the application URL (and optional Git repo URL for SAST)",
    "Run a Light or Full scan",
    "Review findings in the UI (URLs, components, source locations)",
    "Export a PDF, Markdown, or JSON report for stakeholders",
    "Track remediation status (open, acknowledged, resolved, false positive)",
  ]);
  addParagraph(
    "To enable SAST: edit the target, set the Git repository URL, then run a Full scan. SAST findings appear with file paths, line numbers, and snippets in the UI and reports."
  );

  addHeading("10. Limitations", 13);
  addBullets([
    "Automated only — does not replace manual penetration testing or expert judgement",
    "DAST is external-perspective; internal network vulns are out of scope",
    "SAST requires a Git-accessible repository; binary-only apps cannot be analysed",
    "External tool coverage depends on installed versions and configuration",
    "Heuristics reduce but cannot eliminate false positives/negatives",
    "Private repos need scan-server read access (SSH keys or tokens)",
  ]);

  // Footer on last page
  ensureSpace(16);
  y += 4;
  doc.setDrawColor(180, 180, 180);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);
  y += 8;
  doc.setFontSize(9);
  doc.setFont("helvetica", "italic");
  doc.setTextColor(80, 80, 80);
  doc.text("Ghoststrike — ghoststrike.tech  |  See also in-app Methodology page for full test methodology.", MARGIN, y);

  // Page numbers
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(120, 120, 120);
    doc.text(`Page ${i} of ${pageCount}`, PAGE_W - MARGIN, 290, { align: "right" });
  }

  return Buffer.from(doc.output("arraybuffer"));
}
