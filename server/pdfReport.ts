/**
 * PDF Report — generates a PDF buffer from report data using jsPDF.
 * Mirrors the structure of the Markdown report for consistency.
 */

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import type { ReportData } from "./reportGenerator";

function riskLabel(score: number): string {
  if (score < 40) return "CRITICAL RISK";
  if (score < 60) return "HIGH RISK";
  if (score < 75) return "MEDIUM RISK";
  if (score < 90) return "LOW RISK";
  return "MINIMAL RISK";
}

/** Truncate text for table cells to avoid overflow. */
function truncate(s: string, max: number): string {
  if (!s) return "";
  return s.length <= max ? s : s.slice(0, max - 2) + "..";
}

export function generatePdfReport(data: ReportData): Buffer {
  const { scan, target, findings, generatedAt } = data;
  const score = scan.securityScore ?? 0;
  const tools = (scan.tools || "").split(",").map((t) => t.trim());

  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = 210; // A4 width in mm
  let y = 18;
  const margin = 14;
  const lineH = 6;

  const addHeading = (text: string, fontSize = 14) => {
    if (y > 270) {
      doc.addPage();
      y = 18;
    }
    doc.setFontSize(fontSize);
    doc.setFont("helvetica", "bold");
    doc.text(text, margin, y);
    y += lineH + 2;
  };

  const addParagraph = (text: string, maxLen = 1000) => {
    if (y > 270) {
      doc.addPage();
      y = 18;
    }
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    const str = text.length > maxLen ? text.slice(0, maxLen) + "..." : text;
    const lines = doc.splitTextToSize(str, pageW - 2 * margin);
    doc.text(lines, margin, y);
    y += lines.length * 5 + 3;
  };

  // Title
  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text("Penetration Test Report", margin, y);
  y += 10;

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text(`Generated: ${generatedAt.toUTCString()}`, margin, y);
  y += 5;
  doc.text(`Target: ${target.name} — ${target.url}`, margin, y);
  y += 5;
  doc.text(`Scan ID: ${scan.id}  |  Triggered by: ${scan.triggeredBy === "schedule" ? "Scheduled" : "Manual"}`, margin, y);
  y += 10;

  // 1. Scope of Work
  addHeading("1. Scope of Work", 12);
  addParagraph(`In scope: ${target.name} (${target.url}). Assessment type: Automated penetration test (DAST). Test domains: ${tools.join(", ")}. Scan mode: ${scan.scanMode ?? "light"}.`);
  addParagraph("Out of scope: Manual penetration testing, social engineering, code review (SAST), and systems not explicitly included as the target URL.");
  y += 5;

  // 2. Executive Summary
  addHeading("2. Executive Summary", 12);
  const bySeverity = {
    critical: findings.filter((f) => f.severity === "critical"),
    high: findings.filter((f) => f.severity === "high"),
    medium: findings.filter((f) => f.severity === "medium"),
    low: findings.filter((f) => f.severity === "low"),
    info: findings.filter((f) => f.severity === "info"),
  };
  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Security Score", `${score}/100`],
      ["Risk Level", riskLabel(score)],
      ["Total Findings", String(findings.length)],
      ["Critical", String(bySeverity.critical.length)],
      ["High", String(bySeverity.high.length)],
      ["Medium", String(bySeverity.medium.length)],
      ["Low", String(bySeverity.low.length)],
      ["Informational", String(bySeverity.info.length)],
    ],
    margin: { left: margin },
    theme: "grid",
    headStyles: { fillColor: [66, 66, 66] },
  });
  y = (doc as any).lastAutoTable.finalY + 8;
  if (bySeverity.critical.length > 0 || bySeverity.high.length > 0) {
    addParagraph("Business risk: Critical and high severity findings may expose the organisation to data breach, regulatory penalties, or service compromise.");
  }
  addParagraph(score < 60 ? "Immediate action required to address critical and high severity vulnerabilities." : score < 80 ? "Security improvements recommended." : "Good security posture. Continue monitoring and address remaining findings.");
  y += 5;

  // 3. Test Coverage
  addHeading("3. Test Coverage", 12);
  addParagraph(`Test domains assessed: ${tools.map((t) => t.toUpperCase()).join(", ")}.`);
  y += 5;

  // 4. Findings Summary
  addHeading("4. Findings Summary", 12);
  if (findings.length === 0) {
    addParagraph("No vulnerabilities detected. The target passed all security checks for the selected test categories.");
  } else {
    const severityOrder: Array<"critical" | "high" | "medium" | "low" | "info"> = ["critical", "high", "medium", "low", "info"];
    const body = findings.map((f, i) => [
      String(i + 1),
      truncate(f.title, 50),
      f.severity.toUpperCase(),
      truncate(f.category, 20),
      (f.status ?? "open").toUpperCase(),
    ]);
    autoTable(doc, {
      startY: y,
      head: [["#", "Title", "Severity", "Category", "Status"]],
      body,
      margin: { left: margin },
      theme: "grid",
      headStyles: { fillColor: [66, 66, 66], fontSize: 8 },
      bodyStyles: { fontSize: 8 },
      columnStyles: { 0: { cellWidth: 8 }, 1: { cellWidth: 75 }, 2: { cellWidth: 20 }, 3: { cellWidth: 35 }, 4: { cellWidth: 22 } },
      tableWidth: "wrap",
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }
  if (y > 250) {
    doc.addPage();
    y = 18;
  }

  // 5. Detailed Findings (abbreviated per finding to fit)
  if (findings.length > 0) {
    addHeading("5. Detailed Findings", 12);
    for (const f of findings.slice(0, 30)) {
      if (y > 260) {
        doc.addPage();
        y = 18;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.text(truncate(f.title, 90), margin, y);
      y += 5;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      if (f.description) addParagraph(f.description, 400);
      if (f.recommendation) addParagraph("Recommendation: " + f.recommendation, 350);
      y += 3;
    }
    if (findings.length > 30) {
      addParagraph(`... and ${findings.length - 30} more finding(s). See Markdown or JSON export for full details.`);
    }
  }

  // 6. Recommendations
  if (y > 250) {
    doc.addPage();
    y = 18;
  }
  addHeading("6. Recommendations", 12);
  addParagraph("Address critical and high findings immediately. Schedule weekly automated pen tests, integrate SAST into CI/CD, audit dependencies, and maintain an incident response plan.");

  // 7. Standards & Appendix
  if (y > 255) {
    doc.addPage();
    y = 18;
  }
  addHeading("7. Standards Compliance", 12);
  addParagraph("OWASP Top 10:2021 (A01, A02, A03, A05, A07). PTES phases 2–5. NIST SP 800-115. CWE Top 25. ISO/IEC 27001 A.14.");
  addHeading("Appendix A — Glossary", 12);
  doc.setFontSize(9);
  doc.text("CWE: Common Weakness Enumeration. CVE: Common Vulnerabilities and Exposures. DAST: Dynamic Application Security Testing. OWASP: Open Web Application Security Project. PTES: Penetration Testing Execution Standard. XSS: Cross-Site Scripting. SQLi: SQL Injection. CORS: Cross-Origin Resource Sharing.", margin, y, { maxWidth: pageW - 2 * margin });
  y += 20;

  const pageCount = doc.getNumberOfPages();
  doc.setPage(pageCount);
  const pageHeight = (doc as unknown as { internal: { pageSize: { height: number } } }).internal?.pageSize?.height ?? 297;
  doc.text(`Report generated: ${generatedAt.toUTCString()} | PenTest Portal | Scan ID: ${scan.id}`, margin, pageHeight - 10);

  const out = doc.output("arraybuffer");
  return Buffer.from(out);
}
