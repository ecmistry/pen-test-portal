/**
 * Stakeholder brief — why Ghoststrike is useful.
 * Short downloadable PDF for leadership / eng / ops audiences.
 */

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

const PAGE_W = 210;
const MARGIN = 14;
const LINE_H = 6;

export function generateWhyGhoststrikePdf(generatedAt: Date = new Date()): Buffer {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  let y = 18;

  const ensureSpace = (needed = 20) => {
    if (y + needed > 280) {
      doc.addPage();
      y = 18;
    }
  };

  const addHeading = (text: string, fontSize = 13) => {
    ensureSpace(14);
    doc.setFontSize(fontSize);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(20, 20, 20);
    doc.text(text, MARGIN, y);
    y += LINE_H + 2;
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

  // Cover
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, PAGE_W, 44, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.text("Why Ghoststrike is useful", MARGIN, 18);
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.text("A short brief for engineering, operations, and leadership", MARGIN, 28);
  doc.setFontSize(9);
  doc.text(`Generated: ${generatedAt.toUTCString()}  |  ghoststrike.tech`, MARGIN, 38);
  doc.setTextColor(0, 0, 0);
  y = 54;

  addHeading("1. The problem it solves");
  addParagraph(
    "Manual penetration tests are valuable but infrequent and expensive. Most applications change every sprint. Ghoststrike gives the team continuous, standards-mapped security testing between external pentests — so issues are found earlier, tracked, and fixed in the same tools engineers already use."
  );

  addHeading("2. Why it is useful");
  addBullets([
    "Faster feedback — light scans in under a minute; full assessments in minutes, on demand or on a schedule",
    "Broader coverage — live-site DAST plus optional Git SAST/SCA/secrets (Semgrep, OSV/Trivy, Gitleaks)",
    "Authenticated depth — bearer, basic, form/tRPC login, multi-role escalation and IDOR checks",
    "Actionable findings — CWE/OWASP/ATT&CK/CVSS mapping, evidence, remediation priority, PDF/Markdown/JSON/SARIF exports",
    "Current threat intel — daily 03:00 UTC refresh of Nuclei templates, PayloadsAllTheThings, CISA KEV, EPSS, Trivy DB, NVD warm-cache",
    "CI and ops fit — severity gates, waivers, webhooks/n8n alerts, Jira/ticketing push so findings do not die in a PDF",
    "AWS exposure detection — finds leaked AKIA/ASIA keys and /.aws/credentials; can tag known honeytoken prefixes without calling AWS APIs",
  ]);

  addHeading("3. Who benefits");
  autoTable(doc, {
    startY: y,
    head: [["Audience", "Value"]],
    body: [
      ["Engineering / product", "Continuous scans on apps and APIs; file/line SAST and dependency CVEs; fix in-sprint"],
      ["Ops / security", "KEV/EPSS prioritisation, schedules, CI gates, alerts and ticketing"],
      ["Leadership / compliance", "Consistent methodology and reports mapped to industry standards"],
    ],
    margin: { left: MARGIN, right: MARGIN },
    theme: "grid",
    headStyles: { fillColor: [30, 64, 120], fontSize: 9, cellPadding: 2 },
    bodyStyles: { fontSize: 9, cellPadding: 2 },
    styles: { overflow: "linebreak" },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  addHeading("4. Standards it aligns to");
  addParagraph(
    "Findings and reports map to OWASP Top 10:2021, OWASP API Security Top 10:2023, PTES, NIST SP 800-115, CWE Top 25, CVSSv3.1, MITRE ATT&CK, and ISO/IEC 27001 (supporting evidence)."
  );

  addHeading("5. How it fits with honeytokens (canaries)");
  addParagraph(
    "Ghoststrike finds exposed AWS credentials before or when they leave a host. A separate infrastructure canary programme (unique fake keys + CloudTrail alerts) detects when a stolen key is used. Together they cover exposure and use — Ghoststrike does not plant CloudTrail canaries itself."
  );

  addHeading("6. What it is not");
  addBullets([
    "Not a replacement for expert manual penetration testing or red-team exercises",
    "Not a substitute for secure SDLC ownership — it surfaces issues; teams still remediate",
    "External scanner depth depends on tools installed on the scan server (Nuclei, ZAP, Semgrep, etc.)",
  ]);

  addHeading("7. Getting value quickly");
  addBullets([
    "Add a target URL (and Git repo URL for SAST/SCA)",
    "Run Light for a quick check or Full for comprehensive coverage",
    "Review findings in the UI; export PDF for stakeholders",
    "Turn on schedules and CI gates for continuous coverage",
    "Download this brief or the full portal overview from Docs at ghoststrike.tech/methodology",
  ]);

  ensureSpace(16);
  y += 4;
  doc.setDrawColor(180, 180, 180);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);
  y += 8;
  doc.setFontSize(9);
  doc.setFont("helvetica", "italic");
  doc.setTextColor(80, 80, 80);
  doc.text("Ghoststrike — ghoststrike.tech  |  For full methodology see Docs in the portal.", MARGIN, y);

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
