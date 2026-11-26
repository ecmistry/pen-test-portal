/**
 * AI-assisted finding triage using the portal LLM helper.
 */
import { invokeLLM } from "./_core/llm";

export type TriageFinding = {
  id: number;
  title: string;
  severity: string;
  category: string;
  description?: string | null;
  cweId?: string | null;
};

export type TriageResult = {
  summary: string;
  clusters: Array<{ name: string; findingIds: number[]; rationale: string }>;
  priorityOrder: number[];
  remediationThemes: string[];
};

export async function triageFindings(findings: TriageFinding[]): Promise<TriageResult> {
  const open = findings.filter((f) => f.severity !== "info").slice(0, 40);
  if (open.length === 0) {
    return { summary: "No actionable findings to triage.", clusters: [], priorityOrder: [], remediationThemes: [] };
  }

  // Fallback deterministic triage when LLM unavailable
  const fallback = (): TriageResult => {
    const byCat = new Map<string, number[]>();
    for (const f of open) {
      const arr = byCat.get(f.category) || [];
      arr.push(f.id);
      byCat.set(f.category, arr);
    }
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const priorityOrder = [...open]
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
      .map((f) => f.id);
    return {
      summary: `Clustered ${open.length} findings into ${byCat.size} categories by severity.`,
      clusters: Array.from(byCat.entries()).map(([name, findingIds]) => ({
        name,
        findingIds,
        rationale: `Grouped by category ${name}`,
      })),
      priorityOrder,
      remediationThemes: Array.from(byCat.keys()).slice(0, 5),
    };
  };

  try {
    const prompt = `You are a security triage assistant. Given findings JSON, return JSON with keys:
summary (string), clusters (array of {name, findingIds, rationale}), priorityOrder (finding id array highest first), remediationThemes (string array).
Findings: ${JSON.stringify(open.map((f) => ({ id: f.id, title: f.title, severity: f.severity, category: f.category, cweId: f.cweId })))}`;

    const result = await invokeLLM({
      messages: [
        { role: "system", content: "Respond with valid JSON only." },
        { role: "user", content: prompt },
      ],
      maxTokens: 1200,
    });

    const text =
      typeof result === "string"
        ? result
        : (result as any)?.content ||
          (result as any)?.choices?.[0]?.message?.content ||
          (result as any)?.text ||
          "";
    const raw = String(text);
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return fallback();
    const parsed = JSON.parse(jsonMatch[0]) as TriageResult;
    if (!parsed.summary || !Array.isArray(parsed.clusters)) return fallback();
    return parsed;
  } catch {
    return fallback();
  }
}
