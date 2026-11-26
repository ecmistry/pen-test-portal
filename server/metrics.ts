/**
 * In-process Prometheus-style metrics for Ghoststrike.
 */
type CounterMap = Map<string, number>;

const counters: CounterMap = new Map();
const gauges: CounterMap = new Map();
const histograms: Map<string, number[]> = new Map();

function key(name: string, labels?: Record<string, string>): string {
  if (!labels || !Object.keys(labels).length) return name;
  const parts = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`)
    .join(",");
  return `${name}{${parts}}`;
}

export function incCounter(name: string, labels?: Record<string, string>, by = 1) {
  const k = key(name, labels);
  counters.set(k, (counters.get(k) || 0) + by);
}

export function setGauge(name: string, value: number, labels?: Record<string, string>) {
  gauges.set(key(name, labels), value);
}

export function observeHistogram(name: string, value: number, labels?: Record<string, string>) {
  const k = key(name, labels);
  const arr = histograms.get(k) || [];
  arr.push(value);
  if (arr.length > 500) arr.shift();
  histograms.set(k, arr);
}

export function renderPrometheus(): string {
  const lines: string[] = [];
  lines.push("# HELP ghoststrike_info Ghoststrike portal metrics");
  lines.push("# TYPE ghoststrike_info gauge");
  lines.push('ghoststrike_info{version="1.0.0"} 1');

  for (const [k, v] of Array.from(counters.entries())) {
    const name = k.includes("{") ? k.slice(0, k.indexOf("{")) : k;
    lines.push(`# TYPE ${name} counter`);
    lines.push(`${k} ${v}`);
  }
  for (const [k, v] of Array.from(gauges.entries())) {
    const name = k.includes("{") ? k.slice(0, k.indexOf("{")) : k;
    lines.push(`# TYPE ${name} gauge`);
    lines.push(`${k} ${v}`);
  }
  for (const [k, samples] of Array.from(histograms.entries())) {
    const name = k.includes("{") ? k.slice(0, k.indexOf("{")) : k;
    const sum = samples.reduce((a: number, b: number) => a + b, 0);
    const count = samples.length;
    lines.push(`# TYPE ${name} summary`);
    const labels = k.includes("{") ? k.slice(k.indexOf("{")) : "";
    const base = k.includes("{") ? name : name;
    if (labels) {
      lines.push(`${base}_sum${labels} ${sum}`);
      lines.push(`${base}_count${labels} ${count}`);
    } else {
      lines.push(`${base}_sum ${sum}`);
      lines.push(`${base}_count ${count}`);
    }
  }
  return lines.join("\n") + "\n";
}
