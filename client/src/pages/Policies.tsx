import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { useState } from "react";
import { Loader2, ScrollText } from "lucide-react";
import { LIGHT_DEFAULT_TOOLS } from "@shared/scanTools";

export default function Policies() {
  const utils = trpc.useUtils();
  const { data, isLoading } = trpc.policies.list.useQuery();
  const [name, setName] = useState("");
  const [tools, setTools] = useState(LIGHT_DEFAULT_TOOLS.join(","));
  const [scanMode, setScanMode] = useState<"light" | "full">("light");
  const [failOn, setFailOn] = useState<"critical" | "high" | "medium" | "low">("high");
  const [onlyNew, setOnlyNew] = useState(true);
  const [isDefault, setIsDefault] = useState(false);

  const createMutation = trpc.policies.create.useMutation({
    onSuccess: () => {
      utils.policies.list.invalidate();
      setName("");
      toast.success("Policy created");
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteMutation = trpc.policies.delete.useMutation({
    onSuccess: () => {
      utils.policies.list.invalidate();
      toast.success("Policy deleted");
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <AppLayout title="Scan Policies">
      <div className="p-6 space-y-6 max-w-3xl">
        <div>
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <ScrollText className="w-5 h-5" /> Scan policy profiles
          </h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            Org-level baselines for tools, scan mode, and CI gate defaults (org admin).
          </p>
        </div>

        <section className="rounded-xl border border-border p-4 space-y-3">
          <h3 className="text-sm font-semibold">Create policy</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="PCI light gate" />
            </div>
            <div>
              <Label>Tools (comma-separated)</Label>
              <Input value={tools} onChange={(e) => setTools(e.target.value)} />
            </div>
            <div>
              <Label>Scan mode</Label>
              <select
                className="w-full h-9 rounded-md border border-border bg-input px-2 text-sm"
                value={scanMode}
                onChange={(e) => setScanMode(e.target.value as any)}
              >
                <option value="light">Light</option>
                <option value="full">Full</option>
              </select>
            </div>
            <div>
              <Label>Fail on severity</Label>
              <select
                className="w-full h-9 rounded-md border border-border bg-input px-2 text-sm"
                value={failOn}
                onChange={(e) => setFailOn(e.target.value as any)}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)} />
              Fail on new only
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
              Default for org
            </label>
          </div>
          <Button
            disabled={!name || createMutation.isPending}
            onClick={() =>
              createMutation.mutate({
                name,
                tools: tools.split(",").map((t) => t.trim()).filter(Boolean),
                scanMode,
                failOnSeverity: failOn,
                onlyNew,
                isDefault,
              })
            }
          >
            Create
          </Button>
        </section>

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : (
          <div className="divide-y divide-border rounded-xl border border-border">
            {(data ?? []).map((p) => (
              <div key={p.id} className="p-4 flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium text-foreground">
                    {p.name} {p.isDefault ? <span className="text-xs text-primary">(default)</span> : null}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {p.scanMode} · fail≥{p.failOnSeverity} · onlyNew={String(p.onlyNew)}
                  </div>
                  <div className="text-xs font-mono text-muted-foreground mt-1 break-all">{p.tools}</div>
                </div>
                <Button size="sm" variant="outline" onClick={() => deleteMutation.mutate({ id: p.id })}>
                  Delete
                </Button>
              </div>
            ))}
            {!data?.length && (
              <div className="p-6 text-sm text-muted-foreground text-center">No policies yet</div>
            )}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
