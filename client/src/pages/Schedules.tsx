import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { useState } from "react";
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Loader2, Info } from "lucide-react";

const PRESET_CRONS = [
  { label: "Every day at midnight", value: "0 0 0 * * *" },
  { label: "Every Monday at 9am", value: "0 0 9 * * 1" },
  { label: "Every Sunday at 2am", value: "0 0 2 * * 0" },
  { label: "Every 12 hours", value: "0 0 */12 * * *" },
  { label: "First of every month", value: "0 0 0 1 * *" },
  { label: "Custom", value: "custom" },
];

const TOOL_OPTIONS = [
  { value: "headers", label: "Security Headers" },
  { value: "auth", label: "Authentication" },
  { value: "sqli", label: "SQL Injection" },
  { value: "xss", label: "XSS" },
  { value: "recon", label: "Intelligence Gathering" },
  { value: "nikto", label: "Nikto" },
  { value: "nuclei", label: "Nuclei" },
  { value: "zap", label: "OWASP ZAP" },
];

export default function Schedules() {
  const utils = trpc.useUtils();
  const { data: schedules, isLoading } = trpc.schedules.list.useQuery();
  const { data: targets } = trpc.targets.list.useQuery();

  const createMutation = trpc.schedules.create.useMutation({
    onSuccess: () => {
      utils.schedules.list.invalidate();
      toast.success("Schedule created");
      setShowCreate(false);
      resetForm();
    },
    onError: (e) => toast.error(e.message),
  });
  const updateMutation = trpc.schedules.update.useMutation({
    onSuccess: () => {
      utils.schedules.list.invalidate();
      toast.success("Schedule updated");
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteMutation = trpc.schedules.delete.useMutation({
    onSuccess: () => {
      utils.schedules.list.invalidate();
      toast.success("Schedule deleted");
    },
    onError: (e) => toast.error(e.message),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState<string>("");
  const [cronPreset, setCronPreset] = useState("0 0 9 * * 1");
  const [customCron, setCustomCron] = useState("");
  const [selectedTools, setSelectedTools] = useState<string[]>(["headers", "auth", "sqli", "xss"]);

  function resetForm() {
    setSelectedTargetId("");
    setCronPreset("0 0 9 * * 1");
    setCustomCron("");
    setSelectedTools(["headers", "auth", "sqli", "xss"]);
  }

  function toggleTool(tool: string) {
    setSelectedTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    );
  }

  function handleCreate() {
    if (!selectedTargetId) { toast.error("Select a target"); return; }
    const cron = cronPreset === "custom" ? customCron : cronPreset;
    if (!cron) { toast.error("Enter a cron expression"); return; }
    if (selectedTools.length === 0) { toast.error("Select at least one tool"); return; }
    createMutation.mutate({
      targetId: Number(selectedTargetId),
      cronExpression: cron,
      tools: selectedTools,
      enabled: true,
    });
  }

  return (
    <AppLayout title="Schedules">
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-foreground">Scan Schedules</h2>
            <p className="text-sm text-muted-foreground mt-0.5">Automate pen tests on a recurring schedule</p>
          </div>
          <Button
            size="sm"
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            onClick={() => setShowCreate(true)}
          >
            <Plus className="w-3.5 h-3.5" /> New Schedule
          </Button>
        </div>

        {/* Info banner */}
        <div className="flex items-start gap-3 p-4 rounded-lg bg-blue-900/20 border border-blue-800/30 text-sm text-blue-300">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <div>
            Schedules use 6-field cron expressions (seconds minutes hours day month weekday). The scheduler checks every minute and triggers scans when the cron expression matches. Scans run asynchronously in the background.
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12 gap-2 text-muted-foreground">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading schedules...
          </div>
        ) : !schedules || schedules.length === 0 ? (
          <div className="bg-card border border-border rounded-xl p-12 text-center">
            <Clock className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No schedules yet</h3>
            <p className="text-muted-foreground text-sm mb-6">
              Create a schedule to automatically run pen tests on your targets at regular intervals.
            </p>
            <Button
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
              onClick={() => setShowCreate(true)}
            >
              <Plus className="w-3.5 h-3.5" /> Create First Schedule
            </Button>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="divide-y divide-border/50">
              {schedules.map((s: any) => {
                const target = targets?.find((t: any) => t.id === s.targetId);
                return (
                  <div key={s.id} className="flex items-center gap-4 px-5 py-4 hover:bg-accent/20 transition-colors">
                    <button
                      onClick={() => updateMutation.mutate({ id: s.id, enabled: !s.enabled })}
                      className="shrink-0"
                      title={s.enabled ? "Disable" : "Enable"}
                    >
                      {s.enabled ? (
                        <ToggleRight className="w-6 h-6 text-primary" />
                      ) : (
                        <ToggleLeft className="w-6 h-6 text-muted-foreground" />
                      )}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-foreground">
                          {target?.name || `Target #${s.targetId}`}
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${s.enabled ? "bg-emerald-900/30 text-emerald-400 border-emerald-800/30" : "bg-slate-800/40 text-slate-400 border-slate-700/30"}`}>
                          {s.enabled ? "Active" : "Paused"}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-0.5 flex items-center gap-3">
                        <span className="font-mono">{s.cronExpression}</span>
                        <span>·</span>
                        <span>{s.tools}</span>
                      </div>
                      {s.lastRunAt && (
                        <div className="text-xs text-muted-foreground mt-0.5">
                          Last run: {new Date(s.lastRunAt).toLocaleString()}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => deleteMutation.mutate({ id: s.id })}
                      className="p-1.5 rounded text-muted-foreground hover:text-red-400 hover:bg-red-900/20 transition-colors shrink-0"
                      title="Delete schedule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={(o) => { if (!o) { setShowCreate(false); resetForm(); } }}>
        <DialogContent className="bg-card border-border text-foreground max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Scan Schedule</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Target *</Label>
              <Select value={selectedTargetId} onValueChange={setSelectedTargetId}>
                <SelectTrigger className="bg-input border-border text-foreground">
                  <SelectValue placeholder="Select a target..." />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  {targets?.map((t: any) => (
                    <SelectItem key={t.id} value={String(t.id)}>{t.name} — {t.url}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-foreground text-sm mb-1.5 block">Schedule</Label>
              <Select value={cronPreset === "custom" ? "custom" : cronPreset} onValueChange={(v) => { if (v === "custom") { setCronPreset("custom"); } else { setCronPreset(v); } }}>
                <SelectTrigger className="bg-input border-border text-foreground">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  {PRESET_CRONS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {cronPreset === "custom" && (
                <Input
                  placeholder="0 0 9 * * 1  (6-field cron)"
                  value={customCron}
                  onChange={(e) => setCustomCron(e.target.value)}
                  className="mt-2 bg-input border-border text-foreground placeholder:text-muted-foreground font-mono text-sm"
                />
              )}
            </div>

            <div>
              <Label className="text-foreground text-sm mb-2 block">Security Tools</Label>
              <div className="grid grid-cols-2 gap-2">
                {TOOL_OPTIONS.map((tool) => (
                  <label key={tool.value} className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-accent/30 transition-colors">
                    <input
                      type="checkbox"
                      checked={selectedTools.includes(tool.value)}
                      onChange={() => toggleTool(tool.value)}
                      className="accent-primary"
                    />
                    <span className="text-sm text-foreground">{tool.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-border text-foreground" onClick={() => { setShowCreate(false); resetForm(); }}>
              Cancel
            </Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90"
              onClick={handleCreate}
              disabled={createMutation.isPending}
            >
              Create Schedule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppLayout>
  );
}
