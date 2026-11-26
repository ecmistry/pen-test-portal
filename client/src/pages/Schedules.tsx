import AppLayout from "@/components/AppLayout";
import ToolPicker from "@/components/ToolPicker";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { useState } from "react";
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Loader2, Info } from "lucide-react";
import { LIGHT_DEFAULT_TOOLS } from "@shared/scanTools";

const PRESET_CRONS = [
  { label: "Every day at midnight", value: "0 0 0 * * *" },
  { label: "Every Monday at 9am", value: "0 0 9 * * 1" },
  { label: "Every Sunday at 2am", value: "0 0 2 * * 0" },
  { label: "Every 12 hours", value: "0 0 */12 * * *" },
  { label: "First of every month", value: "0 0 0 1 * *" },
  { label: "Custom", value: "custom" },
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
  const [selectedTools, setSelectedTools] = useState<string[]>([...LIGHT_DEFAULT_TOOLS]);
  const [scanMode, setScanMode] = useState<"light" | "full">("light");
  const [autoPush, setAutoPush] = useState(false);

  function resetForm() {
    setSelectedTargetId("");
    setCronPreset("0 0 9 * * 1");
    setCustomCron("");
    setSelectedTools([...LIGHT_DEFAULT_TOOLS]);
    setScanMode("light");
    setAutoPush(false);
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
      scanMode,
      autoPushTicketing: autoPush,
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

        <div className="flex items-start gap-3 p-4 rounded-lg bg-blue-900/20 border border-blue-800/30 text-sm text-blue-300">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <div>
            Schedules use 6-field cron (seconds minutes hours day month weekday). The runner checks every minute and starts scans when the expression matches. Target <code className="text-xs">scanFrequency</code> is informational — schedules are the source of truth.
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12 gap-2 text-muted-foreground">
            <Loader2 className="w-4 h-4 animate-spin" />
          </div>
        ) : !schedules?.length ? (
          <div className="text-center py-16 text-muted-foreground">
            <Clock className="w-10 h-10 mx-auto mb-3 opacity-40" />
            <p className="mb-4">No schedules yet</p>
            <Button size="sm" variant="outline" onClick={() => setShowCreate(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" /> Create First Schedule
            </Button>
          </div>
        ) : (
          <div className="rounded-xl border border-border divide-y divide-border">
            {schedules.map((s: any) => {
              const target = targets?.find((t: any) => t.id === s.targetId);
              return (
                <div key={s.id} className="flex items-center justify-between gap-4 p-4">
                  <div className="min-w-0">
                    <div className="font-medium text-foreground truncate">{target?.name ?? `Target #${s.targetId}`}</div>
                    <div className="text-xs text-muted-foreground font-mono mt-0.5">{s.cronExpression}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {(s.scanMode || "light").toUpperCase()} · {s.tools}
                      {s.autoPushTicketing ? " · auto-push tickets" : ""}
                      {s.lastRunAt ? ` · last ${new Date(s.lastRunAt).toLocaleString()}` : ""}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => updateMutation.mutate({ id: s.id, enabled: !s.enabled })}
                      className="text-muted-foreground hover:text-foreground"
                      title={s.enabled ? "Disable" : "Enable"}
                    >
                      {s.enabled ? <ToggleRight className="w-5 h-5 text-emerald-400" /> : <ToggleLeft className="w-5 h-5" />}
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteMutation.mutate({ id: s.id })}
                      className="text-muted-foreground hover:text-red-400"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <Dialog open={showCreate} onOpenChange={(o) => { if (!o) { setShowCreate(false); resetForm(); } }}>
        <DialogContent className="bg-card border-border text-foreground max-w-2xl max-h-[90vh] overflow-y-auto">
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
              <Label className="text-foreground text-sm mb-1.5 block">Scan mode</Label>
              <Select value={scanMode} onValueChange={(v: "light" | "full") => setScanMode(v)}>
                <SelectTrigger className="bg-input border-border text-foreground">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="full">Full (auto-adds advanced tools)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-foreground text-sm mb-2 block">Security Tools</Label>
              <ToolPicker selected={selectedTools} onChange={setSelectedTools} />
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border p-3">
              <div>
                <div className="text-sm text-foreground">Auto-push to ticketing</div>
                <div className="text-xs text-muted-foreground">Uses saved Integrations after each scheduled scan</div>
              </div>
              <Switch checked={autoPush} onCheckedChange={setAutoPush} />
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
