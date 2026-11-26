import { SCAN_TOOL_OPTIONS, type ScanToolId } from "@shared/scanTools";
import { Label } from "@/components/ui/label";

interface ToolPickerProps {
  selected: string[];
  onChange: (tools: string[]) => void;
  showGroups?: Array<"core" | "advanced" | "external">;
}

export default function ToolPicker({
  selected,
  onChange,
  showGroups = ["core", "advanced", "external"],
}: ToolPickerProps) {
  function toggle(tool: string) {
    onChange(
      selected.includes(tool) ? selected.filter((t) => t !== tool) : [...selected, tool]
    );
  }

  return (
    <div className="space-y-3">
      {showGroups.map((group) => {
        const opts = SCAN_TOOL_OPTIONS.filter((t) => t.group === group);
        if (opts.length === 0) return null;
        return (
          <div key={group}>
            <Label className="text-foreground text-xs uppercase tracking-wide text-muted-foreground mb-1.5 block">
              {group}
            </Label>
            <div className="flex flex-wrap gap-2">
              {opts.map((t) => {
                const active = selected.includes(t.value);
                return (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => toggle(t.value)}
                    className={`text-xs px-2.5 py-1 rounded-md border transition-colors ${
                      active
                        ? "bg-primary/20 border-primary/50 text-foreground"
                        : "bg-muted/30 border-border text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {t.label}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
      <p className="text-xs text-muted-foreground">
        {selected.length} tool{selected.length === 1 ? "" : "s"} selected
        {selected.includes("headers" as ScanToolId) ? "" : ""}
      </p>
    </div>
  );
}
