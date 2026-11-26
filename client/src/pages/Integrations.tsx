import AppLayout from "@/components/AppLayout";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { useEffect, useState } from "react";
import { Loader2, Plug, Trash2 } from "lucide-react";

type Severity = "critical" | "high" | "medium" | "low";

export default function Integrations() {
  const utils = trpc.useUtils();
  const { data, isLoading } = trpc.integrations.get.useQuery();

  const [jiraEnabled, setJiraEnabled] = useState(false);
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraToken, setJiraToken] = useState("");
  const [jiraMin, setJiraMin] = useState<Severity>("medium");

  const [ghEnabled, setGhEnabled] = useState(false);
  const [ghRepo, setGhRepo] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [ghMin, setGhMin] = useState<Severity>("high");

  const [linEnabled, setLinEnabled] = useState(false);
  const [linKey, setLinKey] = useState("");
  const [linTeam, setLinTeam] = useState("");
  const [linMin, setLinMin] = useState<Severity>("high");

  useEffect(() => {
    const c = data?.config;
    if (!c) return;
    if (c.jira) {
      setJiraEnabled(c.jira.enabled);
      setJiraBaseUrl(c.jira.baseUrl || "");
      setJiraProjectKey(c.jira.projectKey || "");
      setJiraEmail(c.jira.email || "");
      setJiraToken(c.jira.apiToken || "");
      setJiraMin(c.jira.minSeverity || "medium");
    }
    if (c.github) {
      setGhEnabled(c.github.enabled);
      setGhRepo(c.github.repo || "");
      setGhToken(c.github.token || "");
      setGhMin(c.github.minSeverity || "high");
    }
    if (c.linear) {
      setLinEnabled(c.linear.enabled);
      setLinKey(c.linear.apiKey || "");
      setLinTeam(c.linear.teamId || "");
      setLinMin(c.linear.minSeverity || "high");
    }
  }, [data]);

  const saveMutation = trpc.integrations.save.useMutation({
    onSuccess: () => {
      utils.integrations.get.invalidate();
      toast.success("Integrations saved");
    },
    onError: (e) => toast.error(e.message),
  });

  const deleteMutation = trpc.integrations.delete.useMutation({
    onSuccess: () => {
      utils.integrations.get.invalidate();
      toast.success("Integrations cleared");
    },
    onError: (e) => toast.error(e.message),
  });

  function handleSave() {
    saveMutation.mutate({
      config: {
        jira: jiraEnabled
          ? {
              enabled: true,
              baseUrl: jiraBaseUrl,
              projectKey: jiraProjectKey,
              email: jiraEmail,
              apiToken: jiraToken || "********",
              minSeverity: jiraMin,
              deduplication: true,
            }
          : undefined,
        github: ghEnabled
          ? {
              enabled: true,
              repo: ghRepo,
              token: ghToken || "********",
              minSeverity: ghMin,
            }
          : undefined,
        linear: linEnabled
          ? {
              enabled: true,
              apiKey: linKey || "********",
              teamId: linTeam,
              minSeverity: linMin,
            }
          : undefined,
      },
    });
  }

  return (
    <AppLayout title="Integrations">
      <div className="p-6 space-y-6 max-w-3xl">
        <div>
          <h2 className="text-xl font-semibold text-foreground flex items-center gap-2">
            <Plug className="w-5 h-5" /> Ticketing Integrations
          </h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            Store Jira, GitHub, or Linear credentials (encrypted) for pushing findings from scans and scheduled runs.
          </p>
        </div>

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground py-8">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : (
          <div className="space-y-8">
            <section className="space-y-3 rounded-xl border border-border p-4">
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-foreground">Jira</h3>
                <Switch checked={jiraEnabled} onCheckedChange={setJiraEnabled} />
              </div>
              {jiraEnabled && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label className="text-sm">Base URL</Label>
                    <Input value={jiraBaseUrl} onChange={(e) => setJiraBaseUrl(e.target.value)} placeholder="https://org.atlassian.net" />
                  </div>
                  <div>
                    <Label className="text-sm">Project key</Label>
                    <Input value={jiraProjectKey} onChange={(e) => setJiraProjectKey(e.target.value)} placeholder="SEC" />
                  </div>
                  <div>
                    <Label className="text-sm">Email</Label>
                    <Input value={jiraEmail} onChange={(e) => setJiraEmail(e.target.value)} />
                  </div>
                  <div>
                    <Label className="text-sm">API token</Label>
                    <Input type="password" value={jiraToken} onChange={(e) => setJiraToken(e.target.value)} placeholder="Leave blank to keep saved" />
                  </div>
                </div>
              )}
            </section>

            <section className="space-y-3 rounded-xl border border-border p-4">
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-foreground">GitHub Issues</h3>
                <Switch checked={ghEnabled} onCheckedChange={setGhEnabled} />
              </div>
              {ghEnabled && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label className="text-sm">Repo (owner/name)</Label>
                    <Input value={ghRepo} onChange={(e) => setGhRepo(e.target.value)} placeholder="acme/app" />
                  </div>
                  <div>
                    <Label className="text-sm">Token</Label>
                    <Input type="password" value={ghToken} onChange={(e) => setGhToken(e.target.value)} placeholder="Leave blank to keep saved" />
                  </div>
                </div>
              )}
            </section>

            <section className="space-y-3 rounded-xl border border-border p-4">
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-foreground">Linear</h3>
                <Switch checked={linEnabled} onCheckedChange={setLinEnabled} />
              </div>
              {linEnabled && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label className="text-sm">API key</Label>
                    <Input type="password" value={linKey} onChange={(e) => setLinKey(e.target.value)} placeholder="Leave blank to keep saved" />
                  </div>
                  <div>
                    <Label className="text-sm">Team ID</Label>
                    <Input value={linTeam} onChange={(e) => setLinTeam(e.target.value)} />
                  </div>
                </div>
              )}
            </section>

            <div className="flex gap-2">
              <Button onClick={handleSave} disabled={saveMutation.isPending}>
                {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
                Save
              </Button>
              <Button
                variant="outline"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending || !data?.configured}
              >
                <Trash2 className="w-4 h-4 mr-2" /> Clear
              </Button>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
