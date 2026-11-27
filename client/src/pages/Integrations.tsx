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

  const [whUrl, setWhUrl] = useState("");
  const [whType, setWhType] = useState<"slack" | "teams" | "generic">("slack");
  const [whSecret, setWhSecret] = useState("");
  const [webhookList, setWebhookList] = useState<
    Array<{ url: string; type: "slack" | "teams" | "generic"; secret?: string }>
  >([]);

  const [waiverTitle, setWaiverTitle] = useState("");
  const [waiverReason, setWaiverReason] = useState("");
  const [cloneToken, setCloneToken] = useState("");
  const [cloneTokenConfigured, setCloneTokenConfigured] = useState(false);

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
    if (c.webhooks?.length) {
      setWebhookList(
        c.webhooks.map((w) => ({
          url: w.url,
          type: (w.type || "generic") as "slack" | "teams" | "generic",
          secret: w.secret,
        }))
      );
    }
    if (c.repoScan?.githubToken) {
      setCloneTokenConfigured(true);
      setCloneToken("");
    } else {
      setCloneTokenConfigured(false);
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

  const { data: cicdKeys } = trpc.cicd.listKeys.useQuery();
  const [newKeyName, setNewKeyName] = useState("CI key");
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const createKeyMutation = trpc.cicd.createKey.useMutation({
    onSuccess: (data) => {
      utils.cicd.listKeys.invalidate();
      setRevealedKey(data.apiKey);
      toast.success("CI API key created — copy it now");
    },
    onError: (e) => toast.error(e.message),
  });
  const revokeKeyMutation = trpc.cicd.revokeKey.useMutation({
    onSuccess: () => {
      utils.cicd.listKeys.invalidate();
      toast.success("Key revoked");
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
        webhooks: webhookList.length
          ? webhookList.map((w) => ({
              url: w.url,
              type: w.type,
              secret: w.secret || "********",
              events: ["scan.completed", "scan.failed", "gate.failed", "finding.critical"] as Array<
                "scan.completed" | "scan.failed" | "gate.failed" | "finding.critical"
              >,
            }))
          : undefined,
        repoScan:
          cloneToken || cloneTokenConfigured
            ? { githubToken: cloneToken || "********" }
            : undefined,
      },
    });
  }

  const { data: waivers } = trpc.waivers.list.useQuery();
  const createWaiverMutation = trpc.waivers.create.useMutation({
    onSuccess: () => {
      utils.waivers.list.invalidate();
      setWaiverTitle("");
      setWaiverReason("");
      toast.success("Waiver created");
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteWaiverMutation = trpc.waivers.delete.useMutation({
    onSuccess: () => {
      utils.waivers.list.invalidate();
      toast.success("Waiver removed");
    },
    onError: (e) => toast.error(e.message),
  });

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
              <h3 className="font-medium text-foreground">GitHub clone token (SAST / SCA)</h3>
              <p className="text-xs text-muted-foreground">
                Encrypted PAT used to clone private GitHub repos during full scans (e.g.{" "}
                <code className="text-[11px]">gravitee-ops-analytics</code>). Needs{" "}
                Contents: Read. Optional{" "}
                <code className="text-[11px]">GITHUB_TOKEN</code> in server <code className="text-[11px]">.env</code>{" "}
                still overrides this when set.
              </p>
              <div>
                <Label className="text-sm">Personal access token</Label>
                <Input
                  type="password"
                  value={cloneToken}
                  onChange={(e) => setCloneToken(e.target.value)}
                  placeholder={cloneTokenConfigured ? "Saved — leave blank to keep" : "ghp_… or github_pat_…"}
                  autoComplete="off"
                />
                {cloneTokenConfigured && (
                  <p className="text-xs text-emerald-500/90 mt-1">A clone token is already saved.</p>
                )}
              </div>
            </section>

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

            <section className="space-y-3 rounded-xl border border-border p-4">
              <h3 className="font-medium text-foreground">Webhooks (Slack / Teams)</h3>
              <p className="text-xs text-muted-foreground">
                Org-shared notifications for scan complete/fail and critical findings. Config is stored with integrations.
                {data?.orgScoped ? " · Currently org-scoped" : ""}
              </p>
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <Label className="text-sm">Webhook URL</Label>
                  <Input value={whUrl} onChange={(e) => setWhUrl(e.target.value)} placeholder="https://hooks.slack.com/..." />
                </div>
                <div>
                  <Label className="text-sm">Type</Label>
                  <select
                    className="w-full h-9 rounded-md border border-border bg-input px-2 text-sm"
                    value={whType}
                    onChange={(e) => setWhType(e.target.value as any)}
                  >
                    <option value="slack">Slack</option>
                    <option value="teams">Teams</option>
                    <option value="generic">Generic</option>
                  </select>
                </div>
              </div>
              <div>
                <Label className="text-sm">Signing secret (optional)</Label>
                <Input type="password" value={whSecret} onChange={(e) => setWhSecret(e.target.value)} />
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  if (!whUrl) return;
                  setWebhookList((prev) => [...prev, { url: whUrl, type: whType, secret: whSecret || undefined }]);
                  setWhUrl("");
                  setWhSecret("");
                }}
              >
                Add webhook
              </Button>
              <div className="divide-y divide-border rounded-lg border border-border">
                {webhookList.map((w, i) => (
                  <div key={`${w.url}-${i}`} className="flex items-center justify-between gap-3 p-3 text-sm">
                    <div className="min-w-0">
                      <div className="text-foreground truncate">{w.url}</div>
                      <div className="text-xs text-muted-foreground">{w.type}</div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setWebhookList((prev) => prev.filter((_, idx) => idx !== i))}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
                {!webhookList.length && (
                  <div className="p-3 text-xs text-muted-foreground">No webhooks configured</div>
                )}
              </div>
            </section>

            <section className="space-y-3 rounded-xl border border-border p-4">
              <h3 className="font-medium text-foreground">Finding waivers</h3>
              <p className="text-xs text-muted-foreground">
                Suppress known findings across scans and CI gates (org-scoped fingerprint).
              </p>
              <div className="grid gap-2 sm:grid-cols-2">
                <div>
                  <Label className="text-sm">Title</Label>
                  <Input value={waiverTitle} onChange={(e) => setWaiverTitle(e.target.value)} placeholder="Exact finding title" />
                </div>
                <div>
                  <Label className="text-sm">Reason</Label>
                  <Input value={waiverReason} onChange={(e) => setWaiverReason(e.target.value)} />
                </div>
              </div>
              <Button
                size="sm"
                disabled={!waiverTitle || createWaiverMutation.isPending}
                onClick={() =>
                  createWaiverMutation.mutate({ title: waiverTitle, reason: waiverReason || undefined })
                }
              >
                Add waiver
              </Button>
              <div className="divide-y divide-border rounded-lg border border-border">
                {(waivers ?? []).map((w) => (
                  <div key={w.id} className="flex items-center justify-between gap-3 p-3 text-sm">
                    <div className="min-w-0">
                      <div className="text-foreground truncate">{w.title}</div>
                      <div className="text-xs text-muted-foreground font-mono truncate">{w.fingerprint}</div>
                    </div>
                    <Button size="sm" variant="outline" onClick={() => deleteWaiverMutation.mutate({ id: w.id })}>
                      Remove
                    </Button>
                  </div>
                ))}
                {!waivers?.length && (
                  <div className="p-3 text-xs text-muted-foreground">No waivers</div>
                )}
              </div>
            </section>

            <section className="space-y-3 rounded-xl border border-border p-4">
              <h3 className="font-medium text-foreground">CI/CD API keys</h3>
              <p className="text-xs text-muted-foreground">
                Create rotatable keys for pipeline gates (`cicd.scan` / `cicd.status`). Legacy `CICD_API_KEY` env still works.
              </p>
              {revealedKey && (
                <div className="rounded-lg border border-amber-700/40 bg-amber-950/30 p-3 text-xs font-mono break-all text-amber-200">
                  {revealedKey}
                </div>
              )}
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <Label className="text-sm">Name</Label>
                  <Input value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} />
                </div>
                <Button
                  onClick={() => createKeyMutation.mutate({ name: newKeyName || "CI key" })}
                  disabled={createKeyMutation.isPending}
                >
                  Create key
                </Button>
              </div>
              <div className="divide-y divide-border rounded-lg border border-border">
                {(cicdKeys ?? []).map((k) => (
                  <div key={k.id} className="flex items-center justify-between gap-3 p-3 text-sm">
                    <div>
                      <div className="text-foreground">{k.name}</div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {k.keyPrefix}… {k.revokedAt ? "(revoked)" : ""}
                        {k.lastUsedAt ? ` · last used ${new Date(k.lastUsedAt).toLocaleString()}` : ""}
                      </div>
                    </div>
                    {!k.revokedAt && (
                      <Button size="sm" variant="outline" onClick={() => revokeKeyMutation.mutate({ id: k.id })}>
                        Revoke
                      </Button>
                    )}
                  </div>
                ))}
                {!cicdKeys?.length && (
                  <div className="p-3 text-xs text-muted-foreground">No keys yet</div>
                )}
              </div>
            </section>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
