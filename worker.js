/**
 * GitHub Org Webhook -> Cloudflare Worker -> Slack Incoming Webhook
 *
 * Required Worker secrets (Cloudflare Dashboard -> Worker -> Settings -> Variables and Secrets):
 * - SLACK_WEBHOOK_URL        Slack Incoming Webhook URL
 * - GITHUB_WEBHOOK_SECRET    Same secret you set in the GitHub webhook
 *
 * Optional Worker variables (Text, non-secret):
 * - MUTED_EVENTS             Comma-separated event names, example: "gollum,page_build"
 * - MUTED_EVENT_ACTIONS      Comma-separated "event:action" pairs, example: "pull_request:edited,repository:edited"
 * - MUTED_REPOS              Comma-separated repo patterns, example: "miswag/playground,miswag/legacy-*"
 * - SHOW_DELIVERY_ID         "true" or "false" (default: true)
 *
 * If you want to add more GitHub events later:
 * - Append the event name to CONFIG.ALLOWED_EVENTS
 * - Official list and payload schemas:
 *   https://docs.github.com/en/webhooks/webhook-events-and-payloads
 */

const CONFIG = {
  ALLOWED_EVENTS: [
    "branch_protection_configuration",
    "branch_protection_rule",
    "repository_ruleset",
    "code_scanning_alert",
    "member",
    "delete",
    "custom_property_values",
    "deploy_key",
    "deployment",
    "deployment_status",
    "fork",
    "org_block",
    "organization",
    "personal_access_token_request",
    "pull_request",
    "repository",
    "repository_import",
    "repository_vulnerability_alert",
    "secret_scanning_alert_location",
    "secret_scanning_alert",
    "security_and_analysis",
    "team_add",
    "public",
    "gollum",
    "team",
    "release",
    "page_build",
    "milestone",
    "meta",
  ],

  RAW_PAYLOAD_HELP:
    "Raw payload: <https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries|View webhook deliveries in GitHub>",

  MAX_LIST_ITEMS: 6,
};

const ALLOWED_SET = new Set(CONFIG.ALLOWED_EVENTS);

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("OK", { status: 200 });

    const event = request.headers.get("X-GitHub-Event") || "";
    const sig = request.headers.get("X-Hub-Signature-256") || "";
    const deliveryId = request.headers.get("X-GitHub-Delivery") || "";

    if (!ALLOWED_SET.has(event)) return new Response("Ignored", { status: 200 });

    const rawBody = await request.text();

    const ok = await verifyGitHubSig(rawBody, sig, env.GITHUB_WEBHOOK_SECRET);
    if (!ok) return new Response("Invalid signature", { status: 401 });

    const payload = JSON.parse(rawBody);

    const msg = buildSlackMessage({ event, payload, env, deliveryId });
    if (!msg) return new Response("Ignored", { status: 200 });

    await fetch(env.SLACK_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: msg }),
    });

    return new Response("OK", { status: 200 });
  },
};

// ---------------- Noise controls ----------------

function csvSet(v) {
  return new Set((v || "").split(",").map(s => s.trim()).filter(Boolean));
}
function csvArr(v) {
  return (v || "").split(",").map(s => s.trim()).filter(Boolean);
}
function matchRepo(repo, patterns) {
  for (const p of patterns) {
    if (!p) continue;
    if (p.endsWith("*")) {
      if (repo.startsWith(p.slice(0, -1))) return true;
    } else if (repo === p) return true;
  }
  return false;
}
function isMuted(event, action, repo, env) {
  if (csvSet(env.MUTED_EVENTS).has(event)) return true;
  if (action && csvSet(env.MUTED_EVENT_ACTIONS).has(`${event}:${action}`)) return true;
  if (repo && matchRepo(repo, csvArr(env.MUTED_REPOS))) return true;
  return false;
}

// ---------------- GitHub signature verification ----------------

async function verifyGitHubSig(rawBody, sigHeader, secret) {
  if (!sigHeader || !sigHeader.startsWith("sha256=") || !secret) return false;
  const expectedHex = sigHeader.slice("sha256=".length);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  const actualHex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");

  if (actualHex.length !== expectedHex.length) return false;
  let diff = 0;
  for (let i = 0; i < actualHex.length; i++) diff |= actualHex.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  return diff === 0;
}

// ---------------- Slack formatting (no emojis) ----------------

function headerLine(title, action, repo, actor) {
  const a = action ? `\nAction: ${action}` : "";
  const r = repo ? `\nRepo: ${repo}` : "";
  const u = actor ? `\nActor: ${actor}` : "";
  return `:shield: *GitHub Alert: ${title}*${a}${r}${u}`;
}

function firstUrl(p) {
  return (
    p?.html_url ||
    p?.alert?.html_url ||
    p?.pull_request?.html_url ||
    p?.repository?.html_url ||
    p?.release?.html_url ||
    p?.milestone?.html_url ||
    p?.deployment_status?.target_url ||
    p?.pages?.[0]?.html_url ||
    ""
  );
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

function take(list, n) {
  if (!Array.isArray(list)) return [];
  return list.slice(0, n);
}

function summarizeChanges(changesObj) {
  if (!changesObj || typeof changesObj !== "object") return "";
  const keys = Object.keys(changesObj);
  if (!keys.length) return "";

  const parts = [];
  for (const k of keys.slice(0, CONFIG.MAX_LIST_ITEMS)) {
    const prev = changesObj?.[k]?.from ?? changesObj?.[k]?.previous ?? changesObj?.[k];
    parts.push(`${k}: from ${safeStr(prev)}`);
  }
  const more = keys.length > CONFIG.MAX_LIST_ITEMS ? `\nMore changes: ${keys.length - CONFIG.MAX_LIST_ITEMS}` : "";
  return `\nChanges:\n- ${parts.join("\n- ")}${more}`;
}

function buildSlackMessage({ event, payload: p, env, deliveryId }) {
  const action = (p?.action || "").toLowerCase();
  const repo = p?.repository?.full_name || "";
  const actor = p?.sender?.login || "";

  if (isMuted(event, action, repo, env)) return null;

  const url = firstUrl(p);

  const showDelivery = (env.SHOW_DELIVERY_ID || "true") === "true";
  const deliveryLine = showDelivery && deliveryId ? `\nDelivery ID: ${deliveryId}` : "";

  let details = "";

  // pull_request
  if (event === "pull_request") {
    const pr = p?.pull_request;
    const number = pr?.number ?? p?.number ?? "";
    const title = pr?.title || "";
    const baseRef = pr?.base?.ref || "";
    const headRef = pr?.head?.ref || "";
    details += number ? `\nPR: #${number}` : "";
    details += title ? `\nTitle: ${title}` : "";
    details += baseRef && headRef ? `\nBranch: ${headRef} -> ${baseRef}` : "";
    details += pr?.draft === true ? `\nDraft: true` : "";
    details += pr?.merged === true ? `\nMerged: true` : "";
  }

  // gollum (wiki)
  if (event === "gollum") {
    const pages = take(p?.pages, CONFIG.MAX_LIST_ITEMS);
    if (pages.length) {
      details += `\nPages changed: ${p?.pages?.length || pages.length}`;
      const lines = pages.map(pg => {
        const pn = pg?.page_name || pg?.title || "unknown";
        const pa = pg?.action || "edited";
        const pu = pg?.html_url || "";
        return pu ? `${pa}: ${pn}\n${pu}` : `${pa}: ${pn}`;
      });
      details += `\n${lines.join("\n\n")}`;
      if ((p?.pages?.length || 0) > CONFIG.MAX_LIST_ITEMS) {
        details += `\nMore pages: ${(p.pages.length - CONFIG.MAX_LIST_ITEMS)}`;
      }
    }
  }

  // delete (branch or tag deletion)
  if (event === "delete") {
    details += p?.ref_type ? `\nRef type: ${p.ref_type}` : "";
    details += p?.ref ? `\nRef: ${p.ref}` : "";
  }

  // code_scanning_alert
  if (event === "code_scanning_alert") {
    const sev = (p?.alert?.rule?.severity || "").toLowerCase();
    const rule = p?.alert?.rule?.id || p?.alert?.rule?.name || "";
    const state = p?.alert?.state || "";
    const tool = p?.alert?.tool?.name || "";
    details += sev ? `\nSeverity: ${sev}` : "";
    details += state ? `\nState: ${state}` : "";
    details += tool ? `\nTool: ${tool}` : "";
    details += rule ? `\nRule: ${rule}` : "";
  }

  // secret_scanning_alert
  if (event === "secret_scanning_alert") {
    const secretType = p?.alert?.secret_type_display_name || p?.alert?.secret_type || "";
    const state = p?.alert?.state || "";
    const resolution = p?.alert?.resolution || "";
    details += secretType ? `\nSecret type: ${secretType}` : "";
    details += state ? `\nState: ${state}` : "";
    details += resolution ? `\nResolution: ${resolution}` : "";
  }

  // secret_scanning_alert_location
  if (event === "secret_scanning_alert_location") {
    const alertNum = p?.alert?.number ?? p?.alert?.id ?? "";
    const locType = p?.location?.type || p?.location?.details?.type || "";
    const path = p?.location?.details?.path || p?.location?.details?.blob_path || p?.location?.path || "";
    details += alertNum ? `\nAlert: ${alertNum}` : "";
    details += locType ? `\nLocation type: ${locType}` : "";
    details += path ? `\nPath: ${path}` : "";
  }

  // repository_vulnerability_alert (Dependabot related; deprecated in favor of dependabot_alert, but still appears in some setups)
  if (event === "repository_vulnerability_alert") {
    const adv = p?.alert?.security_advisory || {};
    const dep = p?.alert?.dependency || {};
    const pkg = dep?.package?.name || dep?.package || "";
    const manifest = dep?.manifest_path || "";
    const scope = dep?.scope || "";
    const severity = adv?.severity || p?.alert?.security_vulnerability?.severity || "";
    const summary = adv?.summary || "";
    const ghsa = adv?.ghsa_id || "";
    const cve = adv?.cve_id || "";
    details += severity ? `\nSeverity: ${severity}` : "";
    details += pkg ? `\nPackage: ${pkg}` : "";
    details += scope ? `\nScope: ${scope}` : "";
    details += manifest ? `\nManifest: ${manifest}` : "";
    details += ghsa ? `\nGHSA: ${ghsa}` : "";
    details += cve ? `\nCVE: ${cve}` : "";
    details += summary ? `\nSummary: ${summary}` : "";
  }

  // repository_ruleset
  if (event === "repository_ruleset") {
    const rulesetName = p?.ruleset?.name || "";
    const enforcement = p?.ruleset?.enforcement || "";
    details += rulesetName ? `\nRuleset: ${rulesetName}` : "";
    details += enforcement ? `\nEnforcement: ${enforcement}` : "";
    details += summarizeChanges(p?.changes);
  }

  // branch_protection_rule
  if (event === "branch_protection_rule") {
    const ruleName = p?.rule?.name || "";
    const pattern = p?.rule?.pattern || "";
    details += ruleName ? `\nRule: ${ruleName}` : "";
    details += pattern ? `\nPattern: ${pattern}` : "";
    details += summarizeChanges(p?.changes);
  }

  // branch_protection_configuration (enable/disable branch protections broadly)
  if (event === "branch_protection_configuration") {
    details += p?.repository?.default_branch ? `\nDefault branch: ${p.repository.default_branch}` : "";
    details += summarizeChanges(p?.changes);
  }

  // deploy_key
  if (event === "deploy_key") {
    const keyTitle = p?.key?.title || "";
    const keyId = p?.key?.id || "";
    const ro = p?.key?.read_only;
    details += keyTitle ? `\nKey title: ${keyTitle}` : "";
    details += keyId ? `\nKey id: ${keyId}` : "";
    details += typeof ro === "boolean" ? `\nRead only: ${ro}` : "";
  }

  // deployment
  if (event === "deployment") {
    const envName = p?.deployment?.environment || "";
    const ref = p?.deployment?.ref || "";
    const sha = p?.deployment?.sha || "";
    details += envName ? `\nEnvironment: ${envName}` : "";
    details += ref ? `\nRef: ${ref}` : "";
    details += sha ? `\nSHA: ${sha}` : "";
  }

  // deployment_status
  if (event === "deployment_status") {
    const envName = p?.deployment?.environment || "";
    const state = p?.deployment_status?.state || "";
    const desc = p?.deployment_status?.description || "";
    details += envName ? `\nEnvironment: ${envName}` : "";
    details += state ? `\nState: ${state}` : "";
    details += desc ? `\nDescription: ${desc}` : "";
  }

  // fork
  if (event === "fork") {
    const forkee = p?.forkee || {};
    details += forkee?.full_name ? `\nFork: ${forkee.full_name}` : "";
    details += forkee?.owner?.login ? `\nFork owner: ${forkee.owner.login}` : "";
  }

  // member (collaborator add/remove/change)
  if (event === "member") {
    const user = p?.member?.login || "";
    details += user ? `\nUser: ${user}` : "";
  }

  // organization (org renamed, member invited/added/removed, etc)
  if (event === "organization") {
    const org = p?.organization?.login || "";
    const member = p?.membership?.user?.login || p?.member?.login || "";
    const role = p?.membership?.role || "";
    details += org ? `\nOrg: ${org}` : "";
    details += member ? `\nMember: ${member}` : "";
    details += role ? `\nRole: ${role}` : "";
    details += summarizeChanges(p?.changes);
  }

  // org_block
  if (event === "org_block") {
    const org = p?.organization?.login || "";
    const blocked = p?.blocked_user?.login || "";
    details += org ? `\nOrg: ${org}` : "";
    details += blocked ? `\nBlocked user: ${blocked}` : "";
  }

  // personal_access_token_request
  if (event === "personal_access_token_request") {
    const req = p?.personal_access_token_request || {};
    const requester = req?.requester?.login || p?.sender?.login || "";
    const tokenName = req?.token_name || req?.name || "";
    const scopes = Array.isArray(req?.scopes) ? req.scopes.join(", ") : "";
    details += requester ? `\nRequester: ${requester}` : "";
    details += tokenName ? `\nToken name: ${tokenName}` : "";
    details += scopes ? `\nScopes: ${scopes}` : "";
  }

  // repository
  if (event === "repository") {
    const vis = p?.repository?.visibility || (p?.repository?.private ? "private" : "public");
    details += vis ? `\nVisibility: ${vis}` : "";
    details += p?.repository?.default_branch ? `\nDefault branch: ${p.repository.default_branch}` : "";
    details += summarizeChanges(p?.changes);
  }

  // repository_import
  if (event === "repository_import") {
    const status = p?.repository_import?.status || "";
    const vcs = p?.repository_import?.vcs || "";
    details += status ? `\nStatus: ${status}` : "";
    details += vcs ? `\nVCS: ${vcs}` : "";
  }

  // security_and_analysis
  if (event === "security_and_analysis") {
    details += summarizeChanges(p?.changes);
  }

  // team and team_add
  if (event === "team" || event === "team_add") {
    const teamName = p?.team?.name || "";
    const repoName = p?.repository?.full_name || "";
    const perm = p?.team?.permission || "";
    details += teamName ? `\nTeam: ${teamName}` : "";
    details += repoName ? `\nRepo: ${repoName}` : "";
    details += perm ? `\nPermission: ${perm}` : "";
  }

  // public (repository is made public)
  if (event === "public") {
    details += `\nRepository became public`;
  }

  // release
  if (event === "release") {
    const rel = p?.release || {};
    details += rel?.tag_name ? `\nTag: ${rel.tag_name}` : "";
    details += rel?.name ? `\nName: ${rel.name}` : "";
    details += typeof rel?.draft === "boolean" ? `\nDraft: ${rel.draft}` : "";
    details += typeof rel?.prerelease === "boolean" ? `\nPrerelease: ${rel.prerelease}` : "";
  }

  // page_build
  if (event === "page_build") {
    const pb = p?.build || p?.page_build || {};
    const status = pb?.status || "";
    const err = pb?.error?.message || "";
    details += status ? `\nStatus: ${status}` : "";
    details += err ? `\nError: ${err}` : "";
  }

  // milestone
  if (event === "milestone") {
    const ms = p?.milestone || {};
    details += ms?.title ? `\nTitle: ${ms.title}` : "";
    details += ms?.state ? `\nState: ${ms.state}` : "";
    details += ms?.due_on ? `\nDue: ${ms.due_on}` : "";
    details += ms?.open_issues !== undefined ? `\nOpen issues: ${ms.open_issues}` : "";
    details += ms?.closed_issues !== undefined ? `\nClosed issues: ${ms.closed_issues}` : "";
  }

  // custom_property_values
  if (event === "custom_property_values") {
    const props = p?.custom_property_values || p?.properties || null;
    if (props && typeof props === "object") {
      const keys = Object.keys(props);
      details += keys.length ? `\nProperties changed: ${keys.slice(0, CONFIG.MAX_LIST_ITEMS).join(", ")}` : "";
      if (keys.length > CONFIG.MAX_LIST_ITEMS) details += `\nMore properties: ${keys.length - CONFIG.MAX_LIST_ITEMS}`;
    }
    details += summarizeChanges(p?.changes);
  }

  // meta (hook deleted)
  if (event === "meta") {
    const hookId = p?.hook_id || p?.hook?.id || "";
    const action2 = (p?.action || "").toLowerCase();
    details += hookId ? `\nHook id: ${hookId}` : "";
    details += action2 ? `\nMeta action: ${action2}` : "";
  }

  const base = headerLine(event, action, repo, actor);
  const link = url ? `\nLink: ${url}` : "";
  return `${base}${details}${link}${deliveryLine}\n${CONFIG.RAW_PAYLOAD_HELP}`;
}
