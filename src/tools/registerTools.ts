import { readFileSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { BlackDuckClient } from "../client.js";
import { resolveProjectVersion } from "../resolve.js";
import type { VulnerableComponent } from "../types.js";
import {
  VALID_USAGES,
  extractSemverPrefix,
  metaHref,
  parseVersionFromGuidance,
} from "../utils.js";
import { isWriteError, jsonResult, resolveWriteMode } from "./common.js";

function filterBySeverity(components: VulnerableComponent[], severityFilter: string): VulnerableComponent[] {
  if (!severityFilter) return components;
  const allowed = new Set(severityFilter.split(",").map((s) => s.trim().toUpperCase()));
  const filtered: VulnerableComponent[] = [];
  for (const comp of components) {
    const vulns = comp.vulnerabilities.filter((v) => allowed.has(v.severity.toUpperCase()));
    if (!vulns.length) continue;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const v of vulns) {
      const sev = v.severity.toUpperCase();
      if (sev in counts) counts[sev as keyof typeof counts] += 1;
      else counts.UNKNOWN += 1;
    }
    filtered.push({ ...comp, vulnerabilities: vulns, severity_counts: counts });
  }
  return filtered;
}

function vulnSummary(components: VulnerableComponent[]) {
  const severityCounts: Record<string, number> = {};
  let totalVulns = 0;
  for (const comp of components) {
    for (const vuln of comp.vulnerabilities) {
      totalVulns += 1;
      severityCounts[vuln.severity] = (severityCounts[vuln.severity] ?? 0) + 1;
    }
  }
  return { totalVulns, severityCounts };
}

export function registerBlackDuckTools(server: McpServer, client: BlackDuckClient): void {
  // --- Health / identity ---
  server.registerTool("blackduck_health", { title: "Black Duck Health", description: "Check Black Duck API reachability.", inputSchema: {} }, async () =>
    jsonResult(await client.get("/api/current-user")),
  );

  server.registerTool("blackduck_current_user", { title: "Black Duck Current User", description: "Get authenticated Black Duck user details.", inputSchema: {} }, async () =>
    jsonResult(await client.get("/api/current-user")),
  );

  // --- Projects (name + ID based) ---
  server.registerTool(
    "blackduck_list_projects",
    { title: "Black Duck List Projects", description: "List or search Black Duck projects.", inputSchema: { search: z.string().optional(), limit: z.number().int().positive().max(100).optional(), offset: z.number().int().min(0).optional() } },
    async ({ search, limit, offset }) => {
      const q = search ? `name:${search}` : undefined;
      const data = await client.get("/api/projects", { limit: limit ?? 50, offset: offset ?? 0, q });
      return jsonResult(data);
    },
  );

  server.registerTool(
    "blackduck_list_versions",
    { title: "Black Duck List Versions", description: "List versions for a project by exact project name.", inputSchema: { projectName: z.string().min(1) } },
    async ({ projectName }) => {
      const project = await client.findProject(projectName);
      if (!project) return jsonResult({ error: `Project '${projectName}' not found` });
      const projectId = metaHref(project).split("/projects/")[1]?.split("/")[0];
      if (!projectId) return jsonResult({ error: "Could not resolve project ID" });
      const data = (await client.get(`/api/projects/${projectId}/versions`, { limit: 100 })) as { items?: { versionName?: string; _meta?: { href?: string } }[] };
      return jsonResult({
        project: projectName,
        versions: (data.items ?? []).map((v) => ({ name: v.versionName, href: v._meta?.href ?? "" })),
      });
    },
  );

  server.registerTool(
    "blackduck_resolve_project_version",
    { title: "Black Duck Resolve Project Version", description: "Resolve project and version names to IDs and metadata.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => jsonResult(await resolveProjectVersion(client, projectName, versionName)),
  );

  server.registerTool(
    "blackduck_get_project_versions",
    { title: "Black Duck Project Versions by ID", description: "List versions for a project by project ID.", inputSchema: { projectId: z.string().min(1), limit: z.number().int().positive().max(100).optional(), offset: z.number().int().min(0).optional() } },
    async ({ projectId, limit, offset }) => jsonResult(await client.get(`/api/projects/${encodeURIComponent(projectId)}/versions`, { limit, offset })),
  );

  // --- Vulnerabilities ---
  server.registerTool(
    "blackduck_get_vulnerabilities",
    { title: "Black Duck Get Vulnerabilities", description: "Get open vulnerabilities with upgrade guidance for a project version.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), severityFilter: z.string().optional() } },
    async ({ projectName, versionName, severityFilter }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      let components = await client.getVulnerableComponents(resolved.project, resolved.version);
      components = filterBySeverity(components, severityFilter ?? "");
      const { totalVulns, severityCounts } = vulnSummary(components);
      return jsonResult({ project: projectName, version: versionName, summary: { vulnerable_components: components.length, total_vulnerabilities: totalVulns, ...severityCounts }, components });
    },
  );

  server.registerTool(
    "blackduck_get_vulnerability_summary",
    { title: "Black Duck Vulnerability Summary", description: "Concise severity counts and top 10 vulnerable components.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const components = await client.getVulnerableComponents(resolved.project, resolved.version);
      const { totalVulns, severityCounts } = vulnSummary(components);
      const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
      const top = components.slice(0, 10).map((comp) => ({
        component: `${comp.componentName} ${comp.componentVersionName}`,
        type: comp.isTransitive ? "Transitive" : "Direct",
        vuln_count: comp.vulnerabilities.length,
        max_severity: comp.vulnerabilities.length
          ? comp.vulnerabilities.reduce((a, b) => (sevRank[a.severity as keyof typeof sevRank] ?? 0) >= (sevRank[b.severity as keyof typeof sevRank] ?? 0) ? a : b).severity
          : "UNKNOWN",
        upgrade_guidance: comp.upgradeGuidance,
      }));
      return jsonResult({ project: projectName, version: versionName, vulnerable_components: components.length, total_vulnerabilities: totalVulns, severity_counts: severityCounts, top_components: top });
    },
  );

  server.registerTool(
    "blackduck_get_component_detail",
    { title: "Black Duck Component Detail", description: "Full vulnerability details for a component (partial name match).", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1) } },
    async ({ projectName, versionName, componentName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const components = await client.getVulnerableComponents(resolved.project, resolved.version);
      const matches = components.filter((c) => c.componentName.toLowerCase().includes(componentName.toLowerCase()));
      if (!matches.length) return jsonResult({ error: `No vulnerable component matching '${componentName}' found` });
      return jsonResult(matches);
    },
  );

  server.registerTool(
    "blackduck_search_cve",
    { title: "Black Duck Search CVE", description: "Find vulnerable components matching a CVE ID in a project version.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), cveId: z.string().min(1) } },
    async ({ projectName, versionName, cveId }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const components = await client.getVulnerableComponents(resolved.project, resolved.version);
      const needle = cveId.toUpperCase();
      const matches = components
        .map((comp) => ({ ...comp, vulnerabilities: comp.vulnerabilities.filter((v) => v.name.toUpperCase().includes(needle) || v.relatedVulnerability.toUpperCase().includes(needle)) }))
        .filter((c) => c.vulnerabilities.length > 0);
      return jsonResult({ project: projectName, version: versionName, cveId, match_count: matches.length, components: matches });
    },
  );

  // --- Policy ---
  server.registerTool(
    "blackduck_get_policy_violations",
    { title: "Black Duck Policy Violations", description: "Policy violations with rule details for a project version.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const result = await client.getPolicyViolations(resolved.project, resolved.version);
      if ("error" in result) return jsonResult(result);
      return jsonResult({ project: projectName, version: versionName, overallPolicyStatus: result.overallStatus, summary: result.summary, totalViolations: result.totalViolations, violations: result.violations });
    },
  );

  server.registerTool(
    "blackduck_get_version_policy_status",
    { title: "Black Duck Version Policy Status", description: "Quick policy status summary without per-component rule drill-down.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const data = await client.get(`/api/projects/${resolved.projectId}/versions/${resolved.versionId}/policy-status`);
      return jsonResult({ project: projectName, version: versionName, ...(data as object) });
    },
  );

  // --- BOM read ---
  server.registerTool(
    "blackduck_list_bom_components",
    { title: "Black Duck List BOM Components", description: "List all BOM components with optional filters.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), matchTypeFilter: z.string().optional(), reviewStatusFilter: z.string().optional(), usageFilter: z.string().optional() } },
    async ({ projectName, versionName, matchTypeFilter, reviewStatusFilter, usageFilter }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      let items = await client.getAllBomComponents(resolved.projectId, resolved.versionId, reviewStatusFilter || undefined);
      if (matchTypeFilter) {
        const allowed = new Set(matchTypeFilter.split(",").map((s) => s.trim().toUpperCase()));
        items = items.filter((c) => ((c.matchTypes as string[] | undefined) ?? []).some((mt) => allowed.has(mt.toUpperCase())));
      }
      if (usageFilter) {
        const u = usageFilter.toUpperCase();
        items = items.filter((c) => ((c.usages as string[] | undefined) ?? []).some((x) => x.toUpperCase() === u));
      }
      const formatted = items.map((c) => ({
        componentName: c.componentName,
        componentVersionName: c.componentVersionName,
        matchTypes: c.matchTypes,
        usages: c.usages,
        reviewStatus: c.reviewStatus,
        policyStatus: c.policyStatus,
        ignored: c.ignored,
        licenses: (c.licenses as unknown[] | undefined)?.map((l) => (l as { licenseDisplay?: string }).licenseDisplay).filter(Boolean),
        href: metaHref(c),
      }));
      return jsonResult({ project: projectName, version: versionName, total: formatted.length, components: formatted });
    },
  );

  server.registerTool(
    "blackduck_list_project_components",
    { title: "Black Duck List Project Components by ID", description: "List BOM components by project and version ID.", inputSchema: { projectId: z.string().min(1), versionId: z.string().min(1), limit: z.number().int().positive().max(200).optional(), offset: z.number().int().min(0).optional(), sort: z.string().optional(), filter: z.array(z.string().min(1)).optional() } },
    async ({ projectId, versionId, limit, offset, sort, filter }) =>
      jsonResult(await client.get(`/api/projects/${encodeURIComponent(projectId)}/versions/${encodeURIComponent(versionId)}/components`, { limit, offset, sort, filter })),
  );

  server.registerTool(
    "blackduck_list_components",
    { title: "Black Duck List Components by Version ID", description: "List components for a version ID.", inputSchema: { versionId: z.string().min(1), limit: z.number().int().positive().max(100).optional(), offset: z.number().int().min(0).optional() } },
    async ({ versionId, limit, offset }) => jsonResult(await client.get(`/api/versions/${encodeURIComponent(versionId)}/components`, { limit, offset })),
  );

  server.registerTool(
    "blackduck_get_component_origins",
    { title: "Black Duck Component Origins", description: "How Black Duck matched a component (Maven, NPM, snippet, etc.).", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1) } },
    async ({ projectName, versionName, componentName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      return jsonResult(await client.getComponentOrigins(resolved.projectId, resolved.versionId, componentName));
    },
  );

  server.registerTool(
    "blackduck_get_bom_component_files",
    { title: "Black Duck BOM Component Files", description: "Source files that triggered a BOM component match.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1) } },
    async ({ projectName, versionName, componentName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      return jsonResult(await client.getBomComponentFiles(resolved.projectId, resolved.versionId, componentName));
    },
  );

  server.registerTool(
    "blackduck_get_snippet_matches",
    { title: "Black Duck Snippet Matches", description: "All snippet-type BOM matches with file line ranges.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      return jsonResult(await client.getSnippetMatches(resolved.projectId, resolved.versionId));
    },
  );

  server.registerTool(
    "blackduck_find_bad_mappings",
    { title: "Black Duck Find Bad Mappings", description: "Flag suspicious BOM mappings (git SHA versions, github-only, unknown license, etc.).", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      return jsonResult(await client.findBadMappings(resolved.projectId, resolved.versionId));
    },
  );

  server.registerTool(
    "blackduck_get_matched_files",
    { title: "Black Duck Matched Files", description: "Get matched-files from a matched-files URL or path.", inputSchema: { matchedFilesPathOrUrl: z.string().min(1), limit: z.number().int().positive().max(500).optional(), offset: z.number().int().min(0).optional() } },
    async ({ matchedFilesPathOrUrl, limit, offset }) => jsonResult(await client.get(matchedFilesPathOrUrl, { limit, offset })),
  );

  // --- Scans ---
  server.registerTool(
    "blackduck_list_scans",
    { title: "Black Duck List Scans", description: "List code locations/scans for a project version.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1) } },
    async ({ projectName, versionName }) => {
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const scans = await client.listScans(resolved.projectId, resolved.versionId);
      return jsonResult({ project: projectName, version: versionName, total_scans: scans.length, scans });
    },
  );

  // --- KB ---
  server.registerTool(
    "blackduck_search_kb_component",
    { title: "Black Duck Search KB Component", description: "Search the Black Duck Knowledge Base for components and versions.", inputSchema: { componentName: z.string().min(1), maxResults: z.number().int().positive().max(25).optional(), includeVersions: z.boolean().optional() } },
    async ({ componentName, maxResults, includeVersions }) =>
      jsonResult(await client.searchKbComponent(componentName, maxResults ?? 10, includeVersions ?? true)),
  );

  // --- Write tools ---
  server.registerTool(
    "blackduck_set_component_usage",
    { title: "Black Duck Set Component Usage", description: "Mark BOM component usage (e.g. DEV_TOOL_EXCLUDED). dry_run defaults true.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1), usage: z.string().optional(), dryRun: z.boolean().optional() } },
    async ({ projectName, versionName, componentName, usage, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      const usageVal = (usage ?? "DEV_TOOL_EXCLUDED").toUpperCase().replace(/ /g, "_");
      if (!VALID_USAGES.has(usageVal)) return jsonResult({ error: `Invalid usage '${usageVal}'` });
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const matches = await client.findBomComponent(resolved.projectId, resolved.versionId, componentName);
      if (!matches.length) return jsonResult({ error: `No BOM component matching '${componentName}' found` });
      const results = [];
      for (const comp of matches) {
        if (dry) {
          results.push({
            componentName: comp.componentName,
            componentVersionName: comp.componentVersionName,
            currentUsages: comp.usages,
            newUsage: usageVal,
            status: "dry_run",
          });
          continue;
        }
        const outcome = await client.setComponentUsage(resolved.projectId, resolved.versionId, comp, usageVal);
        results.push({ componentName: comp.componentName, componentVersionName: comp.componentVersionName, status: isWriteError(outcome) ? "failed" : "updated", detail: isWriteError(outcome) ? outcome.error : outcome });
      }
      return jsonResult({ project: projectName, version: versionName, dry_run: dry, notice, usage_set_to: usageVal, components: results });
    },
  );

  server.registerTool(
    "blackduck_set_component_license",
    { title: "Black Duck Set Component License", description: "Change BOM component license from KB search. dry_run defaults true.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1), licenseName: z.string().min(1), dryRun: z.boolean().optional() } },
    async ({ projectName, versionName, componentName, licenseName, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const licenses = await client.searchLicenses(licenseName);
      if (!licenses.length) return jsonResult({ error: `No license matching '${licenseName}' found in Black Duck KB` });
      const lic = licenses[0]!;
      const matches = await client.findBomComponent(resolved.projectId, resolved.versionId, componentName);
      if (!matches.length) return jsonResult({ error: `No BOM component matching '${componentName}' found` });
      const results = [];
      for (const comp of matches) {
        if (dry) {
          results.push({ componentName: comp.componentName, currentLicenses: comp.licenses, newLicense: lic.name, status: "dry_run" });
          continue;
        }
        const outcome = await client.setComponentLicense(comp, String(lic.href), String(lic.name));
        results.push({ componentName: comp.componentName, license: lic.name, status: isWriteError(outcome) ? "failed" : "updated", detail: outcome });
      }
      return jsonResult({ project: projectName, version: versionName, dry_run: dry, notice, components: results });
    },
  );

  server.registerTool(
    "blackduck_set_component_version",
    { title: "Black Duck Set Component Version", description: "Point BOM component to a different KB version. dry_run defaults true.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1), newVersion: z.string().min(1), dryRun: z.boolean().optional() } },
    async ({ projectName, versionName, componentName, newVersion, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const matches = await client.findBomComponent(resolved.projectId, resolved.versionId, componentName);
      if (!matches.length) return jsonResult({ error: `No BOM component matching '${componentName}' found` });
      const results = [];
      for (const comp of matches) {
        const kbVer = await client.findComponentVersion(String(comp.componentName), newVersion, comp);
        if (!kbVer) {
          results.push({ componentName: comp.componentName, status: "failed", error: `Version '${newVersion}' not found in KB` });
          continue;
        }
        if (dry) {
          results.push({
            componentName: comp.componentName,
            currentVersion: comp.componentVersionName,
            newVersion,
            status: "dry_run",
          });
          continue;
        }
        const outcome = await client.setComponentVersion(comp, metaHref(kbVer));
        results.push({ componentName: comp.componentName, newVersion, status: isWriteError(outcome) ? "failed" : "updated", detail: outcome });
      }
      return jsonResult({ project: projectName, version: versionName, dry_run: dry, notice, components: results });
    },
  );

  server.registerTool(
    "blackduck_bulk_mark_reviewed",
    { title: "Black Duck Bulk Mark Reviewed", description: "Mark NOT_REVIEWED BOM components as REVIEWED. dry_run defaults true.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().optional(), dryRun: z.boolean().optional() } },
    async ({ projectName, versionName, componentName, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      let items = await client.getAllBomComponents(resolved.projectId, resolved.versionId, "NOT_REVIEWED");
      if (componentName) {
        const s = componentName.toLowerCase();
        items = items.filter((c) => String(c.componentName ?? "").toLowerCase().includes(s));
      }
      const results = [];
      for (const comp of items) {
        if (dry) {
          results.push({ componentName: comp.componentName, reviewStatus: comp.reviewStatus, status: "dry_run" });
          continue;
        }
        const outcome = await client.setComponentReviewStatus(comp, "REVIEWED");
        results.push({ componentName: comp.componentName, status: isWriteError(outcome) ? "failed" : "updated" });
      }
      return jsonResult({ project: projectName, version: versionName, dry_run: dry, notice, reviewed_count: results.length, components: results });
    },
  );

  server.registerTool(
    "blackduck_ignore_snippet",
    { title: "Black Duck Ignore Snippet", description: "Mark a snippet BOM match as ignored/false positive. dry_run defaults true.", inputSchema: { projectName: z.string().min(1), versionName: z.string().min(1), componentName: z.string().min(1), dryRun: z.boolean().optional() } },
    async ({ projectName, versionName, componentName, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const matches = await client.findBomComponent(resolved.projectId, resolved.versionId, componentName);
      const snippetMatches = matches.filter((c) => ((c.matchTypes as string[] | undefined) ?? []).some((mt) => mt.toUpperCase().includes("SNIPPET")));
      if (!snippetMatches.length) return jsonResult({ error: `No snippet component matching '${componentName}' found` });
      const results = [];
      for (const comp of snippetMatches) {
        if (dry) {
          results.push({ componentName: comp.componentName, ignored: comp.ignored, status: "dry_run" });
          continue;
        }
        const outcome = await client.setComponentIgnored(comp, true);
        results.push({ componentName: comp.componentName, status: isWriteError(outcome) ? "failed" : "ignored", detail: outcome });
      }
      return jsonResult({ project: projectName, version: versionName, dry_run: dry, notice, components: results });
    },
  );

  server.registerTool(
    "blackduck_update_package_json",
    { title: "Black Duck Update package.json", description: "Apply Black Duck upgrade guidance to a local package.json. dry_run defaults true.", inputSchema: { packageJsonPath: z.string().min(1), projectName: z.string().min(1), versionName: z.string().min(1), severityFilter: z.string().optional(), dryRun: z.boolean().optional() } },
    async ({ packageJsonPath, projectName, versionName, severityFilter, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      let pkg: Record<string, unknown>;
      try {
        pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8")) as Record<string, unknown>;
      } catch (e) {
        return jsonResult({ error: `Cannot read ${packageJsonPath}: ${e instanceof Error ? e.message : String(e)}` });
      }
      const resolved = await resolveProjectVersion(client, projectName, versionName);
      if ("error" in resolved) return jsonResult(resolved);
      const components = await client.getVulnerableComponents(resolved.project, resolved.version);
      const allowedSevs = new Set((severityFilter ?? "CRITICAL,HIGH").split(",").map((s) => s.trim().toUpperCase()));
      const upgradeMap = new Map<string, { recommended_version: string; guidance: string }>();
      for (const comp of components) {
        const maxSev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find((s) => comp.severity_counts[s] > 0) ?? "UNKNOWN";
        if (!allowedSevs.has(maxSev)) continue;
        const guidance = comp.upgradeGuidance;
        if (!guidance || guidance === "N/A") continue;
        const rec = parseVersionFromGuidance(guidance);
        if (!rec) continue;
        let npmName = comp.componentName;
        if (npmName.includes(":")) npmName = npmName.split(":").pop()!;
        upgradeMap.set(npmName, { recommended_version: rec, guidance });
      }
      const changes: unknown[] = [];
      for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        const deps = pkg[section] as Record<string, string> | undefined;
        if (!deps) continue;
        for (const [pkgName, currentSpec] of Object.entries(deps)) {
          const info = upgradeMap.get(pkgName) ?? [...upgradeMap.entries()].find(([k]) => k.toLowerCase() === pkgName.toLowerCase())?.[1];
          if (!info) continue;
          const newSpec = `${extractSemverPrefix(currentSpec)}${info.recommended_version}`;
          if (newSpec !== currentSpec) {
            changes.push({ section, package: pkgName, current: currentSpec, recommended: newSpec, guidance: info.guidance });
            if (!dry) deps[pkgName] = newSpec;
          }
        }
      }
      if (!dry && changes.length) writeFileSync(packageJsonPath, `${JSON.stringify(pkg, null, 2)}\n`, "utf-8");
      return jsonResult({ package_json: packageJsonPath, dry_run: dry, notice, changes, message: changes.length ? `${dry ? "Would update" : "Updated"} ${changes.length} packages` : "No matching packages to update" });
    },
  );

  // --- Escape hatches ---
  server.registerTool(
    "blackduck_api_get",
    { title: "Black Duck API GET", description: "Read any Black Duck API GET endpoint.", inputSchema: { path: z.string().min(1), limit: z.number().int().positive().max(200).optional(), offset: z.number().int().min(0).optional(), q: z.string().optional(), sort: z.string().optional(), filter: z.array(z.string().min(1)).optional() } },
    async ({ path, limit, offset, q, sort, filter }) => jsonResult(await client.get(path, { limit, offset, q, sort, filter })),
  );

  server.registerTool(
    "blackduck_api_put",
    { title: "Black Duck API PUT", description: "Write any Black Duck API PUT endpoint. Requires BLACKDUCK_WRITE_ENABLED=true.", inputSchema: { path: z.string().min(1), body: z.record(z.unknown()), dryRun: z.boolean().optional() } },
    async ({ path, body, dryRun }) => {
      const { dryRun: dry, notice } = resolveWriteMode(dryRun, client.writeEnabled);
      if (dry) {
        return jsonResult({ dry_run: true, notice, path, body, message: "Preview only — no PUT sent" });
      }
      return jsonResult(await client.put(path, body));
    },
  );
}
