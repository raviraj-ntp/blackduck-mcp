import fetch, { type RequestInit } from "node-fetch";
import https from "node:https";
import type { BlackDuckConfig } from "./config.js";
import type {
  BdListResponse,
  BdRecord,
  QueryParams,
  VulnInfo,
  VulnerableComponent,
} from "./types.js";
import {
  BOM_HEADERS,
  BOM_WRITE_HEADERS,
  GIT_SHA_RE,
  KB_HEADERS,
  PROJECT_HEADERS,
  REGISTRY_NAMESPACES,
  SUSPICIOUS_VERSIONS,
  extractId,
  linkHref,
  metaHref,
} from "./utils.js";

export class BlackDuckClient {
  private bearerToken: string | null = null;
  private tokenExpiryMs = 0;
  private readonly agent: https.Agent;

  constructor(private readonly config: BlackDuckConfig) {
    this.agent = new https.Agent({ rejectUnauthorized: config.verifySsl });
  }

  get writeEnabled(): boolean {
    return this.config.writeEnabled;
  }

  async get(path: string, query?: QueryParams, headers?: Record<string, string>): Promise<unknown> {
    await this.authenticate();
    const url = new URL(this.normalizePath(path), this.config.url);
    this.applyQuery(url, query);
    const resp = await fetch(url.toString(), {
      method: "GET",
      headers: { ...this.authHeaders(), ...headers },
      agent: this.agent,
    });
    return this.parseResponse(resp);
  }

  async put(path: string, body: BdRecord, headers?: Record<string, string>): Promise<unknown> {
    await this.authenticate();
    const url = path.startsWith("http") ? path : `${this.config.url}${this.normalizePath(path)}`;
    const resp = await fetch(url, {
      method: "PUT",
      headers: { ...this.authHeaders(), "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
      agent: this.agent,
    } as RequestInit);
    return this.parseResponse(resp, true);
  }

  // --- Project / version discovery ---

  async findProject(projectName: string): Promise<BdRecord | null> {
    const data = (await this.get("/api/projects", { q: `name:${projectName}` })) as BdListResponse;
    for (const project of data.items ?? []) {
      if (project.name === projectName) return project;
    }
    return null;
  }

  async findVersion(project: BdRecord, versionName: string): Promise<BdRecord | null> {
    const versionsLink = linkHref(project, "versions");
    if (!versionsLink) return null;
    const endpoint = versionsLink.replace(this.config.url, "");
    const sep = endpoint.includes("?") ? "&" : "?";
    const data = (await this.get(`${endpoint}${sep}limit=100`)) as BdListResponse;
    for (const version of data.items ?? []) {
      if (version.versionName === versionName) return version;
    }
    return null;
  }

  // --- Vulnerabilities ---

  async getVulnerableComponents(project: BdRecord, version: BdRecord): Promise<VulnerableComponent[]> {
    const projectId = extractId(metaHref(project), "projects");
    const versionId = extractId(metaHref(version), "versions");
    if (!projectId || !versionId) return [];

    const compLookup = new Map<string, BdRecord>();
    let offset = 0;
    const limit = 500;

    while (true) {
      const compData = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/components`,
        { offset, limit },
        BOM_HEADERS,
      )) as BdListResponse;

      for (const comp of compData.items ?? []) {
        const key = `${comp.componentName ?? ""}\0${comp.componentVersionName ?? ""}`;
        let ugLink = "";
        let originUgLink: string | undefined;
        let transitiveUgLink: string | undefined;
        let firstOriginId: string | undefined;

        for (const link of ((comp._meta as BdRecord)?.links as BdRecord[] | undefined) ?? []) {
          if (link.rel === "upgrade-guidance" && typeof link.href === "string") ugLink = link.href;
        }

        for (const origin of (comp.origins as BdRecord[] | undefined) ?? []) {
          if (!firstOriginId) {
            for (const link of ((origin._meta as BdRecord)?.links as BdRecord[] | undefined) ?? []) {
              const href = typeof link.href === "string" ? link.href : "";
              if (["component-origin-copyrights", "upgrade-guidance", "transitive-upgrade-guidance"].includes(String(link.rel)) && href.includes("/origins/")) {
                firstOriginId = href.split("/origins/")[1]?.split("/")[0];
                break;
              }
            }
          }
          for (const link of ((origin._meta as BdRecord)?.links as BdRecord[] | undefined) ?? []) {
            if (link.rel === "transitive-upgrade-guidance" && typeof link.href === "string") {
              transitiveUgLink = link.href;
            }
            if (link.rel === "upgrade-guidance" && typeof link.href === "string") {
              originUgLink = link.href;
            }
          }
        }

        compLookup.set(key, {
          matchTypes: comp.matchTypes,
          usages: comp.usages,
          upgradeGuidanceLink: ugLink,
          originUpgradeGuidanceLink: originUgLink,
          transitiveUpgradeGuidanceLink: transitiveUgLink,
          originId: firstOriginId,
        });
      }

      const total = compData.totalCount ?? 0;
      const items = compData.items ?? [];
      if (offset + limit >= total || items.length === 0) break;
      offset += limit;
    }

    const allVulnItems: BdRecord[] = [];
    offset = 0;
    while (true) {
      const vulnData = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/vulnerable-bom-components`,
        { offset, limit },
        BOM_HEADERS,
      )) as BdListResponse;
      const items = vulnData.items ?? [];
      allVulnItems.push(...items);
      const total = vulnData.totalCount ?? 0;
      if (offset + limit >= total || items.length === 0) break;
      offset += limit;
    }

    const componentVulns = new Map<string, VulnerableComponent>();

    for (const item of allVulnItems) {
      if (item.ignored) continue;
      const compName = String(item.componentName ?? "Unknown");
      const compVersion = String(item.componentVersionName ?? "Unknown");
      const vulnData = (item.vulnerabilityWithRemediation as BdRecord) ?? {};
      const vulnName = String(vulnData.vulnerabilityName ?? "");
      if (!vulnName) continue;

      const remediationStatus = String(vulnData.remediationStatus ?? "NEW");
      if (["PATCHED", "IGNORED", "MITIGATED"].includes(remediationStatus)) continue;

      const key = `${compName}\0${compVersion}`;
      const lookup = compLookup.get(key) ?? {};
      const usages = (lookup.usages as string[] | undefined) ?? [];
      const usagesStr = usages.join(", ").toLowerCase();
      if (["dev_tool_excluded", "devtools", "excluded"].some((kw) => usagesStr.includes(kw))) continue;

      const matchTypes = (lookup.matchTypes as string[] | undefined) ?? [];
      const severity = String(vulnData.severity ?? "UNKNOWN");

      const vulnInfo: VulnInfo = {
        name: vulnName,
        severity,
        baseScore: String(vulnData.baseScore ?? "N/A"),
        overallScore: String(vulnData.overallScore ?? "N/A"),
        exploitabilityScore: String(vulnData.exploitabilitySubscore ?? "N/A"),
        impactScore: String(vulnData.impactSubscore ?? "N/A"),
        source: String(vulnData.source ?? "Unknown"),
        remediationStatus: String(vulnData.remediationStatus ?? "Unknown"),
        cweId: String(vulnData.cweId ?? "N/A"),
        description: String(vulnData.description ?? "No description").slice(0, 500),
        publishedDate: String(vulnData.vulnerabilityPublishedDate ?? "N/A"),
        updatedDate: String(vulnData.vulnerabilityUpdatedDate ?? "N/A"),
        relatedVulnerability: String(vulnData.relatedVulnerability ?? ""),
        bdsaTags: (vulnData.bdsaTags as unknown[]) ?? [],
      };

      if (!componentVulns.has(key)) {
        const isTransitive = matchTypes.some((mt) => mt.toUpperCase().includes("TRANSITIVE"));
        const entry: VulnerableComponent = {
          componentName: compName,
          componentVersionName: compVersion,
          componentVersionOriginName: String(item.componentVersionOriginName ?? ""),
          componentVersionOriginId: String(item.componentVersionOriginId ?? ""),
          packageUrl: String(item.packageUrl ?? ""),
          matchTypes: matchTypes.length ? matchTypes.join(", ") : "N/A",
          usages: usages.length ? usages.join(", ") : "N/A",
          isTransitive,
          vulnerabilities: [],
          upgradeGuidance: "N/A",
          transitiveUpgradeGuidance: "N/A",
          severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
        };

        const ugLink = (lookup.originUpgradeGuidanceLink as string | undefined) ?? (lookup.upgradeGuidanceLink as string | undefined);
        let componentOwnGuidance = "N/A";
        if (ugLink) componentOwnGuidance = await this.getUpgradeGuidanceFromLink(ugLink);
        if (componentOwnGuidance === "N/A" || componentOwnGuidance === "No upgrade guidance available") {
          componentOwnGuidance = `Direct dependency ${compName} ${compVersion} is already at latest version`;
        }

        if (isTransitive) {
          const originId = lookup.originId as string | undefined;
          if (originId) {
            const parentGuidance = await this.getDirectParentTransitiveGuidance(projectId, versionId, originId);
            entry.upgradeGuidance = parentGuidance && parentGuidance !== "N/A"
              ? parentGuidance
              : "Direct dependency is already at latest version (parent component not identified)";
          } else {
            entry.upgradeGuidance = "Direct dependency is already at latest version (parent component not identified)";
          }
        } else {
          entry.upgradeGuidance = componentOwnGuidance;
        }

        componentVulns.set(key, entry);
      }

      const comp = componentVulns.get(key)!;
      comp.vulnerabilities.push(vulnInfo);
      const sev = severity.toUpperCase();
      if (sev in comp.severity_counts) comp.severity_counts[sev] += 1;
      else comp.severity_counts.UNKNOWN += 1;
    }

    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
    return [...componentVulns.values()].sort((a, b) => {
      const aKey = Object.keys(order).find((s) => a.severity_counts[s] > 0) ?? "UNKNOWN";
      const bKey = Object.keys(order).find((s) => b.severity_counts[s] > 0) ?? "UNKNOWN";
      return (order[aKey as keyof typeof order] ?? 5) - (order[bKey as keyof typeof order] ?? 5);
    });
  }

  // --- BOM ---

  async findBomComponent(projectId: string, versionId: string, componentName: string): Promise<BdRecord[]> {
    const allItems: BdRecord[] = [];
    let offset = 0;
    const limit = 500;
    while (true) {
      const data = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/components`,
        { offset, limit },
        BOM_HEADERS,
      )) as BdListResponse;
      const items = data.items ?? [];
      allItems.push(...items);
      const total = data.totalCount ?? 0;
      if (offset + limit >= total || items.length === 0) break;
      offset += limit;
    }
    const searchLower = componentName.toLowerCase();
    return allItems.filter((c) => String(c.componentName ?? "").toLowerCase().includes(searchLower));
  }

  async getAllBomComponents(
    projectId: string,
    versionId: string,
    reviewStatusFilter?: string,
  ): Promise<BdRecord[]> {
    const allItems: BdRecord[] = [];
    let offset = 0;
    const limit = 500;
    while (true) {
      const data = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/components`,
        { offset, limit },
        BOM_HEADERS,
      )) as BdListResponse;
      const items = data.items ?? [];
      allItems.push(...items);
      const total = data.totalCount ?? 0;
      if (offset + limit >= total || items.length === 0) break;
      offset += limit;
    }
    if (!reviewStatusFilter) return allItems;
    return allItems.filter((c) => (c.reviewStatus ?? "NOT_REVIEWED") === reviewStatusFilter);
  }

  async setComponentUsage(_projectId: string, _versionId: string, component: BdRecord, usage: string): Promise<unknown> {
    const compHref = metaHref(component);
    if (!compHref) return { error: "Component has no href — cannot update" };
    component.usages = [usage];
    return this.put(compHref, component, BOM_WRITE_HEADERS);
  }

  async setComponentReviewStatus(component: BdRecord, status = "REVIEWED"): Promise<unknown> {
    const compHref = metaHref(component);
    if (!compHref) return { error: "Component has no href — cannot update" };
    component.reviewStatus = status;
    return this.put(compHref, component, BOM_WRITE_HEADERS);
  }

  async setComponentIgnored(component: BdRecord, ignored = true): Promise<unknown> {
    const compHref = metaHref(component);
    if (!compHref) return { error: "Component has no href — cannot update" };
    component.ignored = ignored;
    return this.put(compHref, component, BOM_WRITE_HEADERS);
  }

  async setComponentLicense(component: BdRecord, licenseHref: string, licenseName = ""): Promise<unknown> {
    const compHref = metaHref(component);
    if (!compHref) return { error: "Component has no href — cannot update" };
    component.licenses = [{ license: licenseHref, licenseDisplay: licenseName, licenseType: "OPEN_SOURCE" }];
    return this.put(compHref, component, BOM_WRITE_HEADERS);
  }

  async setComponentVersion(component: BdRecord, newVersionHref: string): Promise<unknown> {
    const compHref = metaHref(component);
    if (!compHref) return { error: "Component has no href — cannot update" };
    component.componentVersion = newVersionHref;
    return this.put(compHref, component, BOM_WRITE_HEADERS);
  }

  async getComponentOrigins(projectId: string, versionId: string, componentName: string): Promise<BdRecord[]> {
    const matches = await this.findBomComponent(projectId, versionId, componentName);
    return matches.map((comp) => {
      const originsDetail = ((comp.origins as BdRecord[] | undefined) ?? []).map((origin) => {
        const ns = String(origin.externalNamespace ?? "");
        const extId = String(origin.externalId ?? "");
        return {
          namespace: ns,
          externalId: extId,
          packageUrl: ns && extId ? `${ns}:${extId}` : extId || ns,
          originName: origin.name ?? "",
          originId: origin.externalId ?? "",
        };
      });
      return {
        componentName: comp.componentName ?? "",
        componentVersionName: comp.componentVersionName ?? "",
        matchTypes: comp.matchTypes ?? [],
        reviewStatus: comp.reviewStatus ?? "",
        ignored: comp.ignored ?? false,
        origins: originsDetail,
        href: metaHref(comp),
      };
    });
  }

  async getBomComponentFiles(projectId: string, versionId: string, componentName: string): Promise<BdRecord[]> {
    const matches = await this.findBomComponent(projectId, versionId, componentName);
    const results: BdRecord[] = [];

    for (const comp of matches) {
      const compHref = metaHref(comp);
      const compIdInBom = extractId(compHref, "components");
      let mfUrl = linkHref(comp, "matched-files");
      if (!mfUrl && compIdInBom) {
        mfUrl = `${this.config.url}/api/projects/${projectId}/versions/${versionId}/components/${compIdInBom}/matched-files`;
      }

      const filesList: BdRecord[] = [];
      if (mfUrl) {
        const mfData = (await this.get(mfUrl, undefined, BOM_HEADERS)) as BdListResponse;
        for (const f of mfData.items ?? []) {
          const fileEntry: BdRecord = {
            filePath: f.filePath ?? f.path ?? "",
            archiveContext: f.archiveContext ?? "",
            matchType: f.fileMatchType ?? f.matchType ?? "",
            usages: f.usages ?? [],
          };
          const snippet = f.fileSnippetBomComponents as BdRecord | undefined;
          if (snippet) {
            fileEntry.snippetStartLine = snippet.sourceStartLine;
            fileEntry.snippetEndLine = snippet.sourceEndLine;
            fileEntry.snippetScore = snippet.matchScore;
            fileEntry.snippetIgnored = snippet.ignored ?? false;
          }
          filesList.push(fileEntry);
        }
      }

      results.push({
        componentName: comp.componentName ?? "",
        componentVersionName: comp.componentVersionName ?? "",
        matchTypes: comp.matchTypes ?? [],
        reviewStatus: comp.reviewStatus ?? "",
        ignored: comp.ignored ?? false,
        totalFiles: filesList.length,
        files: filesList,
        href: compHref,
      });
    }
    return results;
  }

  async getSnippetMatches(projectId: string, versionId: string): Promise<BdRecord[]> {
    const allComps = await this.getAllBomComponents(projectId, versionId);
    const snippetComps = allComps.filter((c) =>
      ((c.matchTypes as string[] | undefined) ?? []).some((mt) => mt.toUpperCase().includes("SNIPPET")),
    );

    const results: BdRecord[] = [];
    for (const comp of snippetComps) {
      const compHref = metaHref(comp);
      const compIdInBom = extractId(compHref, "components");
      let mfUrl = linkHref(comp, "matched-files");
      if (!mfUrl && compIdInBom) {
        mfUrl = `${this.config.url}/api/projects/${projectId}/versions/${versionId}/components/${compIdInBom}/matched-files`;
      }

      const filesList: BdRecord[] = [];
      if (mfUrl) {
        const mfData = (await this.get(mfUrl, undefined, BOM_HEADERS)) as BdListResponse;
        for (const f of mfData.items ?? []) {
          const fileEntry: BdRecord = {
            filePath: f.filePath ?? f.path ?? "",
            matchType: f.fileMatchType ?? f.matchType ?? "",
          };
          const snippet = f.fileSnippetBomComponents as BdRecord | undefined;
          if (snippet) {
            fileEntry.projectStartLine = snippet.sourceStartLine;
            fileEntry.projectEndLine = snippet.sourceEndLine;
            fileEntry.ossStartLine = snippet.snippetSourceStartLine;
            fileEntry.ossEndLine = snippet.snippetSourceEndLine;
            fileEntry.matchScore = snippet.matchScore;
            fileEntry.snippetIgnored = snippet.ignored ?? false;
          }
          filesList.push(fileEntry);
        }
      }

      const licenses: string[] = [];
      for (const lic of (comp.licenses as BdRecord[] | undefined) ?? []) {
        const ld = String(lic.licenseDisplay ?? "");
        if (ld && !licenses.includes(ld)) licenses.push(ld);
      }

      results.push({
        componentName: comp.componentName ?? "",
        componentVersionName: comp.componentVersionName ?? "",
        reviewStatus: comp.reviewStatus ?? "",
        ignored: comp.ignored ?? false,
        licenses,
        matchedFiles: filesList,
        href: compHref,
      });
    }
    return results;
  }

  async findBadMappings(projectId: string, versionId: string): Promise<BdRecord> {
    const allComps = await this.getAllBomComponents(projectId, versionId);
    const modifiedOnlyTypes = new Set(["FILE_SOME_FILES_MODIFIED", "FILE_FILES_ADDED_DELETED_AND_MODIFIED"]);
    const flagged: BdRecord[] = [];
    const byIssue: Record<string, number> = {};

    for (const comp of allComps) {
      if (comp.ignored) continue;
      const name = String(comp.componentName ?? "");
      const version = String(comp.componentVersionName ?? "");
      const matchTypes = (comp.matchTypes as string[] | undefined) ?? [];
      const origins = (comp.origins as BdRecord[] | undefined) ?? [];
      const namespaces = origins.map((o) => String(o.externalNamespace ?? "").toLowerCase()).filter(Boolean);
      const hasExternalId = origins.some((o) => o.externalId);

      const licenses: string[] = [];
      for (const lic of (comp.licenses as BdRecord[] | undefined) ?? []) {
        const ld = String(lic.licenseDisplay ?? "");
        if (ld) licenses.push(ld);
      }

      const matchTypesUpper = new Set(matchTypes.map((mt) => mt.toUpperCase()));
      const issues: string[] = [];
      const descriptions: string[] = [];

      if (!origins.length || !hasExternalId) {
        issues.push("no_origins");
        descriptions.push("No origin / externalId — cannot verify component identity");
      }
      if (version && GIT_SHA_RE.test(version)) {
        issues.push("git_hash_version");
        descriptions.push(`Version '${version}' is a git commit SHA, not a release tag`);
      }
      if (!version.trim()) {
        issues.push("no_version");
        descriptions.push("componentVersionName is empty — version unknown");
      }
      if (SUSPICIOUS_VERSIONS.has(version.toLowerCase())) {
        issues.push("suspicious_version");
        descriptions.push(`Version '${version}' is a placeholder / non-specific value`);
      }
      if (namespaces.length && namespaces.every((ns) => ns === "github")) {
        issues.push("github_only_origin");
        descriptions.push("All origins map to 'github' — source repo match instead of a package registry");
      } else if (namespaces.length && !namespaces.some((ns) => REGISTRY_NAMESPACES.has(ns))) {
        issues.push("non_registry_origin");
        descriptions.push(`Origin namespace(s) ${namespaces} are not standard package registries`);
      }
      if (!licenses.length || licenses.some((l) => l.toLowerCase().includes("unknown"))) {
        issues.push("unknown_license");
        descriptions.push(`License is unknown or missing: ${licenses.length ? licenses : ["(none)"]}`);
      }
      if (
        matchTypesUpper.size &&
        [...matchTypesUpper].every((mt) => modifiedOnlyTypes.has(mt)) &&
        ![...matchTypesUpper].some((mt) => !modifiedOnlyTypes.has(mt))
      ) {
        issues.push("modified_only_match");
        descriptions.push(
          "Only FILE_SOME_FILES_MODIFIED / FILE_FILES_ADDED_DELETED_AND_MODIFIED match types — possible fork with wrong component mapping",
        );
      }

      if (!issues.length) continue;
      for (const issue of issues) byIssue[issue] = (byIssue[issue] ?? 0) + 1;

      flagged.push({
        componentName: name,
        componentVersionName: version,
        matchTypes,
        origins: origins.map((o) => ({
          namespace: o.externalNamespace ?? "",
          externalId: o.externalId ?? "",
        })),
        licenses,
        reviewStatus: comp.reviewStatus ?? "",
        issues,
        issueDescriptions: descriptions,
        href: metaHref(comp),
      });
    }

    return { total_scanned: allComps.length, total_flagged: flagged.length, by_issue: byIssue, flagged };
  }

  // --- KB / licenses ---

  async searchLicenses(search: string, limit = 20): Promise<BdRecord[]> {
    const data = (await this.get("/api/licenses", { q: `name:${search}`, limit }, KB_HEADERS)) as BdListResponse;
    return (data.items ?? []).map((item) => ({
      name: item.name ?? "",
      spdxId: (item.spdx as BdRecord | undefined)?.id ?? item.spdxId ?? "",
      licenseFamily: (item.licenseFamily as BdRecord | undefined)?.name ?? "",
      ownership: item.ownership ?? "",
      href: metaHref(item),
    }));
  }

  async findComponentVersion(
    componentName: string,
    versionName: string,
    bomComponent?: BdRecord,
  ): Promise<BdRecord | null> {
    if (bomComponent) {
      let compVersionUrl = String(bomComponent.componentVersion ?? "");
      if (!compVersionUrl) compVersionUrl = linkHref(bomComponent, "componentVersion");
      if (compVersionUrl) {
        const parts = compVersionUrl.split("/versions/");
        if (parts.length >= 2) {
          const result = await this.searchKbVersions(`${parts[0]}/versions`, versionName);
          if (result) return result;
        }
      }
      let componentUrl = String(bomComponent.component ?? "");
      if (!componentUrl) componentUrl = linkHref(bomComponent, "component");
      if (componentUrl) {
        const kbCompData = (await this.get(componentUrl, undefined, KB_HEADERS)) as BdRecord;
        const versionsHref = linkHref(kbCompData, "versions");
        if (versionsHref) {
          const result = await this.searchKbVersions(versionsHref, versionName);
          if (result) return result;
        }
      }
    }

    const searchNames = [componentName];
    if (componentName.includes("/")) searchNames.push(componentName.split("/").pop()!);

    for (const name of searchNames) {
      const kbComponent = await this.findKbComponent(name);
      if (!kbComponent) continue;
      const versionsHref = linkHref(kbComponent, "versions");
      if (versionsHref) {
        const result = await this.searchKbVersions(versionsHref, versionName);
        if (result) return result;
      }
    }
    return null;
  }

  async searchKbComponent(query: string, maxResults = 10, includeVersions = true): Promise<BdRecord[]> {
    const data = (await this.get("/api/components", { q: `name:${query}`, limit: maxResults, offset: 0 }, KB_HEADERS)) as BdListResponse;
    const results: BdRecord[] = [];

    for (const item of data.items ?? []) {
      const compHref = metaHref(item);
      const compId = extractId(compHref, "components");
      const entry: BdRecord = {
        componentId: compId,
        componentName: item.name ?? "",
        description: String(item.description ?? "").slice(0, 200),
        primaryLanguage: item.primaryLanguage ?? "",
        homepage: item.url ?? "",
        approvalStatus: item.approvalStatus ?? "",
        totalVersions: 0,
        versions: [],
        href: compHref,
      };

      if (includeVersions && compId) {
        const verData = (await this.get(`/api/components/${compId}/versions`, { limit: 25, offset: 0, sort: "releasedOn desc" }, KB_HEADERS)) as BdListResponse;
        entry.totalVersions = verData.totalCount ?? 0;
        const versionsList: BdRecord[] = [];
        for (const v of verData.items ?? []) {
          let purl = "";
          for (const origin of (v.origins as BdRecord[] | undefined) ?? []) {
            if (origin.externalNamespace && origin.externalId) {
              purl = `${origin.externalNamespace}:${origin.externalId}`;
              break;
            }
          }
          versionsList.push({
            versionName: v.versionName ?? "",
            releasedOn: typeof v.releasedOn === "string" ? v.releasedOn.slice(0, 10) : "",
            packageUrl: purl,
            versionHref: metaHref(v),
          });
        }
        entry.versions = versionsList;
      }
      results.push(entry);
    }
    return results;
  }

  // --- Policy ---

  async getPolicyViolations(project: BdRecord, version: BdRecord): Promise<BdRecord> {
    const projectId = extractId(metaHref(project), "projects");
    const versionId = extractId(metaHref(version), "versions");
    if (!projectId || !versionId) return { error: "Could not resolve project/version IDs" };

    const policyStatus = (await this.get(
      `/api/projects/${projectId}/versions/${versionId}/policy-status`,
      undefined,
      BOM_HEADERS,
    )) as BdRecord;

    const overallStatus = policyStatus.overallStatus ?? "UNKNOWN";
    const statusCounts: Record<string, unknown> = {};
    for (const entry of (policyStatus.componentVersionStatusCounts as BdRecord[] | undefined) ?? []) {
      statusCounts[String(entry.name)] = entry.value;
    }

    const violations: BdRecord[] = [];
    let offset = 0;
    const limit = 500;

    while (true) {
      const compData = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/components`,
        { offset, limit },
        BOM_HEADERS,
      )) as BdListResponse;

      for (const comp of compData.items ?? []) {
        const compPolicy = String(comp.policyStatus ?? "NOT_IN_VIOLATION");
        if (!["IN_VIOLATION", "IN_VIOLATION_OVERRIDDEN"].includes(compPolicy)) continue;

        const rulesLink = linkHref(comp, "policy-rules");
        const ruleDetails: BdRecord[] = [];
        if (rulesLink) {
          const rulesData = (await this.get(rulesLink, undefined, BOM_HEADERS)) as BdListResponse;
          for (const rule of rulesData.items ?? []) {
            const conditions: string[] = [];
            const expression = (rule.expression as BdRecord) ?? {};
            for (const expr of (expression.expressions as BdRecord[] | undefined) ?? []) {
              const op = String(expr.operation ?? "");
              const name = String(expr.name ?? "");
              const values = (expr.values as unknown[]) ?? [];
              if (name && op) conditions.push(`${name} ${op} ${values.map(String).join(", ")}`);
            }
            ruleDetails.push({
              name: rule.name ?? "Unknown Rule",
              description: rule.description ?? "",
              severity: rule.severity ?? "UNSPECIFIED",
              policyApprovalStatus: rule.policyApprovalStatus ?? "",
              conditions,
            });
          }
        }

        const violationEntry: BdRecord = {
          componentName: comp.componentName ?? "Unknown",
          componentVersionName: comp.componentVersionName ?? "Unknown",
          policyStatus: compPolicy,
          packageUrl: "",
          licenses: [] as string[],
          licenseType: "",
          violatedRules: ruleDetails,
        };

        for (const origin of (comp.origins as BdRecord[] | undefined) ?? []) {
          const licenseInfo = (origin.license as BdRecord) ?? {};
          const licName = String(licenseInfo.licenseDisplay ?? "");
          const licType = String(licenseInfo.licenseType ?? "");
          const licenses = violationEntry.licenses as string[];
          if (licName && !licenses.includes(licName)) licenses.push(licName);
          if (!violationEntry.licenseType && licType) violationEntry.licenseType = licType;
          const pkgUrl = String(origin.externalId ?? "");
          if (pkgUrl && !violationEntry.packageUrl) violationEntry.packageUrl = pkgUrl;
        }

        for (const lic of (comp.licenses as BdRecord[] | undefined) ?? []) {
          const licDisplay = String(lic.licenseDisplay ?? "");
          const licType = String(lic.licenseType ?? "");
          const licenses = violationEntry.licenses as string[];
          if (licDisplay && !licenses.includes(licDisplay)) licenses.push(licDisplay);
          if (!violationEntry.licenseType && licType) violationEntry.licenseType = licType;
        }

        violations.push(violationEntry);
      }

      const total = compData.totalCount ?? 0;
      const items = compData.items ?? [];
      if (offset + limit >= total || items.length === 0) break;
      offset += limit;
    }

    return { overallStatus, summary: statusCounts, totalViolations: violations.length, violations };
  }

  // --- Scans ---

  async listScans(projectId: string, versionId: string): Promise<BdRecord[]> {
    const allScans: BdRecord[] = [];
    let offset = 0;
    const limit = 100;

    while (true) {
      const data = (await this.get(
        `/api/projects/${projectId}/versions/${versionId}/codelocations`,
        { offset, limit },
        PROJECT_HEADERS,
      )) as BdListResponse;
      const items = data.items ?? [];
      if (!items.length) break;

      for (const item of items) {
        let summaryStatus = "UNKNOWN";
        let filesCount = 0;
        let scanSource = "";
        const summaryHref = linkHref(item, "latest-scan-summary");
        if (summaryHref) {
          const summary = (await this.get(summaryHref, undefined, PROJECT_HEADERS)) as BdRecord;
          summaryStatus = String(summary.status ?? "UNKNOWN");
          filesCount = Number(summary.numFiles ?? 0);
          scanSource = String(summary.scanSource ?? "");
        }
        allScans.push({
          name: item.name ?? "",
          type: item.type ?? "UNKNOWN",
          scanSource: scanSource || item.scanType || "",
          status: summaryStatus,
          numFiles: filesCount,
          scanSize: item.scanSize ?? 0,
          createdAt: item.createdAt ?? "",
          updatedAt: item.updatedAt ?? "",
          url: item.url ?? "",
          href: metaHref(item),
        });
      }

      const total = data.totalCount ?? 0;
      if (offset + limit >= total) break;
      offset += limit;
    }

    return allScans.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  }

  // --- Private helpers ---

  private async findKbComponent(name: string): Promise<BdRecord | null> {
    const data = (await this.get("/api/components", { q: `name:${name}`, limit: 50 }, KB_HEADERS)) as BdListResponse;
    const searchLower = name.toLowerCase();
    for (const item of data.items ?? []) {
      if (String(item.name ?? "").toLowerCase() === searchLower) return item;
    }
    for (const item of data.items ?? []) {
      if (String(item.name ?? "").toLowerCase().includes(searchLower)) return item;
    }
    return null;
  }

  private async searchKbVersions(versionsUrl: string, versionName: string): Promise<BdRecord | null> {
    const path = versionsUrl.replace(this.config.url, "");
    let verData = (await this.get(path, { q: `versionName:${versionName}`, limit: 50 }, KB_HEADERS)) as BdListResponse;
    for (const v of verData.items ?? []) {
      if (v.versionName === versionName) return v;
    }
    verData = (await this.get(path, { limit: 200, sort: "releaseDate:desc" }, KB_HEADERS)) as BdListResponse;
    for (const v of verData.items ?? []) {
      if (v.versionName === versionName) return v;
    }
    return null;
  }

  private async getUpgradeGuidanceFromLink(ugLink: string): Promise<string> {
    const path = ugLink.replace(this.config.url, "");
    const data = (await this.get(path, undefined, KB_HEADERS)) as BdRecord;
    if (!data || Object.keys(data).length === 0) return "No upgrade guidance available";

    const parts: string[] = [];
    const shortTerm = data.shortTerm as BdRecord | undefined;
    const longTerm = data.longTerm as BdRecord | undefined;
    if (shortTerm) {
      const r = (shortTerm.vulnerabilityRisk as BdRecord) ?? {};
      parts.push(
        `Short-term: Upgrade to ${shortTerm.versionName ?? "Unknown"} (remaining: C:${r.critical ?? 0} H:${r.high ?? 0} M:${r.medium ?? 0} L:${r.low ?? 0})`,
      );
    }
    if (longTerm) {
      const r = (longTerm.vulnerabilityRisk as BdRecord) ?? {};
      parts.push(
        `Long-term: Upgrade to ${longTerm.versionName ?? "Unknown"} (remaining: C:${r.critical ?? 0} H:${r.high ?? 0} M:${r.medium ?? 0} L:${r.low ?? 0})`,
      );
    }
    return parts.length ? parts.join(" | ") : "No upgrade guidance available";
  }

  private async getTransitiveUpgradeGuidance(tugLink: string): Promise<string> {
    const path = tugLink.replace(this.config.url, "");
    const data = (await this.get(path, undefined, KB_HEADERS)) as BdRecord;
    if (!data || Object.keys(data).length === 0) return "N/A";

    const compName = String(data.componentName ?? "");
    const currentVersion = String(data.versionName ?? "");
    const parts: string[] = [];
    const shortTerm = data.shortTerm as BdRecord | undefined;
    const longTerm = data.longTerm as BdRecord | undefined;
    if (shortTerm) {
      const r = (shortTerm.vulnerabilityRisk as BdRecord) ?? {};
      parts.push(
        `Short-term: Upgrade ${compName} from ${currentVersion} → ${shortTerm.versionName ?? "Unknown"} (remaining: C:${r.critical ?? 0} H:${r.high ?? 0} M:${r.medium ?? 0} L:${r.low ?? 0})`,
      );
    }
    if (longTerm) {
      const r = (longTerm.vulnerabilityRisk as BdRecord) ?? {};
      parts.push(
        `Long-term: Upgrade ${compName} from ${currentVersion} → ${longTerm.versionName ?? "Unknown"} (remaining: C:${r.critical ?? 0} H:${r.high ?? 0} M:${r.medium ?? 0} L:${r.low ?? 0})`,
      );
    }
    return parts.length ? parts.join(" | ") : "N/A";
  }

  private async getDirectParentTransitiveGuidance(
    projectId: string,
    versionId: string,
    originId: string,
  ): Promise<string> {
    const depPathUrl = `/api/project/${projectId}/version/${versionId}/origin/${originId}/dependency-paths`;
    const data = (await this.get(depPathUrl, { limit: 100 }, BOM_HEADERS)) as BdListResponse;
    if (!data?.items?.length) return "N/A";

    for (const depPathItem of data.items) {
      const path = (depPathItem.path as BdRecord[] | undefined) ?? [];
      if (path.length < 2) continue;
      for (const node of [...path].slice(1).reverse()) {
        const nodeName = node.name;
        const nodeVersion = node.version ?? "unknown version";
        if (!nodeName) continue;
        for (const link of ((node._meta as BdRecord)?.links as BdRecord[] | undefined) ?? []) {
          if (link.rel === "transitive-upgrade-guidance" && typeof link.href === "string") {
            const guidance = await this.getTransitiveUpgradeGuidance(link.href);
            if (guidance && guidance !== "N/A") return guidance;
            return `Direct dependency ${nodeName} ${nodeVersion} is already at latest version`;
          }
        }
      }
    }
    return "N/A";
  }

  private async authenticate(): Promise<void> {
    if (this.bearerToken && Date.now() < this.tokenExpiryMs) return;
    const resp = await fetch(`${this.config.url}/api/tokens/authenticate`, {
      method: "POST",
      headers: {
        Authorization: `token ${this.config.apiToken}`,
        Accept: "application/vnd.blackducksoftware.user-4+json",
      },
      agent: this.agent,
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Black Duck auth ${resp.status}: ${text.slice(0, 500)}`);
    }
    const data = (await resp.json()) as { bearerToken?: string; expiresInMilliseconds?: number };
    if (!data.bearerToken) throw new Error("Black Duck auth did not return bearerToken");
    this.bearerToken = data.bearerToken;
    this.tokenExpiryMs = Date.now() + (data.expiresInMilliseconds ?? 7_200_000) - 60_000;
  }

  private authHeaders(): Record<string, string> {
    return {
      Accept: "application/vnd.blackducksoftware.project-detail-5+json",
      Authorization: `Bearer ${this.bearerToken}`,
    };
  }

  private normalizePath(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      const parsed = new URL(path);
      return `${parsed.pathname}${parsed.search}`;
    }
    return path.startsWith("/") ? path : `/${path}`;
  }

  private applyQuery(url: URL, query?: QueryParams): void {
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value === undefined) continue;
      if (Array.isArray(value)) {
        for (const item of value) url.searchParams.append(key, String(item));
      } else {
        url.searchParams.set(key, String(value));
      }
    }
  }

  private async parseResponse(resp: Awaited<ReturnType<typeof fetch>>, allowEmpty = false): Promise<unknown> {
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Black Duck API ${resp.status}: ${text.slice(0, 500)}`);
    }
    if (allowEmpty && (resp.status === 204 || !resp.headers.get("content-type")?.includes("application/json"))) {
      return { status: "ok", http_code: resp.status };
    }
    const contentType = resp.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return { raw: await resp.text() };
    }
    return resp.json();
  }
}
