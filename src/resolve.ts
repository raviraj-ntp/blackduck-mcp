import type { BlackDuckClient } from "./client.js";
import type { BdRecord } from "./types.js";
import { extractId, metaHref } from "./utils.js";

export type ResolvedProjectVersion = {
  project: BdRecord;
  version: BdRecord;
  projectId: string;
  versionId: string;
  projectName: string;
  versionName: string;
};

export async function resolveProjectVersion(
  client: BlackDuckClient,
  projectName: string,
  versionName: string,
): Promise<ResolvedProjectVersion | { error: string }> {
  const project = await client.findProject(projectName);
  if (!project) return { error: `Project '${projectName}' not found` };

  const version = await client.findVersion(project, versionName);
  if (!version) {
    return { error: `Version '${versionName}' not found in project '${projectName}'` };
  }

  const projectId = extractId(metaHref(project), "projects");
  const versionId = extractId(metaHref(version), "versions");
  if (!projectId || !versionId) {
    return { error: "Could not resolve project/version IDs" };
  }

  return {
    project,
    version,
    projectId,
    versionId,
    projectName,
    versionName,
  };
}
