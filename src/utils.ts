import type { BdRecord } from "./types.js";

export function extractId(href: string, segment: string): string {
  const parts = href.split(`/${segment}/`);
  if (parts.length > 1) return parts[parts.length - 1].split("/")[0] ?? "";
  return "";
}

export function linkHref(obj: BdRecord, rel: string): string {
  const links = (obj._meta as BdRecord | undefined)?.links;
  if (!Array.isArray(links)) return "";
  for (const link of links) {
    const l = link as BdRecord;
    if (l.rel === rel && typeof l.href === "string") return l.href;
  }
  return "";
}

export function metaHref(obj: BdRecord): string {
  const meta = obj._meta as BdRecord | undefined;
  return typeof meta?.href === "string" ? meta.href : "";
}

export function parseVersionFromGuidance(guidance: string): string | null {
  const m = guidance.match(/(?:Upgrade to|→)\s+([^\s(,|]+)/i);
  return m?.[1] ?? null;
}

export function extractSemverPrefix(spec: string): string {
  const m = spec.match(/^(\^|~|>=|<=|>|<|=)?/);
  return m?.[1] ?? "";
}

export const GIT_SHA_RE = /^[0-9a-f]{40}$/i;
export const SUSPICIOUS_VERSIONS = new Set([
  "0.0.0", "1.0.0", "0.0.1", "0.1.0", "latest", "unknown",
  "develop", "master", "main", "snapshot", "dev", "head", "tip", "none", "n/a", "null", "undefined",
]);
export const REGISTRY_NAMESPACES = new Set([
  "npmjs", "maven", "pypi", "rubygems", "nuget", "golang", "packagist", "hex", "cpan", "ctan", "crates",
  "alpine", "debian", "ubuntu", "centos", "redhat", "fedora", "opensuse", "oracle_linux", "almalinux",
  "rocky", "anaconda", "photon", "conda-forge", "cocoapods",
]);

export const VALID_USAGES = new Set([
  "DYNAMICALLY_LINKED", "STATICALLY_LINKED", "SOURCE_CODE", "DEV_TOOL_EXCLUDED",
  "IMPLEMENTATION_OF_STANDARD", "PREREQUISITE", "SEPARATE_WORK",
]);

export const BOM_HEADERS = {
  Accept: "application/vnd.blackducksoftware.bill-of-materials-6+json",
};

export const BOM_WRITE_HEADERS = {
  Accept: "application/vnd.blackducksoftware.bill-of-materials-6+json",
  "Content-Type": "application/vnd.blackducksoftware.bill-of-materials-6+json",
};

export const KB_HEADERS = {
  Accept: "application/vnd.blackducksoftware.component-detail-5+json",
};

export const PROJECT_HEADERS = {
  Accept: "application/vnd.blackducksoftware.project-detail-5+json",
};
