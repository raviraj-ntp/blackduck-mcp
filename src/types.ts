export type BdRecord = Record<string, unknown>;

export type BdListResponse = {
  items?: BdRecord[];
  totalCount?: number;
};

export type QueryValue = string | number | boolean | undefined | Array<string | number | boolean>;
export type QueryParams = Record<string, QueryValue>;

export type VulnInfo = {
  name: string;
  severity: string;
  baseScore: string | number;
  overallScore: string | number;
  exploitabilityScore: string | number;
  impactScore: string | number;
  source: string;
  remediationStatus: string;
  cweId: string | number;
  description: string;
  publishedDate: string;
  updatedDate: string;
  relatedVulnerability: string;
  bdsaTags: unknown[];
};

export type VulnerableComponent = {
  componentName: string;
  componentVersionName: string;
  componentVersionOriginName: string;
  componentVersionOriginId: string;
  packageUrl: string;
  matchTypes: string;
  usages: string;
  isTransitive: boolean;
  vulnerabilities: VulnInfo[];
  upgradeGuidance: string;
  transitiveUpgradeGuidance: string;
  severity_counts: Record<string, number>;
};
