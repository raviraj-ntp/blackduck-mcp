/**
 * @raviraj87/blackduck-mcp · client.ts
 * Black Duck REST API client.
 *
 * Copyright (c) 2026 Ravi Raj · MIT License · see LICENSE
 */

import fetch from "node-fetch";
import https from "node:https";

export type QueryValue =
  | string
  | number
  | boolean
  | undefined
  | Array<string | number | boolean>;
export type QueryParams = Record<string, QueryValue>;

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

export class BlackDuckClient {
  private bearerToken: string | null = null;
  private tokenExpiryMs = 0;

  constructor(
    private readonly baseUrl: string,
    private readonly apiToken: string,
  ) {}

  async get(path: string, query?: QueryParams): Promise<unknown> {
    await this.authenticate();

    const url = new URL(this.normalizePath(path), this.baseUrl);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value === undefined) continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          url.searchParams.append(key, String(item));
        }
        continue;
      }
      url.searchParams.set(key, String(value));
    }

    const resp = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.bearerToken}`,
      },
      agent: httpsAgent,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Black Duck API ${resp.status}: ${text.slice(0, 500)}`);
    }

    const contentType = resp.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return { raw: await resp.text() };
    }
    return resp.json();
  }

  private normalizePath(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      const parsed = new URL(path);
      return `${parsed.pathname}${parsed.search}`;
    }
    if (path.startsWith("/")) return path;
    return `/${path}`;
  }

  private async authenticate(): Promise<void> {
    if (this.bearerToken && Date.now() < this.tokenExpiryMs) return;

    const resp = await fetch(`${this.baseUrl.replace(/\/+$/, "")}/api/tokens/authenticate`, {
      method: "POST",
      headers: {
        Authorization: `token ${this.apiToken}`,
        Accept: "application/vnd.blackducksoftware.user-4+json",
      },
      agent: httpsAgent,
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Black Duck auth ${resp.status}: ${text.slice(0, 500)}`);
    }

    const data = (await resp.json()) as {
      bearerToken?: string;
      expiresInMilliseconds?: number;
    };
    if (!data.bearerToken) {
      throw new Error("Black Duck auth did not return bearerToken");
    }

    this.bearerToken = data.bearerToken;
    this.tokenExpiryMs = Date.now() + (data.expiresInMilliseconds ?? 7_200_000) - 60_000;
  }
}

