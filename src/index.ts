#!/usr/bin/env node

/**
 * ------------------------------------------------------------------------------
 * Package : @raviraj87/blackduck-mcp
 * File    : index.ts
 * Purpose : MCP server bootstrap — Black Duck API tools and stdio transport.
 *
 * Copyright (c) 2026 Ravi Raj
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 * ------------------------------------------------------------------------------
 */

/**
 * ------------------------------------------------------------------------------
 * Package : @raviraj87/blackduck-mcp
 * File    : index.ts
 * Purpose : MCP server bootstrap — Black Duck API tools and stdio transport.
 *
 * Copyright (c) 2026 Ravi Raj
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 * ------------------------------------------------------------------------------
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { BlackDuckClient } from "./client.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

const client = new BlackDuckClient(
  requiredEnv("BLACKDUCK_URL"),
  requiredEnv("BLACKDUCK_API_TOKEN"),
);

const server = new McpServer({
  name: "blackduck-mcp",
  version: "1.0.1",
});

server.registerTool(
  "blackduck_health",
  {
    title: "Black Duck Health",
    description: "Check Black Duck API reachability.",
    inputSchema: {},
  },
  async () => {
    const data = await client.get("/api/current-user");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_current_user",
  {
    title: "Black Duck Current User",
    description: "Get authenticated Black Duck user details.",
    inputSchema: {},
  },
  async () => {
    const data = await client.get("/api/current-user");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_list_projects",
  {
    title: "Black Duck List Projects",
    description: "List Black Duck projects.",
    inputSchema: {
      limit: z.number().int().positive().max(100).optional(),
      offset: z.number().int().min(0).optional(),
      q: z.string().optional(),
    },
  },
  async ({ limit, offset, q }) => {
    const data = await client.get("/api/projects", {
      limit,
      offset,
      q,
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_get_project_versions",
  {
    title: "Black Duck Project Versions",
    description: "List versions for a project by project ID.",
    inputSchema: {
      projectId: z.string().min(1),
      limit: z.number().int().positive().max(100).optional(),
      offset: z.number().int().min(0).optional(),
    },
  },
  async ({ projectId, limit, offset }) => {
    const data = await client.get(`/api/projects/${encodeURIComponent(projectId)}/versions`, {
      limit,
      offset,
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_list_project_components",
  {
    title: "Black Duck List Project Components",
    description: "List project-version BOM components with optional repeated filters.",
    inputSchema: {
      projectId: z.string().min(1),
      versionId: z.string().min(1),
      limit: z.number().int().positive().max(200).optional(),
      offset: z.number().int().min(0).optional(),
      sort: z.string().optional(),
      filter: z.array(z.string().min(1)).optional(),
    },
  },
  async ({ projectId, versionId, limit, offset, sort, filter }) => {
    const data = await client.get(
      `/api/projects/${encodeURIComponent(projectId)}/versions/${encodeURIComponent(versionId)}/components`,
      { limit, offset, sort, filter },
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_list_components",
  {
    title: "Black Duck List Components",
    description: "List components for a project version by version ID.",
    inputSchema: {
      versionId: z.string().min(1),
      limit: z.number().int().positive().max(100).optional(),
      offset: z.number().int().min(0).optional(),
    },
  },
  async ({ versionId, limit, offset }) => {
    const data = await client.get(
      `/api/versions/${encodeURIComponent(versionId)}/components`,
      { limit, offset },
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_get_matched_files",
  {
    title: "Black Duck Matched Files",
    description: "Get matched-files details from a matched-files URL/path.",
    inputSchema: {
      matchedFilesPathOrUrl: z.string().min(1),
      limit: z.number().int().positive().max(500).optional(),
      offset: z.number().int().min(0).optional(),
    },
  },
  async ({ matchedFilesPathOrUrl, limit, offset }) => {
    const data = await client.get(matchedFilesPathOrUrl, { limit, offset });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

server.registerTool(
  "blackduck_api_get",
  {
    title: "Black Duck API GET",
    description: "Read any Black Duck API GET endpoint.",
    inputSchema: {
      path: z.string().min(1),
      limit: z.number().int().positive().max(200).optional(),
      offset: z.number().int().min(0).optional(),
      q: z.string().optional(),
      sort: z.string().optional(),
      filter: z.array(z.string().min(1)).optional(),
    },
  },
  async ({ path, limit, offset, q, sort, filter }) => {
    const data = await client.get(path, { limit, offset, q, sort, filter });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
