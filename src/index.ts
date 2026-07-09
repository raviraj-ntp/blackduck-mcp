#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { BlackDuckClient } from "./client.js";
import { loadConfig } from "./config.js";
import { registerBlackDuckTools } from "./tools/registerTools.js";

const config = loadConfig();
const client = new BlackDuckClient(config);

const server = new McpServer({
  name: "blackduck-mcp",
  version: "1.1.0",
});

registerBlackDuckTools(server, client);

const transport = new StdioServerTransport();
await server.connect(transport);
