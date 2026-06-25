import { createHash } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer(
  { name: "executor-e2e-stdio", version: "1.0.0" },
  { capabilities: {} },
);

server.registerTool(
  "secret_status",
  {
    description: "Reports whether Executor supplied the configured template secret",
    inputSchema: {},
  },
  async () => ({
    content: [
      {
        type: "text",
        text: `secret-sha256:${createHash("sha256")
          .update(process.env.EXECUTOR_E2E_STDIO_SECRET ?? "")
          .digest("hex")}`,
      },
    ],
  }),
);

await server.connect(new StdioServerTransport());
