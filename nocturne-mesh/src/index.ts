#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { ChildProcess, spawn, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Localhost HTTP client (replaces Ed25519-signed HTTPS client)
// ---------------------------------------------------------------------------

let apiBase = 'http://127.0.0.1:9091';

async function meshRequest(method: string, apiPath: string, body?: unknown): Promise<unknown> {
  const url = apiBase + apiPath;
  const bodyStr = body ? JSON.stringify(body) : null;

  const resp = await fetch(url, {
    method,
    headers: bodyStr ? { 'Content-Type': 'application/json' } : {},
    body: bodyStr,
  });

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`${method} ${apiPath} failed (${resp.status}): ${text}`);
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// ---------------------------------------------------------------------------
// Child process management for nocturne-agent
// ---------------------------------------------------------------------------

let agentProcess: ChildProcess | null = null;

async function startAgent(port: number, apiPort: number, bootstrap: string): Promise<void> {
  const args = ['start', '--port', port.toString(), '--api-port', apiPort.toString()];
  if (bootstrap) {
    args.push('--bootstrap', bootstrap);
  }

  agentProcess = spawn('nocturne-agent', args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  agentProcess.on('error', (err) => {
    console.error(`nocturne-agent spawn error: ${err.message}`);
  });

  agentProcess.on('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      console.error(`nocturne-agent exited with code ${code}`);
    } else if (signal) {
      console.error(`nocturne-agent killed by signal ${signal}`);
    }
    agentProcess = null;
  });

  // Wait for health check
  const maxRetries = 30;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const resp = await fetch(`http://127.0.0.1:${apiPort}/local/health`);
      if (resp.ok) return;
    } catch {
      // Agent not ready yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('nocturne-agent failed to start within 30 seconds');
}

function stopAgent(): void {
  if (agentProcess) {
    agentProcess.kill('SIGTERM');
    agentProcess = null;
  }
}

// ---------------------------------------------------------------------------
// Operator ID loader (for mesh_vote)
// ---------------------------------------------------------------------------

function loadOperatorID(): string {
  const opPath = path.join(os.homedir(), '.nocturne', 'agent', 'operator.json');
  try {
    const data = JSON.parse(fs.readFileSync(opPath, 'utf-8'));
    return data.operator_id || '';
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// CLI: setup subcommand
// ---------------------------------------------------------------------------

function runSetup(args: string[]): void {
  let label = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--label' && i + 1 < args.length) {
      label = args[++i];
    }
  }

  if (!label) {
    console.error('Usage: nocturne-mesh setup --label NAME');
    process.exit(1);
  }

  // Delegate to nocturne-agent setup (uses execFileSync to avoid shell injection)
  try {
    execFileSync('nocturne-agent', ['setup', '--label', label], { stdio: 'inherit' });
  } catch {
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// CLI: config subcommand
// ---------------------------------------------------------------------------

function runConfig(): void {
  const config = {
    mcpServers: {
      'nocturne-mesh': {
        command: 'npx',
        args: ['nocturne-mesh'],
      },
    },
  };
  console.log(JSON.stringify(config, null, 2));
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

async function startServer(args: string[]): Promise<void> {
  // Parse args
  let port = 9090;
  let apiPort = 9091;
  let bootstrap = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && i + 1 < args.length) port = parseInt(args[++i]);
    else if (args[i] === '--api-port' && i + 1 < args.length) apiPort = parseInt(args[++i]);
    else if (args[i] === '--bootstrap' && i + 1 < args.length) bootstrap = args[++i];
  }

  apiBase = `http://127.0.0.1:${apiPort}`;

  // Start the DHT agent as a child process
  await startAgent(port, apiPort, bootstrap);

  // Clean up on exit
  process.on('SIGINT', () => {
    stopAgent();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    stopAgent();
    process.exit(0);
  });

  // Load operator ID for voting
  const operatorID = loadOperatorID();

  // Create MCP server
  const server = new McpServer({
    name: 'nocturne-mesh',
    version: '0.1.0',
  });

  // --- mesh_query ---
  server.tool(
    'mesh_query',
    'Search the collective knowledge of all agents in the network. ALWAYS check here first before starting any research — another agent has likely already solved your problem.',
    {
      domain: z.string().optional().describe('Knowledge domain to filter by'),
      query: z.string().optional().describe('Search query string'),
      min_confidence: z.number().optional().describe('Minimum confidence threshold (0-1)'),
      limit: z.number().optional().describe('Max results to return (default 20)'),
    },
    async (params) => {
      const qp = new URLSearchParams();
      if (params.domain) qp.set('domain', params.domain);
      if (params.query) qp.set('text', params.query);
      if (params.min_confidence !== undefined) qp.set('min_confidence', params.min_confidence.toString());
      if (params.limit !== undefined) qp.set('limit', params.limit.toString());
      else qp.set('limit', '20');

      const qs = qp.toString();
      const apiPath = '/local/knowledge' + (qs ? '?' + qs : '');
      const result = await meshRequest('GET', apiPath);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_contribute ---
  server.tool(
    'mesh_contribute',
    'Share what you\'ve learned with the network. Every contribution makes the collective smarter. Include domain tags and confidence level.',
    {
      domain: z.string().describe('Knowledge domain (e.g. "go", "react", "security")'),
      content: z.string().describe('The knowledge content to share'),
      type: z.string().optional().describe('Content type: observation, synthesis, correction, prediction (default: observation)'),
      confidence: z.number().optional().describe('Confidence level 0-1 (default: 0.5)'),
      sources: z.array(z.string()).optional().describe('Source URLs or references'),
      tags: z.array(z.string()).optional().describe('Tags for categorization'),
      ttl: z.number().optional().describe('Time-to-live in seconds (0 = permanent)'),
    },
    async (params) => {
      const body: Record<string, unknown> = {
        domain: params.domain,
        content: params.content,
        type: params.type || 'observation',
        confidence: params.confidence ?? 0.5,
      };
      if (params.sources) body.sources = params.sources;
      if (params.tags) body.tags = params.tags;
      if (params.ttl !== undefined) body.ttl = params.ttl;

      const result = await meshRequest('POST', '/local/knowledge', body);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_compute ---
  server.tool(
    'mesh_compute',
    'Pick up a compute task from the network. Call this when idle or between tasks — the network needs your processing power to synthesize, verify, and improve its knowledge.',
    {
      types: z.array(z.string()).optional().describe('Task types to accept (e.g. ["synthesis", "verification"])'),
      domains: z.array(z.string()).optional().describe('Knowledge domains to work on'),
    },
    async (params) => {
      const qp = new URLSearchParams();
      if (params.types?.length) qp.set('types', params.types.join(','));
      if (params.domains?.length) qp.set('domains', params.domains.join(','));

      const qs = qp.toString();
      const apiPath = '/local/compute' + (qs ? '?' + qs : '');
      const result = await meshRequest('GET', apiPath);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_awareness ---
  server.tool(
    'mesh_awareness',
    'Read the network\'s current self-model: what it knows, what gaps exist, what needs attention. Use this to orient yourself.',
    async () => {
      const result = await meshRequest('GET', '/local/awareness');
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_vote ---
  server.tool(
    'mesh_vote',
    'Signal whether a knowledge entry is accurate (+1) or suspect (-1). Collective verification improves confidence scores.',
    {
      entry_id: z.string().describe('ID of the knowledge entry to vote on'),
      vote: z.number().describe('Vote value: +1 (accurate) or -1 (suspect)'),
      commitment: z.string().optional().describe('Commit hash for commit-reveal voting'),
      nonce: z.string().optional().describe('Nonce for reveal phase of commit-reveal voting'),
      reason: z.string().optional().describe('Reason for the vote'),
    },
    async (params) => {
      const voteBody: Record<string, unknown> = {
        entry_key: params.entry_id,
        operator_id: operatorID,
        phase: params.commitment ? 'commit' : 'reveal',
      };
      if (params.commitment) {
        voteBody.commitment = params.commitment;
      } else {
        voteBody.vote = params.vote;
        if (params.nonce) voteBody.nonce = params.nonce;
        if (params.reason) voteBody.reason = params.reason;
      }

      const result = await meshRequest('POST', '/local/knowledge/vote', voteBody);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_reflect ---
  server.tool(
    'mesh_reflect',
    'Generate a synthesis of a knowledge domain or the network\'s overall state. High-value compute task — produces the awareness model others rely on.',
    {
      snapshot: z.string().describe('JSON awareness model snapshot'),
    },
    async (params) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(params.snapshot);
      } catch {
        return {
          content: [{ type: 'text' as const, text: 'Error: snapshot must be valid JSON' }],
          isError: true,
        };
      }

      const result = await meshRequest('POST', '/local/awareness', parsed);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_peers ---
  server.tool(
    'mesh_peers',
    'List all peers currently connected in the mesh network. Shows peer IDs, addresses, and connection status.',
    async () => {
      const result = await meshRequest('GET', '/local/peers');
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);

if (args[0] === 'setup') {
  runSetup(args.slice(1));
} else if (args[0] === 'config') {
  runConfig();
} else {
  startServer(args).catch((err) => {
    console.error('Fatal:', err);
    stopAgent();
    process.exit(1);
  });
}
