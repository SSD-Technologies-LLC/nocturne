#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import nacl from 'tweetnacl';
import { z } from 'zod';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

function keyDir(): string {
  return path.join(os.homedir(), '.nocturne');
}

function defaultKeyPath(): string {
  return path.join(keyDir(), 'agent.key');
}

function loadKey(keyPath: string): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const hex = fs.readFileSync(keyPath, 'utf-8').trim();
  const seed = Buffer.from(hex, 'hex');
  if (seed.length !== 32) {
    throw new Error(`Invalid key file: expected 32-byte seed (64 hex chars), got ${seed.length} bytes`);
  }
  return nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
}

function generateKey(keyPath: string): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const seed = nacl.randomBytes(32);
  const dir = path.dirname(keyPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(keyPath, Buffer.from(seed).toString('hex') + '\n', { mode: 0o600 });
  return nacl.sign.keyPair.fromSeed(seed);
}

function agentIDFromPublicKey(pub: Uint8Array): string {
  return Buffer.from(pub.slice(0, 8)).toString('hex');
}

// ---------------------------------------------------------------------------
// HTTP client with Ed25519 signing
// ---------------------------------------------------------------------------

function signRequest(
  method: string,
  urlPath: string,
  body: string | null,
  agentID: string,
  secretKey: Uint8Array,
): Record<string, string> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const message = method + urlPath + timestamp + (body || '');
  const sig = nacl.sign.detached(new TextEncoder().encode(message), secretKey);
  return {
    'X-Agent-ID': agentID,
    'X-Agent-Timestamp': timestamp,
    'X-Agent-Signature': Buffer.from(sig).toString('hex'),
    'Content-Type': 'application/json',
  };
}

let trackerURL = '';
let agentID = '';
let secretKey: Uint8Array = new Uint8Array(0);

async function meshRequest(method: string, apiPath: string, body?: unknown): Promise<unknown> {
  const url = new URL(apiPath, trackerURL);
  const bodyStr = body ? JSON.stringify(body) : null;
  const headers = signRequest(method, url.pathname, bodyStr, agentID, secretKey);

  const resp = await fetch(url.toString(), {
    method,
    headers,
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
// CLI: setup subcommand
// ---------------------------------------------------------------------------

function runSetup(args: string[]): void {
  let tracker = '';
  let label = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tracker' && i + 1 < args.length) {
      tracker = args[++i];
    } else if (args[i] === '--label' && i + 1 < args.length) {
      label = args[++i];
    }
  }

  if (!tracker) {
    console.error('Usage: nocturne-mesh setup --tracker URL --label NAME');
    process.exit(1);
  }
  if (!label) {
    label = os.hostname();
  }

  const kp = defaultKeyPath();
  if (fs.existsSync(kp)) {
    console.error(`Key already exists: ${kp}`);
    console.error('Delete it first if you want to generate a new one.');
    process.exit(1);
  }

  const keypair = generateKey(kp);
  const id = agentIDFromPublicKey(keypair.publicKey);
  const pubHex = Buffer.from(keypair.publicKey).toString('hex');

  console.log(`Generated key: ${kp}`);
  console.log(`Agent ID: ${id}`);
  console.log(`Public key (give to admin for enrollment): ${pubHex}`);
  console.log('');
  console.log('Ask your admin to run:');
  console.log(`  curl -X POST ${tracker}/api/admin/operator -H 'X-Admin-Secret: <secret>' \\`);
  console.log(`    -d '{"public_key":"${pubHex}","label":"${label}","max_agents":5}'`);
}

// ---------------------------------------------------------------------------
// CLI: config subcommand
// ---------------------------------------------------------------------------

function runConfig(): void {
  const config = {
    mcpServers: {
      'nocturne-mesh': {
        command: 'npx',
        args: ['nocturne-mesh', '--tracker', '<TRACKER_URL>'],
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
  let tracker = process.env['NOCTURNE_TRACKER'] || '';
  let keyPath = defaultKeyPath();

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tracker' && i + 1 < args.length) {
      tracker = args[++i];
    } else if (args[i] === '--key' && i + 1 < args.length) {
      keyPath = args[++i];
    }
  }

  if (!tracker) {
    console.error('Error: --tracker URL or NOCTURNE_TRACKER env required');
    process.exit(1);
  }

  // Load key
  let keypair: { publicKey: Uint8Array; secretKey: Uint8Array };
  try {
    keypair = loadKey(keyPath);
  } catch (err) {
    console.error(`Failed to load key from ${keyPath}: ${err}`);
    console.error('Run "nocturne-mesh setup --tracker URL --label NAME" first.');
    process.exit(1);
  }

  trackerURL = tracker.replace(/\/+$/, '');
  agentID = agentIDFromPublicKey(keypair.publicKey);
  secretKey = keypair.secretKey;

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
      if (params.query) qp.set('query', params.query);
      if (params.min_confidence !== undefined) qp.set('min_confidence', params.min_confidence.toString());
      if (params.limit !== undefined) qp.set('limit', params.limit.toString());
      else qp.set('limit', '20');

      const qs = qp.toString();
      const apiPath = '/api/agent/knowledge' + (qs ? '?' + qs : '');
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

      const result = await meshRequest('POST', '/api/agent/knowledge', body);
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
      const apiPath = '/api/agent/compute' + (qs ? '?' + qs : '');
      const result = await meshRequest('GET', apiPath);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // --- mesh_awareness ---
  server.tool(
    'mesh_awareness',
    'Read the network\'s current self-model: what it knows, what gaps exist, what needs attention. Use this to orient yourself.',
    async () => {
      const result = await meshRequest('GET', '/api/agent/awareness');
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
      const body: Record<string, unknown> = {};

      // Support both commit and reveal phases
      if (params.commitment) {
        body.commitment = params.commitment;
      } else {
        body.vote = params.vote;
        if (params.nonce) body.nonce = params.nonce;
        if (params.reason) body.reason = params.reason;
      }

      const result = await meshRequest('POST', `/api/agent/knowledge/${params.entry_id}/vote`, body);
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

      const result = await meshRequest('POST', '/api/agent/reflect', { snapshot: parsed });
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
    process.exit(1);
  });
}
