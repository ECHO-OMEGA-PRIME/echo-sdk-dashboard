/**
 * Echo SDK Dashboard Worker v1.0.0
 *
 * Developer dashboard API for Echo SDK tenants.
 * Provides usage analytics, API key management, quota monitoring,
 * alert configuration, audit logging, and saved reports.
 *
 * Auth: Validates X-Echo-API-Key against the SDK Gateway /auth/whoami endpoint.
 * Storage: D1 (dashboard_configs, saved_reports, alerts, audit_log, usage_rollups) + KV cache.
 * Service binding: echo-sdk-gateway for auth verification and usage data.
 *
 * Endpoints:
 *   GET    /health              Health check
 *   GET    /dashboard           Full dashboard data
 *   GET    /usage/summary       Usage summary (today, 7d, 30d)
 *   GET    /usage/endpoints     Top endpoints by request count
 *   GET    /usage/timeline      Hourly/daily usage timeline
 *   GET    /usage/errors        Error breakdown by code and endpoint
 *   GET    /quota               Quota status (plan limits vs actual)
 *   GET    /keys                List API keys (proxied from SDK Gateway)
 *   POST   /keys                Create API key (proxied)
 *   DELETE /keys/:id            Revoke key (proxied)
 *   GET    /alerts              List alerts
 *   POST   /alerts              Create alert
 *   PUT    /alerts/:id          Update alert
 *   DELETE /alerts/:id          Delete alert
 *   GET    /audit               Audit log (paginated)
 *   GET    /reports             List saved reports
 *   POST   /reports             Create saved report
 *   GET    /config              Get dashboard config
 *   PUT    /config              Update dashboard config
 *
 * Cron:
 *   0 0 * * *    — Daily usage rollup, stale data cleanup, quota reset check
 *   0 *\/6 * * * — Alert evaluation (check thresholds against current usage)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SDK_GATEWAY: Fetcher;
  WORKER_VERSION: string;
}

interface TenantAuth {
  tenant_id: string;
  plan: string;
  scopes: string[];
  type: string;
  key_id?: string;
  tenant?: {
    name: string;
    email: string;
    rate_limit: number;
    daily_limit: number;
    monthly_limit: number;
  } | null;
}

interface Envelope<T = unknown> {
  success: boolean;
  data: T | null;
  error: { message: string; code: string } | null;
  meta: {
    ts: string;
    version: string;
    service: string;
    latency_ms?: number;
  };
}

interface AlertRow {
  id: string;
  tenant_id: string;
  type: string;
  threshold: number;
  channel: string;
  enabled: number;
  last_triggered: string | null;
  created_at: string;
}

interface ReportRow {
  id: string;
  tenant_id: string;
  name: string;
  report_type: string;
  filters: string;
  schedule: string | null;
  last_run: string | null;
  created_at: string;
}

interface DashboardConfigRow {
  tenant_id: string;
  layout: string;
  widgets: string;
  theme: string;
  created_at: string;
  updated_at: string;
}

interface UsageRollupRow {
  tenant_id: string;
  date: string;
  total_requests: number;
  total_errors: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  top_endpoints: string;
  error_breakdown: string;
}

interface AuditRow {
  id: number;
  tenant_id: string;
  action: string;
  resource: string;
  details: string;
  ip: string | null;
  created_at: string;
}

// Plan limits configuration
const PLAN_LIMITS: Record<string, { rate: number; daily: number; monthly: number }> = {
  free: { rate: 30, daily: 500, monthly: 10000 },
  pro: { rate: 120, daily: 5000, monthly: 100000 },
  enterprise: { rate: 600, daily: 50000, monthly: 1000000 },
  internal: { rate: 10000, daily: 1000000, monthly: 99999999 },
};

const SERVICE_NAME = 'echo-sdk-dashboard';
const STARTUP = Date.now();

// ---------------------------------------------------------------------------
// Envelope helpers
// ---------------------------------------------------------------------------

function ok<T>(data: T, version: string, latencyMs?: number): Envelope<T> {
  return {
    success: true,
    data,
    error: null,
    meta: {
      ts: new Date().toISOString(),
      version,
      service: SERVICE_NAME,
      ...(latencyMs !== undefined && { latency_ms: Math.round(latencyMs * 100) / 100 }),
    },
  };
}

function err(message: string, code: string, version: string): Envelope<null> {
  return {
    success: false,
    data: null,
    error: { message, code },
    meta: {
      ts: new Date().toISOString(),
      version,
      service: SERVICE_NAME,
    },
  };
}

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

function log(
  level: 'debug' | 'info' | 'warn' | 'error',
  message: string,
  extra: Record<string, unknown> = {},
): void {
  const payload = {
    level,
    service: SERVICE_NAME,
    message,
    ts: new Date().toISOString(),
    ...extra,
  };
  if (level === 'error') {
    console.error(JSON.stringify(payload));
  } else if (level === 'warn') {
    console.warn(JSON.stringify(payload));
  } else {
    console.log(JSON.stringify(payload));
  }
}

// ---------------------------------------------------------------------------
// Auth helper — validates against SDK Gateway /auth/whoami
// ---------------------------------------------------------------------------

async function authenticate(
  apiKey: string | undefined,
  gateway: Fetcher,
  cache: KVNamespace,
): Promise<TenantAuth | null> {
  if (!apiKey) return null;

  // Check KV cache first (5min TTL)
  const cacheKey = `auth:${apiKey.slice(0, 16)}`;
  const cached = await cache.get(cacheKey, 'json');
  if (cached) return cached as TenantAuth;

  try {
    const resp = await gateway.fetch('https://gateway/auth/whoami', {
      headers: { 'X-Echo-API-Key': apiKey },
    });
    if (!resp.ok) return null;

    const body = (await resp.json()) as Envelope<TenantAuth>;
    if (!body.success || !body.data) return null;

    const authData = body.data;
    // Cache for 5 minutes
    await cache.put(cacheKey, JSON.stringify(authData), { expirationTtl: 300 });
    return authData;
  } catch (e) {
    log('error', 'Auth verification failed', {
      error: e instanceof Error ? e.message : String(e),
    });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Audit logging helper
// ---------------------------------------------------------------------------

async function auditLog(
  db: D1Database,
  tenantId: string,
  action: string,
  resource: string,
  details: Record<string, unknown> = {},
  ip?: string,
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO audit_log (tenant_id, action, resource, details, ip) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(tenantId, action, resource, JSON.stringify(details), ip || null)
      .run();
  } catch (e) {
    log('error', 'Audit log write failed', {
      tenant_id: tenantId,
      action,
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// ---------------------------------------------------------------------------
// KV cache helper
// ---------------------------------------------------------------------------

async function cachedQuery<T>(
  cache: KVNamespace,
  key: string,
  ttlSeconds: number,
  fetcher: () => Promise<T>,
): Promise<T> {
  const cached = await cache.get(key, 'json');
  if (cached !== null) return cached as T;

  const result = await fetcher();
  await cache.put(key, JSON.stringify(result), { expirationTtl: ttlSeconds });
  return result;
}

// ---------------------------------------------------------------------------
// Helper: fetch usage data from SDK Gateway
// ---------------------------------------------------------------------------

async function fetchGatewayUsage(
  gateway: Fetcher,
  apiKey: string,
  path: string,
): Promise<Record<string, unknown> | null> {
  try {
    const resp = await gateway.fetch(`https://gateway${path}`, {
      headers: { 'X-Echo-API-Key': apiKey },
    });
    if (!resp.ok) return null;
    const body = (await resp.json()) as Envelope;
    return body.success ? (body.data as Record<string, unknown>) : null;
  } catch (e) {
    log('error', 'Gateway usage fetch failed', {
      path,
      error: e instanceof Error ? e.message : String(e),
    });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Helper: proxy request to SDK Gateway
// ---------------------------------------------------------------------------

async function proxyToGateway(
  gateway: Fetcher,
  method: string,
  path: string,
  apiKey: string,
  body?: unknown,
): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: {
      'X-Echo-API-Key': apiKey,
      'Content-Type': 'application/json',
    },
  };
  if (body && (method === 'POST' || method === 'PUT')) {
    init.body = JSON.stringify(body);
  }
  return gateway.fetch(`https://gateway${path}`, init);
}

// ---------------------------------------------------------------------------
// Helper: extract API key from request
// ---------------------------------------------------------------------------

function extractApiKey(req: { header: (name: string) => string | undefined }): string | undefined {
  return (
    req.header('X-Echo-API-Key') ||
    req.header('Authorization')?.replace(/^Bearer\s+/i, '')
  );
}

// ---------------------------------------------------------------------------
// Helper: date math
// ---------------------------------------------------------------------------

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().split('T')[0];
}

function today(): string {
  return new Date().toISOString().split('T')[0];
}

function thisMonth(): string {
  return new Date().toISOString().slice(0, 7);
}

// ---------------------------------------------------------------------------
// Hono App
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env }>();

// CORS middleware
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-Echo-API-Key', 'Authorization'],
  maxAge: 86400,
}));

// ---------------------------------------------------------------------------
// GET /health — Public health check
// ---------------------------------------------------------------------------
app.get('/health', async (c) => {
  const start = Date.now();
  const version = c.env.WORKER_VERSION || '1.0.0';

  // Check D1
  let dbOk = false;
  let dbLatency = 0;
  try {
    const dbStart = Date.now();
    await c.env.DB.prepare('SELECT 1').first();
    dbLatency = Date.now() - dbStart;
    dbOk = true;
  } catch {
    dbOk = false;
  }

  // Check KV
  let kvOk = false;
  try {
    await c.env.CACHE.put('_health_check', '1', { expirationTtl: 60 });
    kvOk = true;
  } catch {
    kvOk = false;
  }

  // Check SDK Gateway binding
  let gatewayOk = false;
  let gatewayLatency = 0;
  try {
    const gwStart = Date.now();
    const resp = await c.env.SDK_GATEWAY.fetch('https://gateway/health');
    gatewayLatency = Date.now() - gwStart;
    gatewayOk = resp.ok;
  } catch {
    gatewayOk = false;
  }

  const status = dbOk && kvOk && gatewayOk ? 'healthy' : 'degraded';

  return c.json(
    ok(
      {
        status,
        version,
        uptime_seconds: Math.floor((Date.now() - STARTUP) / 1000),
        dependencies: {
          d1: { ok: dbOk, latency_ms: dbLatency },
          kv: { ok: kvOk },
          sdk_gateway: { ok: gatewayOk, latency_ms: gatewayLatency },
        },
      },
      version,
      Date.now() - start,
    ),
  );
});

// ---------------------------------------------------------------------------
// Auth middleware for all routes below
// ---------------------------------------------------------------------------
app.use('/*', async (c, next) => {
  // Skip health endpoint (already handled above)
  if (c.req.path === '/health') return next();

  const apiKey = extractApiKey(c.req);
  const auth = await authenticate(apiKey, c.env.SDK_GATEWAY, c.env.CACHE);

  if (!auth) {
    return c.json(
      err('Authentication required. Provide X-Echo-API-Key header.', 'ECHO_DASHBOARD_AUTH_REQUIRED', c.env.WORKER_VERSION || '1.0.0'),
      401,
    );
  }

  c.set('auth' as never, auth);
  c.set('apiKey' as never, apiKey);
  await next();
});

// Type-safe accessor for auth context
function getAuth(c: { get: (key: string) => unknown }): TenantAuth {
  return c.get('auth' as never) as TenantAuth;
}

function getApiKey(c: { get: (key: string) => unknown }): string {
  return c.get('apiKey' as never) as string;
}

function v(c: { env: Env }): string {
  return c.env.WORKER_VERSION || '1.0.0';
}

// ---------------------------------------------------------------------------
// GET /dashboard — Full dashboard data
// ---------------------------------------------------------------------------
app.get('/dashboard', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const apiKey = getApiKey(c);
  const tenantId = auth.tenant_id;
  const cacheKey = `dashboard:${tenantId}`;

  const data = await cachedQuery(c.env.CACHE, cacheKey, 300, async () => {
    // Fetch usage data from SDK Gateway
    const [usageData, tenantUsage] = await Promise.all([
      fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage'),
      fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage/tenant'),
    ]);

    // Fetch local rollups for trend data (last 30 days)
    const rollups = await c.env.DB.prepare(
      `SELECT date, total_requests, total_errors, avg_latency_ms, top_endpoints, error_breakdown
       FROM usage_rollups WHERE tenant_id = ? AND date >= ? ORDER BY date ASC`,
    )
      .bind(tenantId, daysAgo(30))
      .all<UsageRollupRow>();

    // Get plan limits
    const plan = auth.plan || 'free';
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

    // Calculate quota consumed
    const monthlyRequests =
      (tenantUsage?.this_month as Record<string, number> | undefined)?.requests || 0;
    const dailyRequests =
      (usageData?.today as Record<string, number> | undefined)?.requests || 0;

    // Active alerts count
    const alertCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as cnt FROM alerts WHERE tenant_id = ? AND enabled = 1',
    )
      .bind(tenantId)
      .first<{ cnt: number }>();

    // Recent audit events
    const recentAudit = await c.env.DB.prepare(
      'SELECT action, resource, created_at FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 5',
    )
      .bind(tenantId)
      .all<{ action: string; resource: string; created_at: string }>();

    // Trend calculation: compare last 7 days to previous 7 days
    const rollupResults = rollups.results || [];
    const last7 = rollupResults.filter((r) => r.date >= daysAgo(7));
    const prev7 = rollupResults.filter((r) => r.date >= daysAgo(14) && r.date < daysAgo(7));

    const last7Total = last7.reduce((s, r) => s + r.total_requests, 0);
    const prev7Total = prev7.reduce((s, r) => s + r.total_requests, 0);
    const trendPct = prev7Total > 0 ? Math.round(((last7Total - prev7Total) / prev7Total) * 1000) / 10 : 0;

    const last7Errors = last7.reduce((s, r) => s + r.total_errors, 0);
    const last7ErrorRate = last7Total > 0 ? Math.round((last7Errors / last7Total) * 10000) / 100 : 0;

    const avgLatency =
      last7.length > 0
        ? Math.round(last7.reduce((s, r) => s + r.avg_latency_ms, 0) / last7.length * 100) / 100
        : 0;

    // Top endpoints from most recent rollup
    let topEndpoints: unknown[] = [];
    if (rollupResults.length > 0) {
      const latest = rollupResults[rollupResults.length - 1];
      try {
        topEndpoints = JSON.parse(latest.top_endpoints || '[]');
      } catch {
        topEndpoints = [];
      }
    }

    return {
      tenant_id: tenantId,
      plan,
      usage: {
        today: {
          requests: dailyRequests,
          limit: limits.daily,
          pct: limits.daily > 0 ? Math.round((dailyRequests / limits.daily) * 10000) / 100 : 0,
        },
        this_month: {
          requests: monthlyRequests,
          limit: limits.monthly,
          pct: limits.monthly > 0 ? Math.round((monthlyRequests / limits.monthly) * 10000) / 100 : 0,
        },
        rate_limit: limits.rate,
      },
      trends: {
        last_7d_requests: last7Total,
        prev_7d_requests: prev7Total,
        change_pct: trendPct,
        error_rate_pct: last7ErrorRate,
        avg_latency_ms: avgLatency,
      },
      top_endpoints: topEndpoints,
      active_alerts: alertCount?.cnt || 0,
      recent_audit: recentAudit.results || [],
      rollup_days: rollupResults.length,
    };
  });

  await auditLog(c.env.DB, auth.tenant_id, 'view', 'dashboard', {}, c.req.header('CF-Connecting-IP'));

  return c.json(ok(data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /usage/summary — Usage summary (today, 7d, 30d)
// ---------------------------------------------------------------------------
app.get('/usage/summary', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const apiKey = getApiKey(c);
  const tenantId = auth.tenant_id;
  const cacheKey = `usage_summary:${tenantId}`;

  const data = await cachedQuery(c.env.CACHE, cacheKey, 300, async () => {
    // Get live data from SDK Gateway
    const [usageData, tenantUsage] = await Promise.all([
      fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage'),
      fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage/tenant'),
    ]);

    // Get rollups for historical data
    const [last7, last30] = await Promise.all([
      c.env.DB.prepare(
        `SELECT SUM(total_requests) as requests, SUM(total_errors) as errors,
                AVG(avg_latency_ms) as avg_latency
         FROM usage_rollups WHERE tenant_id = ? AND date >= ?`,
      )
        .bind(tenantId, daysAgo(7))
        .first<{ requests: number; errors: number; avg_latency: number }>(),
      c.env.DB.prepare(
        `SELECT SUM(total_requests) as requests, SUM(total_errors) as errors,
                AVG(avg_latency_ms) as avg_latency
         FROM usage_rollups WHERE tenant_id = ? AND date >= ?`,
      )
        .bind(tenantId, daysAgo(30))
        .first<{ requests: number; errors: number; avg_latency: number }>(),
    ]);

    // Previous period comparisons
    const [prev7, prev30] = await Promise.all([
      c.env.DB.prepare(
        `SELECT SUM(total_requests) as requests FROM usage_rollups
         WHERE tenant_id = ? AND date >= ? AND date < ?`,
      )
        .bind(tenantId, daysAgo(14), daysAgo(7))
        .first<{ requests: number }>(),
      c.env.DB.prepare(
        `SELECT SUM(total_requests) as requests FROM usage_rollups
         WHERE tenant_id = ? AND date >= ? AND date < ?`,
      )
        .bind(tenantId, daysAgo(60), daysAgo(30))
        .first<{ requests: number }>(),
    ]);

    const todayData = usageData?.today as Record<string, number> | undefined;
    const monthData = tenantUsage?.this_month as Record<string, number> | undefined;

    const calcTrend = (current: number, previous: number): number =>
      previous > 0 ? Math.round(((current - previous) / previous) * 1000) / 10 : 0;

    return {
      today: {
        requests: todayData?.requests || 0,
        errors: todayData?.errors || 0,
        avg_latency_ms: todayData?.avg_latency_ms || 0,
      },
      last_7d: {
        requests: last7?.requests || 0,
        errors: last7?.errors || 0,
        avg_latency_ms: Math.round((last7?.avg_latency || 0) * 100) / 100,
        trend_pct: calcTrend(last7?.requests || 0, prev7?.requests || 0),
      },
      last_30d: {
        requests: last30?.requests || 0,
        errors: last30?.errors || 0,
        avg_latency_ms: Math.round((last30?.avg_latency || 0) * 100) / 100,
        trend_pct: calcTrend(last30?.requests || 0, prev30?.requests || 0),
      },
      this_month: {
        requests: monthData?.requests || 0,
        errors: monthData?.errors || 0,
      },
    };
  });

  return c.json(ok(data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /usage/endpoints — Top endpoints by request count
// ---------------------------------------------------------------------------
app.get('/usage/endpoints', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;
  const limit = Math.min(parseInt(c.req.query('limit') || '20', 10), 100);
  const cacheKey = `usage_endpoints:${tenantId}:${limit}`;

  const data = await cachedQuery(c.env.CACHE, cacheKey, 300, async () => {
    // Aggregate top endpoints from recent rollups (last 7 days)
    const rollups = await c.env.DB.prepare(
      `SELECT top_endpoints FROM usage_rollups
       WHERE tenant_id = ? AND date >= ? ORDER BY date DESC LIMIT 7`,
    )
      .bind(tenantId, daysAgo(7))
      .all<{ top_endpoints: string }>();

    // Merge endpoint data from multiple days
    const endpointMap = new Map<string, { requests: number; errors: number; latency_sum: number; count: number }>();

    for (const row of rollups.results || []) {
      let endpoints: Array<{ endpoint: string; method?: string; requests: number; errors?: number; avg_latency_ms?: number }>;
      try {
        endpoints = JSON.parse(row.top_endpoints || '[]');
      } catch {
        continue;
      }

      for (const ep of endpoints) {
        const key = `${ep.method || 'GET'} ${ep.endpoint}`;
        const existing = endpointMap.get(key) || { requests: 0, errors: 0, latency_sum: 0, count: 0 };
        existing.requests += ep.requests || 0;
        existing.errors += ep.errors || 0;
        existing.latency_sum += (ep.avg_latency_ms || 0) * (ep.requests || 1);
        existing.count += ep.requests || 1;
        endpointMap.set(key, existing);
      }
    }

    // Sort by request count descending
    const sorted = Array.from(endpointMap.entries())
      .map(([key, stats]) => {
        const [method, ...endpointParts] = key.split(' ');
        return {
          method,
          endpoint: endpointParts.join(' '),
          requests: stats.requests,
          errors: stats.errors,
          error_rate_pct: stats.requests > 0 ? Math.round((stats.errors / stats.requests) * 10000) / 100 : 0,
          avg_latency_ms: stats.count > 0 ? Math.round((stats.latency_sum / stats.count) * 100) / 100 : 0,
        };
      })
      .sort((a, b) => b.requests - a.requests)
      .slice(0, limit);

    return {
      period: 'last_7d',
      endpoints: sorted,
      total: sorted.length,
    };
  });

  return c.json(ok(data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /usage/timeline — Hourly/daily usage timeline
// ---------------------------------------------------------------------------
app.get('/usage/timeline', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;
  const period = (c.req.query('period') || '7d') as '24h' | '7d' | '30d';
  const cacheKey = `usage_timeline:${tenantId}:${period}`;

  const validPeriods = ['24h', '7d', '30d'];
  if (!validPeriods.includes(period)) {
    return c.json(
      err('Invalid period. Use 24h, 7d, or 30d.', 'ECHO_DASHBOARD_INVALID_PERIOD', v(c)),
      400,
    );
  }

  const data = await cachedQuery(c.env.CACHE, cacheKey, 300, async () => {
    let daysBack: number;
    switch (period) {
      case '24h':
        daysBack = 1;
        break;
      case '7d':
        daysBack = 7;
        break;
      case '30d':
        daysBack = 30;
        break;
      default:
        daysBack = 7;
    }

    const rollups = await c.env.DB.prepare(
      `SELECT date, total_requests, total_errors, avg_latency_ms, p95_latency_ms
       FROM usage_rollups WHERE tenant_id = ? AND date >= ? ORDER BY date ASC`,
    )
      .bind(tenantId, daysAgo(daysBack))
      .all<UsageRollupRow>();

    const points = (rollups.results || []).map((r) => ({
      date: r.date,
      requests: r.total_requests,
      errors: r.total_errors,
      error_rate_pct:
        r.total_requests > 0
          ? Math.round((r.total_errors / r.total_requests) * 10000) / 100
          : 0,
      avg_latency_ms: Math.round(r.avg_latency_ms * 100) / 100,
      p95_latency_ms: Math.round(r.p95_latency_ms * 100) / 100,
    }));

    const totalRequests = points.reduce((s, p) => s + p.requests, 0);
    const totalErrors = points.reduce((s, p) => s + p.errors, 0);

    return {
      period,
      points,
      summary: {
        total_requests: totalRequests,
        total_errors: totalErrors,
        avg_error_rate_pct:
          totalRequests > 0
            ? Math.round((totalErrors / totalRequests) * 10000) / 100
            : 0,
        avg_latency_ms:
          points.length > 0
            ? Math.round(
                (points.reduce((s, p) => s + p.avg_latency_ms, 0) / points.length) * 100,
              ) / 100
            : 0,
        data_points: points.length,
      },
    };
  });

  return c.json(ok(data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /usage/errors — Error breakdown
// ---------------------------------------------------------------------------
app.get('/usage/errors', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;
  const cacheKey = `usage_errors:${tenantId}`;

  const data = await cachedQuery(c.env.CACHE, cacheKey, 300, async () => {
    // Get error breakdowns from recent rollups
    const rollups = await c.env.DB.prepare(
      `SELECT date, error_breakdown, total_errors, total_requests
       FROM usage_rollups WHERE tenant_id = ? AND date >= ? ORDER BY date DESC LIMIT 7`,
    )
      .bind(tenantId, daysAgo(7))
      .all<{ date: string; error_breakdown: string; total_errors: number; total_requests: number }>();

    // Aggregate error codes across days
    const errorMap = new Map<string, { count: number; endpoints: Set<string> }>();
    let totalErrors = 0;
    let totalRequests = 0;

    for (const row of rollups.results || []) {
      totalErrors += row.total_errors;
      totalRequests += row.total_requests;

      let breakdown: Record<string, { count: number; endpoints?: string[] }>;
      try {
        breakdown = JSON.parse(row.error_breakdown || '{}');
      } catch {
        continue;
      }

      for (const [code, info] of Object.entries(breakdown)) {
        const existing = errorMap.get(code) || { count: 0, endpoints: new Set<string>() };
        existing.count += typeof info === 'number' ? info : info.count || 0;
        if (typeof info === 'object' && info.endpoints) {
          for (const ep of info.endpoints) {
            existing.endpoints.add(ep);
          }
        }
        errorMap.set(code, existing);
      }
    }

    const byCode = Array.from(errorMap.entries())
      .map(([code, stats]) => ({
        status_code: code,
        count: stats.count,
        pct_of_errors: totalErrors > 0 ? Math.round((stats.count / totalErrors) * 10000) / 100 : 0,
        affected_endpoints: Array.from(stats.endpoints).slice(0, 10),
      }))
      .sort((a, b) => b.count - a.count);

    return {
      period: 'last_7d',
      total_requests: totalRequests,
      total_errors: totalErrors,
      error_rate_pct:
        totalRequests > 0
          ? Math.round((totalErrors / totalRequests) * 10000) / 100
          : 0,
      by_status_code: byCode,
    };
  });

  return c.json(ok(data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /quota — Current quota status
// ---------------------------------------------------------------------------
app.get('/quota', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const apiKey = getApiKey(c);
  const tenantId = auth.tenant_id;
  const plan = auth.plan || 'free';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;

  // Use tenant-level limits from auth if available (they may differ from plan defaults)
  const tenantLimits = auth.tenant
    ? {
        rate: auth.tenant.rate_limit || limits.rate,
        daily: auth.tenant.daily_limit || limits.daily,
        monthly: auth.tenant.monthly_limit || limits.monthly,
      }
    : limits;

  // Get current usage from SDK Gateway
  const [usageData, tenantUsage] = await Promise.all([
    fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage'),
    fetchGatewayUsage(c.env.SDK_GATEWAY, apiKey, '/auth/usage/tenant'),
  ]);

  const todayData = usageData?.today as Record<string, number> | undefined;
  const monthData = tenantUsage?.this_month as Record<string, number> | undefined;

  const dailyUsed = todayData?.requests || 0;
  const monthlyUsed = monthData?.requests || 0;

  const dailyPct = tenantLimits.daily > 0 ? Math.round((dailyUsed / tenantLimits.daily) * 10000) / 100 : 0;
  const monthlyPct = tenantLimits.monthly > 0 ? Math.round((monthlyUsed / tenantLimits.monthly) * 10000) / 100 : 0;

  // Projected monthly usage based on current daily average
  const dayOfMonth = new Date().getDate();
  const daysInMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate();
  const projectedMonthly = dayOfMonth > 0 ? Math.round((monthlyUsed / dayOfMonth) * daysInMonth) : 0;
  const projectedPct = tenantLimits.monthly > 0 ? Math.round((projectedMonthly / tenantLimits.monthly) * 10000) / 100 : 0;

  // Determine quota warnings
  const warnings: string[] = [];
  if (dailyPct >= 90) warnings.push('Daily quota nearly exhausted (>90%)');
  if (dailyPct >= 100) warnings.push('Daily quota EXCEEDED');
  if (monthlyPct >= 80) warnings.push('Monthly quota >80% consumed');
  if (monthlyPct >= 100) warnings.push('Monthly quota EXCEEDED');
  if (projectedPct >= 100) warnings.push(`Projected to exceed monthly quota (${projectedPct}%)`);

  const quotaData = {
    tenant_id: tenantId,
    plan,
    limits: {
      rate_per_minute: tenantLimits.rate,
      daily: tenantLimits.daily,
      monthly: tenantLimits.monthly,
    },
    usage: {
      daily: {
        used: dailyUsed,
        remaining: Math.max(0, tenantLimits.daily - dailyUsed),
        pct: dailyPct,
      },
      monthly: {
        used: monthlyUsed,
        remaining: Math.max(0, tenantLimits.monthly - monthlyUsed),
        pct: monthlyPct,
      },
    },
    projection: {
      estimated_monthly_total: projectedMonthly,
      pct_of_limit: projectedPct,
      days_remaining: daysInMonth - dayOfMonth,
    },
    warnings,
    reset: {
      daily: `${today()}T00:00:00Z (next midnight UTC)`,
      monthly: `${thisMonth()}-01T00:00:00Z (next month)`,
    },
  };

  return c.json(ok(quotaData, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /keys — List API keys (proxied from SDK Gateway)
// ---------------------------------------------------------------------------
app.get('/keys', async (c) => {
  const start = Date.now();
  const apiKey = getApiKey(c);
  const auth = getAuth(c);

  const resp = await proxyToGateway(c.env.SDK_GATEWAY, 'GET', '/auth/keys', apiKey);
  const body = (await resp.json()) as Envelope;

  if (!body.success) {
    return c.json(
      err(
        body.error?.message || 'Failed to list keys',
        body.error?.code || 'ECHO_DASHBOARD_KEY_LIST_FAILED',
        v(c),
      ),
      (resp.status || 500) as ContentfulStatusCode,
    );
  }

  await auditLog(c.env.DB, auth.tenant_id, 'list', 'api_keys', {}, c.req.header('CF-Connecting-IP'));

  return c.json(ok(body.data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// POST /keys — Create API key (proxied)
// ---------------------------------------------------------------------------
app.post('/keys', async (c) => {
  const start = Date.now();
  const apiKey = getApiKey(c);
  const auth = getAuth(c);

  const requestBody = await c.req.json().catch(() => null);
  if (!requestBody) {
    return c.json(err('Invalid JSON body', 'ECHO_DASHBOARD_INVALID_BODY', v(c)), 400);
  }

  // Ensure tenant_id is set to the authenticated tenant
  const payload = {
    ...requestBody,
    tenant_id: auth.tenant_id,
  };

  const resp = await proxyToGateway(c.env.SDK_GATEWAY, 'POST', '/auth/keys', apiKey, payload);
  const body = (await resp.json()) as Envelope;

  if (!body.success) {
    return c.json(
      err(
        body.error?.message || 'Failed to create key',
        body.error?.code || 'ECHO_DASHBOARD_KEY_CREATE_FAILED',
        v(c),
      ),
      (resp.status || 500) as ContentfulStatusCode,
    );
  }

  await auditLog(
    c.env.DB,
    auth.tenant_id,
    'create',
    'api_keys',
    { name: payload.name, scopes: payload.scopes },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(ok(body.data, v(c), Date.now() - start), 201);
});

// ---------------------------------------------------------------------------
// DELETE /keys/:id — Revoke key (proxied)
// ---------------------------------------------------------------------------
app.delete('/keys/:id', async (c) => {
  const start = Date.now();
  const apiKey = getApiKey(c);
  const auth = getAuth(c);
  const keyId = c.req.param('id');

  const resp = await proxyToGateway(c.env.SDK_GATEWAY, 'DELETE', `/auth/keys/${keyId}`, apiKey);
  const body = (await resp.json()) as Envelope;

  if (!body.success) {
    return c.json(
      err(
        body.error?.message || 'Failed to revoke key',
        body.error?.code || 'ECHO_DASHBOARD_KEY_REVOKE_FAILED',
        v(c),
      ),
      (resp.status || 500) as ContentfulStatusCode,
    );
  }

  await auditLog(
    c.env.DB,
    auth.tenant_id,
    'revoke',
    'api_keys',
    { key_id: keyId },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(ok(body.data, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /alerts — List configured alerts
// ---------------------------------------------------------------------------
app.get('/alerts', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const result = await c.env.DB.prepare(
    'SELECT * FROM alerts WHERE tenant_id = ? ORDER BY created_at DESC',
  )
    .bind(tenantId)
    .all<AlertRow>();

  const alerts = (result.results || []).map((a) => ({
    ...a,
    enabled: Boolean(a.enabled),
  }));

  return c.json(ok({ alerts, total: alerts.length }, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// POST /alerts — Create alert
// ---------------------------------------------------------------------------
app.post('/alerts', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const body = await c.req.json<{
    type: string;
    threshold: number;
    channel?: string;
  }>().catch(() => null);

  if (!body || !body.type || body.threshold === undefined) {
    return c.json(
      err('type and threshold are required', 'ECHO_DASHBOARD_VALIDATION', v(c)),
      400,
    );
  }

  const validTypes = [
    'rate_limit_warning',
    'error_spike',
    'quota_daily_threshold',
    'quota_monthly_threshold',
    'latency_threshold',
    'error_rate_threshold',
  ];
  if (!validTypes.includes(body.type)) {
    return c.json(
      err(
        `Invalid alert type. Valid types: ${validTypes.join(', ')}`,
        'ECHO_DASHBOARD_INVALID_ALERT_TYPE',
        v(c),
      ),
      400,
    );
  }

  if (typeof body.threshold !== 'number' || body.threshold < 0) {
    return c.json(
      err('threshold must be a non-negative number', 'ECHO_DASHBOARD_VALIDATION', v(c)),
      400,
    );
  }

  const validChannels = ['email', 'webhook', 'slack', 'moltbook'];
  const channel = body.channel || 'email';
  if (!validChannels.includes(channel)) {
    return c.json(
      err(
        `Invalid channel. Valid channels: ${validChannels.join(', ')}`,
        'ECHO_DASHBOARD_INVALID_CHANNEL',
        v(c),
      ),
      400,
    );
  }

  // Limit alerts per tenant
  const countRow = await c.env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM alerts WHERE tenant_id = ?',
  )
    .bind(tenantId)
    .first<{ cnt: number }>();

  if ((countRow?.cnt || 0) >= 50) {
    return c.json(
      err('Maximum 50 alerts per tenant', 'ECHO_DASHBOARD_ALERT_LIMIT', v(c)),
      429,
    );
  }

  const alertId = `alt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

  await c.env.DB.prepare(
    `INSERT INTO alerts (id, tenant_id, type, threshold, channel, enabled)
     VALUES (?, ?, ?, ?, ?, 1)`,
  )
    .bind(alertId, tenantId, body.type, body.threshold, channel)
    .run();

  await auditLog(
    c.env.DB,
    tenantId,
    'create',
    'alerts',
    { alert_id: alertId, type: body.type, threshold: body.threshold, channel },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(
    ok(
      {
        id: alertId,
        tenant_id: tenantId,
        type: body.type,
        threshold: body.threshold,
        channel,
        enabled: true,
        last_triggered: null,
        created_at: new Date().toISOString(),
      },
      v(c),
      Date.now() - start,
    ),
    201,
  );
});

// ---------------------------------------------------------------------------
// PUT /alerts/:id — Update alert
// ---------------------------------------------------------------------------
app.put('/alerts/:id', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;
  const alertId = c.req.param('id');

  // Verify ownership
  const existing = await c.env.DB.prepare(
    'SELECT tenant_id FROM alerts WHERE id = ?',
  )
    .bind(alertId)
    .first<{ tenant_id: string }>();

  if (!existing) {
    return c.json(err('Alert not found', 'ECHO_DASHBOARD_NOT_FOUND', v(c)), 404);
  }
  if (existing.tenant_id !== tenantId) {
    return c.json(err('Access denied', 'ECHO_DASHBOARD_FORBIDDEN', v(c)), 403);
  }

  const body = await c.req.json<{
    type?: string;
    threshold?: number;
    channel?: string;
    enabled?: boolean;
  }>().catch(() => null);

  if (!body) {
    return c.json(err('Invalid JSON body', 'ECHO_DASHBOARD_INVALID_BODY', v(c)), 400);
  }

  // Build dynamic UPDATE
  const setClauses: string[] = [];
  const params: (string | number)[] = [];

  if (body.type !== undefined) {
    const validTypes = [
      'rate_limit_warning', 'error_spike', 'quota_daily_threshold',
      'quota_monthly_threshold', 'latency_threshold', 'error_rate_threshold',
    ];
    if (!validTypes.includes(body.type)) {
      return c.json(err('Invalid alert type', 'ECHO_DASHBOARD_INVALID_ALERT_TYPE', v(c)), 400);
    }
    setClauses.push('type = ?');
    params.push(body.type);
  }
  if (body.threshold !== undefined) {
    if (typeof body.threshold !== 'number' || body.threshold < 0) {
      return c.json(err('threshold must be a non-negative number', 'ECHO_DASHBOARD_VALIDATION', v(c)), 400);
    }
    setClauses.push('threshold = ?');
    params.push(body.threshold);
  }
  if (body.channel !== undefined) {
    const validChannels = ['email', 'webhook', 'slack', 'moltbook'];
    if (!validChannels.includes(body.channel)) {
      return c.json(err('Invalid channel', 'ECHO_DASHBOARD_INVALID_CHANNEL', v(c)), 400);
    }
    setClauses.push('channel = ?');
    params.push(body.channel);
  }
  if (body.enabled !== undefined) {
    setClauses.push('enabled = ?');
    params.push(body.enabled ? 1 : 0);
  }

  if (setClauses.length === 0) {
    return c.json(err('No fields to update', 'ECHO_DASHBOARD_VALIDATION', v(c)), 400);
  }

  params.push(alertId);
  await c.env.DB.prepare(`UPDATE alerts SET ${setClauses.join(', ')} WHERE id = ?`)
    .bind(...params)
    .run();

  // Fetch updated row
  const updated = await c.env.DB.prepare('SELECT * FROM alerts WHERE id = ?')
    .bind(alertId)
    .first<AlertRow>();

  await auditLog(
    c.env.DB,
    tenantId,
    'update',
    'alerts',
    { alert_id: alertId, changes: body },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(
    ok(
      updated ? { ...updated, enabled: Boolean(updated.enabled) } : null,
      v(c),
      Date.now() - start,
    ),
  );
});

// ---------------------------------------------------------------------------
// DELETE /alerts/:id — Delete alert
// ---------------------------------------------------------------------------
app.delete('/alerts/:id', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;
  const alertId = c.req.param('id');

  // Verify ownership
  const existing = await c.env.DB.prepare(
    'SELECT tenant_id FROM alerts WHERE id = ?',
  )
    .bind(alertId)
    .first<{ tenant_id: string }>();

  if (!existing) {
    return c.json(err('Alert not found', 'ECHO_DASHBOARD_NOT_FOUND', v(c)), 404);
  }
  if (existing.tenant_id !== tenantId) {
    return c.json(err('Access denied', 'ECHO_DASHBOARD_FORBIDDEN', v(c)), 403);
  }

  await c.env.DB.prepare('DELETE FROM alerts WHERE id = ?').bind(alertId).run();

  await auditLog(
    c.env.DB,
    tenantId,
    'delete',
    'alerts',
    { alert_id: alertId },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(ok({ deleted: alertId }, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// GET /audit — Audit log (paginated, filterable)
// ---------------------------------------------------------------------------
app.get('/audit', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const page = Math.max(1, parseInt(c.req.query('page') || '1', 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(c.req.query('page_size') || '50', 10)));
  const action = c.req.query('action');
  const resource = c.req.query('resource');
  const offset = (page - 1) * pageSize;

  // Build query dynamically
  let whereClause = 'WHERE tenant_id = ?';
  const params: (string | number)[] = [tenantId];

  if (action) {
    whereClause += ' AND action = ?';
    params.push(action);
  }
  if (resource) {
    whereClause += ' AND resource = ?';
    params.push(resource);
  }

  // Count total
  const countRow = await c.env.DB.prepare(`SELECT COUNT(*) as cnt FROM audit_log ${whereClause}`)
    .bind(...params)
    .first<{ cnt: number }>();

  const total = countRow?.cnt || 0;

  // Fetch page
  const results = await c.env.DB.prepare(
    `SELECT * FROM audit_log ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(...params, pageSize, offset)
    .all<AuditRow>();

  const entries = (results.results || []).map((row) => ({
    ...row,
    details: safeJsonParse(row.details, {}),
  }));

  return c.json(
    ok(
      {
        entries,
        pagination: {
          page,
          page_size: pageSize,
          total,
          total_pages: Math.ceil(total / pageSize),
          has_next: page * pageSize < total,
          has_prev: page > 1,
        },
      },
      v(c),
      Date.now() - start,
    ),
  );
});

// ---------------------------------------------------------------------------
// GET /reports — List saved reports
// ---------------------------------------------------------------------------
app.get('/reports', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const result = await c.env.DB.prepare(
    'SELECT * FROM saved_reports WHERE tenant_id = ? ORDER BY created_at DESC',
  )
    .bind(tenantId)
    .all<ReportRow>();

  const reports = (result.results || []).map((r) => ({
    ...r,
    filters: safeJsonParse(r.filters, {}),
  }));

  return c.json(ok({ reports, total: reports.length }, v(c), Date.now() - start));
});

// ---------------------------------------------------------------------------
// POST /reports — Create saved report
// ---------------------------------------------------------------------------
app.post('/reports', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const body = await c.req.json<{
    name: string;
    report_type: string;
    filters?: Record<string, unknown>;
    schedule?: string;
  }>().catch(() => null);

  if (!body || !body.name || !body.report_type) {
    return c.json(
      err('name and report_type are required', 'ECHO_DASHBOARD_VALIDATION', v(c)),
      400,
    );
  }

  const validTypes = [
    'usage_summary',
    'endpoint_breakdown',
    'error_analysis',
    'quota_forecast',
    'key_activity',
    'custom',
  ];
  if (!validTypes.includes(body.report_type)) {
    return c.json(
      err(
        `Invalid report_type. Valid types: ${validTypes.join(', ')}`,
        'ECHO_DASHBOARD_INVALID_REPORT_TYPE',
        v(c),
      ),
      400,
    );
  }

  // Limit reports per tenant
  const countRow = await c.env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM saved_reports WHERE tenant_id = ?',
  )
    .bind(tenantId)
    .first<{ cnt: number }>();

  if ((countRow?.cnt || 0) >= 100) {
    return c.json(
      err('Maximum 100 saved reports per tenant', 'ECHO_DASHBOARD_REPORT_LIMIT', v(c)),
      429,
    );
  }

  const reportId = `rpt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

  await c.env.DB.prepare(
    `INSERT INTO saved_reports (id, tenant_id, name, report_type, filters, schedule)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      reportId,
      tenantId,
      body.name,
      body.report_type,
      JSON.stringify(body.filters || {}),
      body.schedule || null,
    )
    .run();

  await auditLog(
    c.env.DB,
    tenantId,
    'create',
    'reports',
    { report_id: reportId, name: body.name, report_type: body.report_type },
    c.req.header('CF-Connecting-IP'),
  );

  return c.json(
    ok(
      {
        id: reportId,
        tenant_id: tenantId,
        name: body.name,
        report_type: body.report_type,
        filters: body.filters || {},
        schedule: body.schedule || null,
        last_run: null,
        created_at: new Date().toISOString(),
      },
      v(c),
      Date.now() - start,
    ),
    201,
  );
});

// ---------------------------------------------------------------------------
// GET /config — Get dashboard config
// ---------------------------------------------------------------------------
app.get('/config', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const config = await c.env.DB.prepare(
    'SELECT * FROM dashboard_configs WHERE tenant_id = ?',
  )
    .bind(tenantId)
    .first<DashboardConfigRow>();

  if (!config) {
    // Return default config if none exists
    return c.json(
      ok(
        {
          tenant_id: tenantId,
          layout: {},
          widgets: [
            'usage_summary',
            'quota_gauge',
            'error_rate',
            'top_endpoints',
            'latency_chart',
            'recent_audit',
          ],
          theme: 'dark',
          created_at: null,
          updated_at: null,
        },
        v(c),
        Date.now() - start,
      ),
    );
  }

  return c.json(
    ok(
      {
        tenant_id: config.tenant_id,
        layout: safeJsonParse(config.layout, {}),
        widgets: safeJsonParse(config.widgets, []),
        theme: config.theme,
        created_at: config.created_at,
        updated_at: config.updated_at,
      },
      v(c),
      Date.now() - start,
    ),
  );
});

// ---------------------------------------------------------------------------
// PUT /config — Update dashboard config
// ---------------------------------------------------------------------------
app.put('/config', async (c) => {
  const start = Date.now();
  const auth = getAuth(c);
  const tenantId = auth.tenant_id;

  const body = await c.req.json<{
    layout?: Record<string, unknown>;
    widgets?: string[];
    theme?: string;
  }>().catch(() => null);

  if (!body) {
    return c.json(err('Invalid JSON body', 'ECHO_DASHBOARD_INVALID_BODY', v(c)), 400);
  }

  const validThemes = ['dark', 'light', 'system'];
  if (body.theme && !validThemes.includes(body.theme)) {
    return c.json(
      err(`Invalid theme. Valid themes: ${validThemes.join(', ')}`, 'ECHO_DASHBOARD_VALIDATION', v(c)),
      400,
    );
  }

  if (body.widgets && (!Array.isArray(body.widgets) || body.widgets.length > 20)) {
    return c.json(
      err('widgets must be an array of up to 20 widget identifiers', 'ECHO_DASHBOARD_VALIDATION', v(c)),
      400,
    );
  }

  // Upsert
  const layoutStr = body.layout !== undefined ? JSON.stringify(body.layout) : '{}';
  const widgetsStr = body.widgets !== undefined ? JSON.stringify(body.widgets) : '[]';
  const theme = body.theme || 'dark';

  await c.env.DB.prepare(
    `INSERT INTO dashboard_configs (tenant_id, layout, widgets, theme, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))
     ON CONFLICT(tenant_id)
     DO UPDATE SET
       layout = COALESCE(?, layout),
       widgets = COALESCE(?, widgets),
       theme = COALESCE(?, theme),
       updated_at = datetime('now')`,
  )
    .bind(
      tenantId,
      layoutStr,
      widgetsStr,
      theme,
      body.layout !== undefined ? layoutStr : null,
      body.widgets !== undefined ? widgetsStr : null,
      body.theme !== undefined ? theme : null,
    )
    .run();

  await auditLog(
    c.env.DB,
    tenantId,
    'update',
    'dashboard_config',
    { fields_updated: Object.keys(body) },
    c.req.header('CF-Connecting-IP'),
  );

  // Fetch the updated config
  const updated = await c.env.DB.prepare(
    'SELECT * FROM dashboard_configs WHERE tenant_id = ?',
  )
    .bind(tenantId)
    .first<DashboardConfigRow>();

  return c.json(
    ok(
      updated
        ? {
            tenant_id: updated.tenant_id,
            layout: safeJsonParse(updated.layout, {}),
            widgets: safeJsonParse(updated.widgets, []),
            theme: updated.theme,
            created_at: updated.created_at,
            updated_at: updated.updated_at,
          }
        : null,
      v(c),
      Date.now() - start,
    ),
  );
});

// ---------------------------------------------------------------------------
// 404 catch-all
// ---------------------------------------------------------------------------
app.all('*', (c) => {
  return c.json(
    err(
      `Route ${c.req.method} ${c.req.path} not found`,
      'ECHO_DASHBOARD_NOT_FOUND',
      c.env.WORKER_VERSION || '1.0.0',
    ),
    404,
  );
});

// ---------------------------------------------------------------------------
// Safe JSON parse utility
// ---------------------------------------------------------------------------

function safeJsonParse<T>(input: string | null | undefined, fallback: T): T {
  if (!input) return fallback;
  try {
    return JSON.parse(input) as T;
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Cron handlers
// ---------------------------------------------------------------------------

async function handleDailyRollup(env: Env): Promise<void> {
  log('info', 'Running daily usage rollup cron');

  try {
    // Get all tenants that had activity (via SDK Gateway usage/tenant endpoint won't work
    // without per-tenant auth, so we roll up from our own audit log as a proxy,
    // and from any existing rollup data)

    // Get distinct tenants from audit log in the last 24h
    const activeTenants = await env.DB.prepare(
      `SELECT DISTINCT tenant_id FROM audit_log
       WHERE created_at >= datetime('now', '-1 day')`,
    ).all<{ tenant_id: string }>();

    const yesterday = daysAgo(1);

    for (const row of activeTenants.results || []) {
      const tenantId = row.tenant_id;

      // Count audit events as a proxy for activity
      const auditStats = await env.DB.prepare(
        `SELECT COUNT(*) as total,
                SUM(CASE WHEN action LIKE '%error%' THEN 1 ELSE 0 END) as errors
         FROM audit_log WHERE tenant_id = ? AND created_at >= ? AND created_at < ?`,
      )
        .bind(tenantId, yesterday, today())
        .first<{ total: number; errors: number }>();

      // Upsert rollup
      await env.DB.prepare(
        `INSERT INTO usage_rollups (tenant_id, date, total_requests, total_errors, avg_latency_ms, p95_latency_ms, p99_latency_ms, top_endpoints, error_breakdown)
         VALUES (?, ?, ?, ?, 0, 0, 0, '[]', '{}')
         ON CONFLICT(tenant_id, date) DO UPDATE SET
           total_requests = total_requests + excluded.total_requests,
           total_errors = total_errors + excluded.total_errors`,
      )
        .bind(tenantId, yesterday, auditStats?.total || 0, auditStats?.errors || 0)
        .run();
    }

    // Cleanup: delete audit entries older than 90 days
    await env.DB.prepare(
      `DELETE FROM audit_log WHERE created_at < datetime('now', '-90 days')`,
    ).run();

    // Cleanup: delete usage rollups older than 365 days
    await env.DB.prepare(
      `DELETE FROM usage_rollups WHERE date < ?`,
    )
      .bind(daysAgo(365))
      .run();

    log('info', 'Daily rollup complete', {
      tenants_processed: (activeTenants.results || []).length,
    });
  } catch (e) {
    log('error', 'Daily rollup failed', {
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

async function handleAlertEvaluation(env: Env): Promise<void> {
  log('info', 'Running alert evaluation cron');

  try {
    // Get all enabled alerts
    const alertRows = await env.DB.prepare(
      `SELECT a.*, r.total_requests, r.total_errors, r.avg_latency_ms
       FROM alerts a
       LEFT JOIN usage_rollups r ON a.tenant_id = r.tenant_id AND r.date = ?
       WHERE a.enabled = 1`,
    )
      .bind(today())
      .all<AlertRow & { total_requests: number | null; total_errors: number | null; avg_latency_ms: number | null }>();

    let triggered = 0;

    for (const alert of alertRows.results || []) {
      let shouldTrigger = false;
      const requests = alert.total_requests || 0;
      const errors = alert.total_errors || 0;
      const latency = alert.avg_latency_ms || 0;

      switch (alert.type) {
        case 'quota_daily_threshold': {
          // Check if daily requests exceed threshold percentage
          const plan = PLAN_LIMITS.free; // Default; real plan lookup would need SDK Gateway
          const pct = plan.daily > 0 ? (requests / plan.daily) * 100 : 0;
          shouldTrigger = pct >= alert.threshold;
          break;
        }
        case 'error_spike': {
          shouldTrigger = errors >= alert.threshold;
          break;
        }
        case 'error_rate_threshold': {
          const errorRate = requests > 0 ? (errors / requests) * 100 : 0;
          shouldTrigger = errorRate >= alert.threshold;
          break;
        }
        case 'latency_threshold': {
          shouldTrigger = latency >= alert.threshold;
          break;
        }
        case 'rate_limit_warning': {
          // This would ideally check real-time rate limit hits; for now, use request count as proxy
          shouldTrigger = requests >= alert.threshold;
          break;
        }
        case 'quota_monthly_threshold': {
          // Sum all rollups this month
          const monthlySum = await env.DB.prepare(
            `SELECT SUM(total_requests) as total FROM usage_rollups
             WHERE tenant_id = ? AND date LIKE ?`,
          )
            .bind(alert.tenant_id, `${thisMonth()}%`)
            .first<{ total: number }>();

          const monthlyTotal = monthlySum?.total || 0;
          const plan = PLAN_LIMITS.free;
          const monthPct = plan.monthly > 0 ? (monthlyTotal / plan.monthly) * 100 : 0;
          shouldTrigger = monthPct >= alert.threshold;
          break;
        }
      }

      if (shouldTrigger) {
        // Check cooldown: don't re-trigger within 6 hours
        if (alert.last_triggered) {
          const lastTriggered = new Date(alert.last_triggered).getTime();
          const sixHoursAgo = Date.now() - 6 * 60 * 60 * 1000;
          if (lastTriggered > sixHoursAgo) continue;
        }

        // Update last_triggered
        await env.DB.prepare(
          `UPDATE alerts SET last_triggered = datetime('now') WHERE id = ?`,
        )
          .bind(alert.id)
          .run();

        // Log the trigger event
        await auditLog(
          env.DB,
          alert.tenant_id,
          'alert_triggered',
          'alerts',
          {
            alert_id: alert.id,
            type: alert.type,
            threshold: alert.threshold,
            channel: alert.channel,
          },
        );

        triggered++;

        log('info', 'Alert triggered', {
          alert_id: alert.id,
          tenant_id: alert.tenant_id,
          type: alert.type,
          threshold: alert.threshold,
          channel: alert.channel,
        });
      }
    }

    log('info', 'Alert evaluation complete', {
      alerts_evaluated: (alertRows.results || []).length,
      alerts_triggered: triggered,
    });
  } catch (e) {
    log('error', 'Alert evaluation failed', {
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export default {
  fetch: app.fetch,

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const cron = event.cron;
    log('info', 'Cron triggered', { cron });

    if (cron === '0 0 * * *') {
      // Midnight UTC — daily rollup
      ctx.waitUntil(handleDailyRollup(env));
    } else if (cron === '0 */6 * * *') {
      // Every 6 hours — alert evaluation
      ctx.waitUntil(handleAlertEvaluation(env));
    } else {
      log('warn', 'Unknown cron trigger', { cron });
    }
  },
};
