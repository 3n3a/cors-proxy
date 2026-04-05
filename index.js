/**
 * CORS Proxy — Cloudflare Worker (single file)
 *
 * Features:
 *   • Proxies any request to an upstream URL passed via ?url=<encoded-url>
 *   • Origin restriction via wildcard subdomain patterns (e.g. "*.example.com")
 *   • Configurable allowed HTTP methods and headers
 *   • Handles preflight (OPTIONS) requests
 *   • Strips hop-by-hop headers from the upstream response
 *
 * Deploy:
 *   npx wrangler deploy cors-proxy.js --name cors-proxy
 *
 * Usage:
 *   https://cors-proxy.<your-zone>.workers.dev/?url=https://api.example.com/data
 */


// ──────────────────────────── CONFIG ────────────────────────────

const CONFIG = {
  /**
   * Allowed origin patterns.
   * Each entry is matched against the request's Origin header.
   *
   *   "*.example.com"       → matches foo.example.com, a.b.example.com
   *   "https://app.test.io" → exact match only
   *   "*"                   → allow everything (development only!)
   */
  allowedOrigins: [
    "*.enea.tech",
    "*.3n3a.ch",
    // "https://localhost:3000",   // uncomment for local dev
  ],

  /** HTTP methods the proxy will accept. */
  allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],

  /** Headers the client is allowed to send. */
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept"],

  /** Headers the client is allowed to read from the response. */
  exposedHeaders: ["Content-Length", "Content-Type", "X-Request-Id"],

  /** Preflight cache duration in seconds. */
  maxAge: 86400,

  /** Allow cookies / auth headers cross-origin. */
  allowCredentials: true,

  /**
   * Optional allowlist of upstream host patterns the proxy may contact.
   * Leave empty [] to allow any upstream.
   *
   *   "api.example.com"     → exact host
   *   "*.example.com"       → wildcard subdomains
   */
  allowedUpstreamHosts: [],
};

// ──────────────────────────── HELPERS ───────────────────────────

/**
 * Match a value against a pattern that may contain a leading "*." wildcard.
 *
 *   matchWildcard("*.example.com", "foo.example.com")       → true
 *   matchWildcard("*.example.com", "a.b.example.com")       → true
 *   matchWildcard("*.example.com", "example.com")           → false
 *   matchWildcard("https://exact.io", "https://exact.io")   → true
 *   matchWildcard("*", <anything>)                          → true
 */
function matchWildcard(pattern, value) {
  if (pattern === "*") return true;

  // Wildcard subdomain pattern: "*.domain.tld"
  if (pattern.startsWith("*.")) {
    const root = pattern.slice(2); // "domain.tld"
    // Extract hostname from origin (which may include scheme)
    let hostname;
    try {
      hostname = new URL(value).hostname;
    } catch {
      hostname = value;
    }
    // Must be a proper subdomain — "example.com" itself does NOT match "*.example.com"
    return hostname.endsWith(`.${root}`);
  }

  return pattern === value;
}

/** Check whether an origin is allowed by at least one configured pattern. */
function isOriginAllowed(origin) {
  if (!origin) return false;
  return CONFIG.allowedOrigins.some((p) => matchWildcard(p, origin));
}

/** Check whether an upstream URL's host is permitted. */
function isUpstreamAllowed(url) {
  if (CONFIG.allowedUpstreamHosts.length === 0) return true;
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false;
  }
  return CONFIG.allowedUpstreamHosts.some(
    (p) => matchWildcard(p.startsWith("*.") ? p : `exact://${p}`, p.startsWith("*.") ? `https://${hostname}` : `exact://${hostname}`)
      // simpler: just compare hostnames directly
  );
}

// Cleaner upstream host check:
function isUpstreamHostAllowed(targetUrl) {
  if (CONFIG.allowedUpstreamHosts.length === 0) return true;
  let hostname;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return false;
  }
  return CONFIG.allowedUpstreamHosts.some((pattern) => {
    if (pattern.startsWith("*.")) {
      const root = pattern.slice(2);
      return hostname === root || hostname.endsWith(`.${root}`);
    }
    return hostname === pattern;
  });
}

/** Build CORS headers for a given allowed origin. */
function corsHeaders(origin) {
  const headers = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": CONFIG.allowedMethods.join(", "),
    "Access-Control-Allow-Headers": CONFIG.allowedHeaders.join(", "),
    "Access-Control-Expose-Headers": CONFIG.exposedHeaders.join(", "),
    "Access-Control-Max-Age": String(CONFIG.maxAge),
  };
  if (CONFIG.allowCredentials) {
    headers["Access-Control-Allow-Credentials"] = "true";
  }
  return headers;
}

/** Headers that must not be forwarded between hops. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

function stripHopByHop(headers) {
  const cleaned = new Headers();
  for (const [key, value] of headers) {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      cleaned.set(key, value);
    }
  }
  return cleaned;
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ──────────────────────────── HANDLER ───────────────────────────

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin");

    // ── Preflight ──────────────────────────────────────────────
    if (request.method === "OPTIONS") {
      if (!isOriginAllowed(origin)) {
        return jsonError("Origin not allowed", 403);
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // ── Origin gate ────────────────────────────────────────────
    if (origin && !isOriginAllowed(origin)) {
      return jsonError("Origin not allowed", 403);
    }

    // ── Extract target URL ─────────────────────────────────────
    const { searchParams } = new URL(request.url);
    const targetUrl = searchParams.get("url");

    if (!targetUrl) {
      return jsonError(
        'Missing "url" query parameter. Usage: ?url=https://api.example.com/path',
        400
      );
    }

    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
    } catch {
      return jsonError("Invalid target URL", 400);
    }

    // Only allow http(s)
    if (!["http:", "https:"].includes(parsedTarget.protocol)) {
      return jsonError("Only http and https targets are supported", 400);
    }

    // ── Upstream host gate ─────────────────────────────────────
    if (!isUpstreamHostAllowed(targetUrl)) {
      return jsonError("Upstream host not allowed", 403);
    }

    // ── Method gate ────────────────────────────────────────────
    if (!CONFIG.allowedMethods.includes(request.method)) {
      return jsonError(`Method ${request.method} not allowed`, 405);
    }

    // ── Proxy the request ──────────────────────────────────────
    const proxyHeaders = new Headers(request.headers);
    // Remove the Origin (don't leak it to upstream) and Host
    proxyHeaders.delete("Origin");
    proxyHeaders.delete("Host");

    try {
      const upstreamResponse = await fetch(targetUrl, {
        method: request.method,
        headers: proxyHeaders,
        body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "follow",
      });

      const responseHeaders = stripHopByHop(upstreamResponse.headers);

      // Attach CORS headers
      if (origin) {
        for (const [k, v] of Object.entries(corsHeaders(origin))) {
          responseHeaders.set(k, v);
        }
      }

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return jsonError(`Upstream request failed: ${err.message}`, 502);
    }
  },
};
