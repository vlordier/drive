import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api/auth (auth routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files
     */
    "/((?!api/auth|_next/static|_next/image|favicon.ico|.*\\..*$).*)",
  ],
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'nonce-{nonce}' 'strict-dynamic'", // nonce for dynamic scripts
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://*.posthog.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "upgrade-insecure-requests",
  ].join("; "),
};

const SENSITIVE_ROUTES = [
  "/admin",
  "/settings",
  "/profile",
  "/billing",
];

const PUBLIC_ROUTES = [
  "/",
  "/login",
  "/register",
  "/forgot-password",
  "/reset-password",
  "/verify",
];

function getClientIp(request: NextRequest): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim();
  }
  // request.ip is available at runtime but not in types - use type assertion
  return (request as NextRequest & { ip?: string }).ip || "unknown";
}

function getCountry(request: NextRequest): string {
  // request.geo is available at runtime but not in types - use type assertion
  const geo = (request as NextRequest & { geo?: { country?: string } }).geo;
  return geo?.country || "unknown";
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const clientIp = getClientIp(request);
  const country = getCountry(request);
  const requestId = request.headers.get("x-request-id") || crypto.randomUUID();

  const response = NextResponse.next({
    request: {
      headers: new Headers(request.headers),
    },
  });

  // Generate CSP nonce for this request
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  // Add security headers with nonce
  const cspWithNonce = SECURITY_HEADERS["Content-Security-Policy"].replace(
    "{nonce}",
    nonce
  );
  response.headers.set("Content-Security-Policy", cspWithNonce);
  response.headers.set("X-Content-Type-Options", SECURITY_HEADERS["X-Content-Type-Options"]);
  response.headers.set("X-Frame-Options", SECURITY_HEADERS["X-Frame-Options"]);
  response.headers.set("X-XSS-Protection", SECURITY_HEADERS["X-XSS-Protection"]);
  response.headers.set("Referrer-Policy", SECURITY_HEADERS["Referrer-Policy"]);
  response.headers.set("Permissions-Policy", SECURITY_HEADERS["Permissions-Policy"]);
  response.headers.set("Strict-Transport-Security", SECURITY_HEADERS["Strict-Transport-Security"]);

  // Add request ID for tracing
  response.headers.set("X-Request-ID", requestId);

  // Remove sensitive headers
  response.headers.delete("X-Powered-By");
  response.headers.delete("Server");

  // Check for suspicious requests - log only, don't block (avoid false positives)
  const userAgent = request.headers.get("user-agent") || "";

  // Log but don't block known scanning tools (reduce false positives)
  const suspiciousUserAgents = [
    "sqlmap",
    "nikto",
    "nmap",
    "metasploit",
    "masscan",
    "gobuster",
    "dirbuster",
    "burp",
    "zap",
  ];

  const lowercaseUserAgent = userAgent.toLowerCase();
  if (suspiciousUserAgents.some((ua) => lowercaseUserAgent.includes(ua))) {
    console.warn(
      JSON.stringify({
        event: "suspicious_user_agent",
        requestId,
        ip: clientIp,
        path: pathname,
        userAgent,
      })
    );
  }

  // Note: Rate limiting is handled by Django DRF throttling (Redis-backed) at the API level.
  // Next.js layer rate limiting would require Redis/Edge Config for multi-instance support.

  // Block suspicious requests - path traversal and obvious attack patterns
  // These patterns indicate clear attack attempts and should be blocked
  const criticalPatterns = [
    /\.\.\//,                    // Path traversal - always block
    /\.(env|git|config|yaml|yml|ini|conf)$/i, // Sensitive file access
    /(\?|&)(exec|cmd|shell|perl|python|ruby)=/i, // Command injection
  ];

  if (criticalPatterns.some((pattern) => pattern.test(pathname))) {
    console.warn(
      JSON.stringify({
        event: "suspicious_request_blocked",
        requestId,
        ip: clientIp,
        country,
        path: pathname,
        userAgent,
      })
    );
    return new NextResponse("Forbidden", {
      status: 403,
      headers: { "X-Request-ID": requestId },
    });
  }

  // Log but don't block less critical suspicious patterns (potential false positives)
  const warningPatterns = [
    /(\?|&)phpinfo/i,     // PHP info
    /(\?|&)wp-admin/i,    // WordPress admin
    /(\?|&)admin=/i,      // Admin access attempts
  ];

  if (warningPatterns.some((pattern) => pattern.test(pathname))) {
    console.warn(
      JSON.stringify({
        event: "suspicious_request_warning",
        requestId,
        ip: clientIp,
        country,
        path: pathname,
        userAgent,
      })
    );
  }

  // Check authentication for protected routes
  const isProtectedRoute = SENSITIVE_ROUTES.some((route) =>
    pathname.startsWith(route)
  );
  const isPublicRoute = PUBLIC_ROUTES.some((route) => pathname === route);

  if (isProtectedRoute && !isPublicRoute) {
    // Check for auth token - presence check only (backend validates actual token)
    const authToken = request.cookies.get("auth_token")?.value;
    const sessionToken = request.cookies.get("session_id")?.value;

    // Basic validation: token should exist and be non-empty
    const token = authToken || sessionToken;
    const hasValidTokenFormat = token !== undefined && token.length > 0;

    if (!hasValidTokenFormat) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("redirect", pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  // Add security headers for API responses
  if (pathname.startsWith("/api/")) {
    response.headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
    response.headers.set("Pragma", "no-cache");
    response.headers.set("Expires", "0");
    response.headers.set("Surrogate-Control", "no-store");
  }

  return response;
}

// Optional: Create a separate middleware for API routes
export const apiMiddleware = (request: NextRequest) => {
  const response = NextResponse.next();

  // Add CORS headers for API
  const origin = request.headers.get("origin");
  if (origin) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",") || [];
    if (allowedOrigins.includes(origin)) {
      response.headers.set("Access-Control-Allow-Origin", origin);
      response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID");
      response.headers.set("Access-Control-Allow-Credentials", "true");
      response.headers.set("Access-Control-Max-Age", "86400");
    }
  }

  return response;
};