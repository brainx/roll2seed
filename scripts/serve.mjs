import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";

const platformPort = process.env.PORT;
// Many hosting platforms set PORT automatically. Binding a cleartext HTTP seed
// generator to all interfaces must be a deliberate choice, never a side effect.
const exposeToNetwork = process.env.ROLL2SEED_EXPOSE === "1";
const host = process.env.HOST ?? (platformPort && exposeToNetwork ? "0.0.0.0" : "127.0.0.1");
const configuredPort = Number(platformPort ?? process.env.ROLL2SEED_PORT ?? "4173");
if (!Number.isInteger(configuredPort) || configuredPort < 1024 || configuredPort > 65535) {
  throw new Error("PORT or ROLL2SEED_PORT must be an integer from 1024 through 65535");
}

const root = resolve("dist");
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
]);

const securityHeaders = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'none'",
    "connect-src 'none'",
    "media-src 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "worker-src 'none'",
    "manifest-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
  ].join("; "),
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": [
    "camera=()",
    "clipboard-read=()",
    "clipboard-write=()",
    "geolocation=()",
    "hid=()",
    "microphone=()",
    "payment=()",
    "serial=()",
    "usb=()",
  ].join(", "),
  "Referrer-Policy": "no-referrer",
  // Honored only when a TLS-terminating proxy passes the response through;
  // browsers ignore HSTS received over cleartext HTTP, so local use is unaffected.
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-DNS-Prefetch-Control": "off",
  "X-Frame-Options": "DENY",
};

function sendText(response, statusCode, text) {
  response.writeHead(statusCode, {
    ...securityHeaders,
    "Content-Type": "text/plain; charset=utf-8",
  });
  response.end(text);
}

const server = createServer(async (request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.setHeader("Allow", "GET, HEAD");
    sendText(response, 405, "Method not allowed");
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url ?? "/", `http://${host}`).pathname);
  } catch {
    sendText(response, 400, "Bad request");
    return;
  }

  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = resolve(root, relativePath);
  if (filePath !== root && !filePath.startsWith(`${root}${sep}`)) {
    sendText(response, 404, "Not found");
    return;
  }

  try {
    const metadata = await stat(filePath);
    if (!metadata.isFile()) {
      sendText(response, 404, "Not found");
      return;
    }

    response.writeHead(200, {
      ...securityHeaders,
      "Content-Length": metadata.size,
      "Content-Type": contentTypes.get(extname(filePath)) ?? "application/octet-stream",
    });
    if (request.method === "HEAD") {
      response.end();
      return;
    }
    createReadStream(filePath).pipe(response);
  } catch {
    sendText(response, 404, "Not found");
  }
});

server.listen(configuredPort, host, () => {
  process.stdout.write(`Roll2Seed is available at http://${host}:${configuredPort}\n`);
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    process.stderr.write(
      "WARNING: Roll2Seed is listening on a non-loopback interface over cleartext HTTP. " +
        "Only do this behind a trusted TLS-terminating proxy; otherwise a network attacker " +
        "can modify the delivered code and steal generated seeds.\n",
    );
  }
});

function closeServer() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", closeServer);
process.on("SIGTERM", closeServer);
