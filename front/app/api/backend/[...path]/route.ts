import { NextRequest } from "next/server";

// The API accepts inventories up to 10 MiB; the margin covers JSON bodies and request framing.
// Anything larger is refused here so an unauthenticated caller cannot make this process hold it.
const MAX_BODY_BYTES = 10 * 1024 * 1024 + 64 * 1024;
const BODY_READ_TIMEOUT_MS = 30_000;

const refuse = (status: number, detail: string) => Response.json({ detail }, { status, headers: { "cache-control": "no-store" } });

async function readBody(request: NextRequest): Promise<Uint8Array<ArrayBuffer> | Response> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) return refuse(400, "Invalid Content-Length.");
    if (length > MAX_BODY_BYTES) return refuse(413, "Request body is too large.");
  }
  if (!request.body) return new Uint8Array(0);
  // Count bytes while streaming, so chunked bodies without a length are bounded too.
  const reader = request.body.getReader();
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => undefined); }, BODY_READ_TIMEOUT_MS);
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        return refuse(413, "Request body is too large.");
      }
      chunks.push(value);
    }
  } catch {
    return refuse(timedOut ? 408 : 400, timedOut ? "Request body took too long to arrive." : "Could not read the request body.");
  } finally {
    clearTimeout(deadline);
  }
  // A cancelled read ends like a finished one; never forward a truncated body.
  if (timedOut) return refuse(408, "Request body took too long to arrive.");
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}

async function proxy(request: NextRequest, context: RouteContext<"/api/backend/[...path]">) {
  const { path } = await context.params;
  // Owner setup is CLI-only (`depradar setup-owner`). The proxy never holds or injects the
  // bootstrap secret, so a browser caller cannot create the owner through this public route.
  if (path.join("/") === "auth/bootstrap") {
    return refuse(403, "Initialize the owner with `docker compose exec api depradar setup-owner`.");
  }
  const backend = (process.env.DEPRADAR_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
  const route = path.map((part) => encodeURIComponent(part)).join("/");
  const target = new URL(`${backend}/api/${route}`);
  target.search = request.nextUrl.search;

  const headers = new Headers();
  // Authorization carries CI/CD bearer tokens, so pipelines can use the same public URL.
  for (const name of ["authorization", "content-type", "cookie", "x-csrf-token"] as const) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set("origin", process.env.DEPRADAR_ALLOWED_ORIGIN ?? new URL(backend).origin);

  let body: Uint8Array<ArrayBuffer> | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const read = await readBody(request);
    if (read instanceof Response) return read;
    body = read;
  }

  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    const responseHeaders = new Headers();
    for (const name of ["content-type", "set-cookie"] as const) {
      const value = upstream.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    responseHeaders.set("cache-control", "no-store");
    return new Response(upstream.status === 204 ? null : await upstream.arrayBuffer(), {
      status: upstream.status,
      headers: responseHeaders,
    });
  } catch {
    return Response.json({ detail: "DepRadar API is unavailable. Start the backend and try again." }, { status: 503 });
  }
}

export const GET = proxy satisfies (request: NextRequest, context: RouteContext<"/api/backend/[...path]">) => Promise<Response>;
export const POST = proxy satisfies (request: NextRequest, context: RouteContext<"/api/backend/[...path]">) => Promise<Response>;
export const PUT = proxy satisfies (request: NextRequest, context: RouteContext<"/api/backend/[...path]">) => Promise<Response>;
export const DELETE = proxy satisfies (request: NextRequest, context: RouteContext<"/api/backend/[...path]">) => Promise<Response>;
