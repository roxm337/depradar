import { NextRequest } from "next/server";

async function proxy(request: NextRequest, context: RouteContext<"/api/backend/[...path]">) {
  const { path } = await context.params;
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

  if (path.join("/") === "auth/bootstrap") {
    const bootstrapToken = process.env.DEPRADAR_BOOTSTRAP_TOKEN;
    if (!bootstrapToken) {
      return Response.json({ detail: "Initialize the owner with `docker compose exec api depradar setup-owner`." }, { status: 409 });
    }
    headers.set("x-bootstrap-token", bootstrapToken);
  }

  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" ? undefined : await request.arrayBuffer(),
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
