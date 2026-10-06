const SITE_ORIGIN = "https://graceli62-cell.github.io";
const HASH_ITERATIONS = 600_000;

function responseHeaders(origin: string | null): HeadersInit {
  return {
    "Access-Control-Allow-Origin": origin ?? SITE_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type, x-supabase-api-version",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8",
  };
}

function jsonResponse(body: Record<string, unknown>, status: number, headers: HeadersInit): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function verifyPassphrase(passphrase: string, saltBase64: string, hashBase64: string): Promise<boolean> {
  const salt = decodeBase64(saltBase64);
  const expectedHash = decodeBase64(hashBase64);
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const actualHash = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: HASH_ITERATIONS, hash: "SHA-256" },
    material,
    expectedHash.length * 8,
  ));
  return constantTimeEqual(actualHash, expectedHash);
}

Deno.serve(async (request: Request): Promise<Response> => {
  const origin = request.headers.get("origin");
  const headers = responseHeaders(origin === SITE_ORIGIN ? origin : null);

  if (origin && origin !== SITE_ORIGIN) {
    return jsonResponse({ error: "Origin not allowed" }, 403, headers);
  }
  if (request.method === "OPTIONS") return new Response("ok", { headers });
  if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405, headers);

  let body: { passphrase?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid request" }, 400, headers);
  }

  if (typeof body.passphrase !== "string" || body.passphrase.length === 0 || body.passphrase.length > 128) {
    return jsonResponse({ error: "Invalid request" }, 400, headers);
  }

  const projectUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!projectUrl || !serviceKey) return jsonResponse({ error: "Server configuration error" }, 500, headers);

  const adminHeaders = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    "Content-Type": "application/json",
  };

  try {
    const secretResponse = await fetch(
      `${projectUrl}/rest/v1/poll_secrets?select=secret_salt,secret_hash&singleton=eq.true`,
      { headers: adminHeaders },
    );
    if (!secretResponse.ok) return jsonResponse({ error: "Server configuration error" }, 500, headers);

    const secretRows = await secretResponse.json();
    if (!Array.isArray(secretRows) || secretRows.length !== 1) {
      return jsonResponse({ error: "Server configuration error" }, 500, headers);
    }

    const isOrganizer = await verifyPassphrase(
      body.passphrase,
      secretRows[0].secret_salt,
      secretRows[0].secret_hash,
    );
    if (!isOrganizer) return jsonResponse({ error: "Incorrect passphrase" }, 401, headers);

    const closeResponse = await fetch(
      `${projectUrl}/rest/v1/poll_status?singleton=eq.true&is_closed=eq.false`,
      {
        method: "PATCH",
        headers: { ...adminHeaders, Prefer: "return=representation" },
        body: JSON.stringify({ is_closed: true, closed_at: new Date().toISOString() }),
      },
    );
    if (!closeResponse.ok) return jsonResponse({ error: "Could not close poll" }, 500, headers);

    const updatedRows = await closeResponse.json();
    if (Array.isArray(updatedRows) && updatedRows.length === 1) {
      return jsonResponse({ ok: true, closed: true }, 200, headers);
    }

    const statusResponse = await fetch(
      `${projectUrl}/rest/v1/poll_status?select=is_closed&singleton=eq.true`,
      { headers: adminHeaders },
    );
    if (statusResponse.ok) {
      const statusRows = await statusResponse.json();
      if (Array.isArray(statusRows) && statusRows.length === 1 && statusRows[0].is_closed === true) {
        return jsonResponse({ ok: true, closed: true }, 200, headers);
      }
    }
    return jsonResponse({ error: "Could not close poll" }, 500, headers);
  } catch {
    return jsonResponse({ error: "Request failed" }, 500, headers);
  }
});
