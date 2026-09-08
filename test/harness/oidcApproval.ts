import {
  readReadableStreamChunkWithAbort,
} from "../../src/cancellation.js";
import { safeErrorMessage } from "../../src/output.js";

/**
 * Approves a device grant against the disposable local MAS through its real
 * browser-facing forms. This is test infrastructure only: the password is used
 * solely to approve MAS OAuth, never by the product CLI's login flow.
 */
const MAS_BASE = new URL("http://localhost:8008/auth/");
const APPROVAL_TIMEOUT_MS = 15_000;

function cancellationError(): Error {
  return new Error("approveDeviceCode: approval cancelled");
}

async function fetchWithinApprovalBound(
  input: RequestInfo | URL,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  if (signal.aborted) throw cancellationError();
  let rejectAbort!: (error: Error) => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = reject;
  });
  const onAbort = (): void => rejectAbort(cancellationError());
  signal.addEventListener("abort", onAbort, { once: true });

  const request = Promise.resolve().then(() => {
    if (signal.aborted) throw cancellationError();
    return fetch(input, init);
  });
  request.catch(() => undefined);
  try {
    return await Promise.race([request, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function localMasUrl(location: string): URL {
  const url = new URL(location, MAS_BASE);
  if (url.origin !== MAS_BASE.origin || url.username || url.password) {
    throw new Error(`approveDeviceCode: refusing non-local MAS URL ${location}`);
  }
  if (!url.pathname.startsWith(MAS_BASE.pathname)) {
    throw new Error(`approveDeviceCode: refusing non-MAS URL ${location}`);
  }
  return url;
}

function extractCsrf(html: string): string {
  for (const match of html.matchAll(/<input\b[^>]*>/gi)) {
    const input = match[0];
    const name = input.match(/\bname\s*=\s*(["'])(.*?)\1/i)?.[2];
    if (name !== "csrf") continue;
    const value = input.match(/\bvalue\s*=\s*(["'])(.*?)\1/i)?.[2];
    if (value) return value;
  }
  throw new Error("approveDeviceCode: no CSRF token on MAS page");
}

function extractFormAction(html: string, fallback: URL): string {
  const form = html.match(/<form\b[^>]*>/i)?.[0];
  if (!form) throw new Error("approveDeviceCode: no form on MAS page");
  const action = form.match(/\baction\s*=\s*(["'])(.*?)\1/i)?.[2];
  return new URL(action || fallback.toString(), fallback).toString();
}

class CookieJar {
  private readonly cookies = new Map<string, string>();
  private readonly signal: AbortSignal;

  constructor(signal: AbortSignal) {
    this.signal = signal;
  }

  private update(response: Response): void {
    for (const cookie of response.headers.getSetCookie?.() ?? []) {
      const [pair] = cookie.split(";");
      const equals = pair.indexOf("=");
      if (equals <= 0) throw new Error("approveDeviceCode: malformed Set-Cookie header");
      const name = pair.slice(0, equals);
      const value = pair.slice(equals + 1);
      if (
        /[\u0000-\u001f\u007f-\u009f]/u.test(name) ||
        /[\u0000-\u001f\u007f-\u009f]/u.test(value)
      ) {
        throw new Error("approveDeviceCode: cookie contains a control character");
      }
      this.cookies.set(name, value);
    }
  }

  private header(): string {
    return [...this.cookies.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  async get(location: string): Promise<Response> {
    const response = await fetchWithinApprovalBound(localMasUrl(location), {
      headers: { Cookie: this.header() },
      redirect: "manual",
      signal: this.signal,
    }, this.signal);
    this.update(response);
    return response;
  }

  async post(location: string, fields: Record<string, string>): Promise<Response> {
    const response = await fetchWithinApprovalBound(localMasUrl(location), {
      method: "POST",
      headers: {
        Cookie: this.header(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(fields).toString(),
      redirect: "manual",
      signal: this.signal,
    }, this.signal);
    this.update(response);
    return response;
  }

  async follow(response: Response): Promise<Response> {
    let current = response;
    for (let redirects = 0; redirects < 10; redirects++) {
      const location = current.headers.get("location");
      if (current.status < 300 || current.status >= 400 || !location) return current;
      current = await this.get(location);
    }
    throw new Error("approveDeviceCode: too many MAS redirects");
  }
}

function htmlDiagnostic(html: string, redactions: string[]): string {
  for (const secret of redactions) {
    if (secret) html = html.split(secret).join("<redacted>");
  }
  return safeErrorMessage(html.replace(/(<input\b[^>]*\bvalue\s*=\s*)(["'])(.*?)\2/giu, "$1$2<redacted>$2"));
}

async function readHtml(response: Response, signal: AbortSignal, redactions: string[]): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  const abortError = cancellationError();
  let failure: unknown;
  try {
    while (true) {
      const next = await readReadableStreamChunkWithAbort(reader, signal, abortError);
      if (next.done) break;
      chunks.push(next.value);
    }
  } catch (error) {
    const partial = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
    const message = error instanceof Error ? error.message : "MAS response read failed";
    failure = new Error(
      `${message}; body received before failure:\n${htmlDiagnostic(partial, redactions)}`,
      { cause: error },
    );
  } finally {
    try {
      reader.releaseLock();
    } catch (error) {
      failure = failure === undefined ? error : new AggregateError([failure, error], "MAS response read and reader cleanup failed");
    }
  }
  if (failure !== undefined) throw failure;
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

export async function approveDeviceCodeViaHttp(
  username: string,
  password: string,
  userCode: string,
  parentSignal?: AbortSignal,
): Promise<void> {
  // Keep the deadline on an ordinary timer so fake-timer tests can advance it
  // deterministically. AbortSignal.timeout() has implementation-specific
  // timer behavior and can leave a hung fetch outside the test clock.
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(cancellationError()), APPROVAL_TIMEOUT_MS);
  const signal = parentSignal ? AbortSignal.any([parentSignal, timeoutController.signal]) : timeoutController.signal;
  const jar = new CookieJar(signal);
  try {
    let response = await jar.get(new URL("login", MAS_BASE).toString());
    let csrf = extractCsrf(await readHtml(response, signal, [username, password, userCode]));
    response = await jar.post(new URL("login", MAS_BASE).toString(), { csrf, username, password });
    if (response.status !== 303) {
      const redactions = [username, password, userCode, csrf];
      throw new Error(`approveDeviceCode: login did not redirect (${response.status}): ${htmlDiagnostic(await readHtml(response, signal, redactions), redactions)}`);
    }
    await jar.follow(response);

    const linkUrl = new URL("link", MAS_BASE);
    response = await jar.get(linkUrl.toString());
    const linkHtml = await readHtml(response, signal, [username, password, userCode, csrf]);
    if (response.status !== 200) {
      throw new Error(`approveDeviceCode: device-link form failed (${response.status}): ${htmlDiagnostic(linkHtml, [username, password, userCode, csrf])}`);
    }
    csrf = extractCsrf(linkHtml);
    const linkAction = extractFormAction(linkHtml, linkUrl);
    response = await jar.post(linkAction, { csrf, code: userCode });
    const devicePath = response.headers.get("location");
    if (response.status !== 303 || !devicePath) {
      const redactions = [username, password, userCode, csrf];
      throw new Error(`approveDeviceCode: device-link submission failed (${response.status}): ${htmlDiagnostic(await readHtml(response, signal, redactions), redactions)}`);
    }
    response = await jar.follow(response);

    csrf = extractCsrf(await readHtml(response, signal, [username, password, userCode, csrf]));
    response = await jar.post(devicePath, { csrf, confirm_device: "on", action: "consent" });
    if (response.status !== 200) {
      const redactions = [username, password, userCode, csrf];
      throw new Error(`approveDeviceCode: consent failed (${response.status}): ${htmlDiagnostic(await readHtml(response, signal, redactions), redactions)}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}
