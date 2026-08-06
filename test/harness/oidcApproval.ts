/**
 * Approves an OIDC device-code grant against the local disposable MAS the
 * same way a human browser user would: login form, device-link form, then
 * consent. This is test-only. The test knows the password only because it
 * provisions its own throwaway MAS account; the product CLI never receives
 * a password.
 */
const MAS_BASE = "http://localhost:8082";

function extractCsrf(html: string): string {
  const match = html.match(/name="csrf" value="([^"]+)"/);
  if (!match) throw new Error("approveDeviceCode: no CSRF token found on MAS page");
  return match[1];
}

class CookieJar {
  private readonly jar = new Map<string, string>();

  private update(response: Response): void {
    const cookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    for (const cookie of cookies) {
      const [pair] = cookie.split(";");
      const [name, value] = pair.split("=");
      this.jar.set(name, value);
    }
  }

  private header(): string {
    return [...this.jar.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  async get(requestPath: string): Promise<Response> {
    const response = await fetch(MAS_BASE + requestPath, {
      headers: { Cookie: this.header() },
      redirect: "manual",
    });
    this.update(response);
    return response;
  }

  async postForm(requestPath: string, fields: Record<string, string>): Promise<Response> {
    const response = await fetch(MAS_BASE + requestPath, {
      method: "POST",
      headers: { Cookie: this.header(), "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
      redirect: "manual",
    });
    this.update(response);
    return response;
  }

  async follow(response: Response): Promise<Response> {
    let current = response;
    let location = current.headers.get("location");
    for (let redirects = 0; current.status >= 300 && current.status < 400 && location && redirects < 10; redirects++) {
      current = await this.get(location.startsWith("http") ? location.replace(MAS_BASE, "") : location);
      location = current.headers.get("location");
    }
    return current;
  }
}

/** Log into disposable MAS and approve `userCode` for its pending device. */
export async function approveDeviceCodeViaHttp(
  username: string,
  password: string,
  userCode: string,
): Promise<void> {
  const jar = new CookieJar();

  let response = await jar.get("/login");
  let html = await response.text();
  let csrf = extractCsrf(html);
  response = await jar.postForm("/login", { csrf, username, password });
  if (response.status !== 303) {
    throw new Error(`approveDeviceCode: login POST did not redirect (status ${response.status})`);
  }
  await jar.follow(response);

  response = await jar.get("/link");
  html = await response.text();
  csrf = extractCsrf(html);
  response = await jar.postForm("/link", { csrf, code: userCode });
  const devicePath = response.headers.get("location");
  if (response.status !== 303 || !devicePath) {
    throw new Error(`approveDeviceCode: entering the user code did not redirect (status ${response.status})`);
  }
  response = await jar.follow(response);
  html = await response.text();

  csrf = extractCsrf(html);
  response = await jar.postForm(devicePath, { csrf, confirm_device: "on", action: "consent" });
  if (response.status !== 200) {
    throw new Error(`approveDeviceCode: consent POST failed (status ${response.status})`);
  }
}
