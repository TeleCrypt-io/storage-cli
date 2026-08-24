import { afterEach, describe, expect, it, vi } from "vitest";
import { approveDeviceCodeViaHttp } from "./harness/oidcApproval.js";

function response(body: string, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("local MAS device approval", () => {
  it("uses the MAS login, device-link, and consent forms with CSRF and preserved cookies", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock
      .mockResolvedValueOnce(response('<input type="hidden" name="csrf" value="login-csrf">'))
      .mockResolvedValueOnce(
        response("", 303, {
          location: "/auth/after-login",
          "set-cookie": "session=contains=equals; Path=/; HttpOnly",
        }),
      )
      .mockResolvedValueOnce(response("logged in"))
      .mockResolvedValueOnce(
        response('<form method="POST" action="/auth/link"><input type="hidden" name="csrf" value="link-csrf"></form>'),
      )
      .mockResolvedValueOnce(response("", 303, { location: "/auth/authorize/device" }))
      .mockResolvedValueOnce(response('<input type="hidden" name="csrf" value="consent-csrf">'))
      .mockResolvedValueOnce(response("approved"));

    await approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123");

    const paths = fetchMock.mock.calls.map(([input]) => new URL(String(input)).pathname);
    expect(paths).toEqual([
      "/auth/login",
      "/auth/login",
      "/auth/after-login",
      "/auth/link",
      "/auth/link",
      "/auth/authorize/device",
      "/auth/authorize/device",
    ]);
    const login = new URLSearchParams(String(fetchMock.mock.calls[1]?.[1]?.body));
    expect(Object.fromEntries(login)).toEqual({
      csrf: "login-csrf",
      username: "alice",
      password: "test-only-password",
    });
    const deviceLink = new URLSearchParams(String(fetchMock.mock.calls[4]?.[1]?.body));
    expect(Object.fromEntries(deviceLink)).toEqual({ csrf: "link-csrf", code: "ABC-123" });
    const consent = new URLSearchParams(String(fetchMock.mock.calls[6]?.[1]?.body));
    expect(Object.fromEntries(consent)).toEqual({
      csrf: "consent-csrf",
      confirm_device: "on",
      action: "consent",
    });
    expect((fetchMock.mock.calls[2]?.[1]?.headers as Record<string, string>).Cookie).toBe(
      "session=contains=equals",
    );
  });

  it("fails closed when MAS redirects the approval flow away from localhost", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock
      .mockResolvedValueOnce(response('<input type="hidden" name="csrf" value="login-csrf">'))
      .mockResolvedValueOnce(response("", 303, { location: "https://example.invalid/" }));

    await expect(approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123")).rejects.toThrow(
      /refusing non-local MAS URL/,
    );
  });

  it("fails closed when a MAS form action leaves the auth path", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock
      .mockResolvedValueOnce(response('<input type="hidden" name="csrf" value="login-csrf">'))
      .mockResolvedValueOnce(response("", 303, { location: "/auth/after-login" }))
      .mockResolvedValueOnce(response("logged in"))
      .mockResolvedValueOnce(
        response('<form method="POST" action="/outside-auth"><input type="hidden" name="csrf" value="link-csrf"></form>'),
      );

    await expect(approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123")).rejects.toThrow(
      /refusing non-MAS URL/,
    );
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("bounds local MAS HTML responses", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response("x".repeat((1 << 20) + 1)));
    vi.stubGlobal("fetch", fetchMock);

    await expect(approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123")).rejects.toThrow(
      /response exceeds the output limit/,
    );
  });

  it("aborts a hung MAS response body by the approval deadline and bounds stream cleanup", async () => {
    vi.useFakeTimers();
    try {
      let cancelCalled = false;
      const body = new ReadableStream<Uint8Array>({
        cancel: () => {
          cancelCalled = true;
          return new Promise<void>(() => {});
        },
      });
      const fetchMock = vi.fn().mockResolvedValue(new Response(body));
      vi.stubGlobal("fetch", fetchMock);

      const approval = approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123");
      const failure = expect(approval).rejects.toThrow(/approval cancelled/);
      await vi.advanceTimersByTimeAsync(15_000);
      await failure;
      expect(cancelCalled).toBe(true);

      // The reader's deliberately hung cancel must not leave a live cleanup
      // timer or an unhandled rejection after the bounded grace period.
      await vi.advanceTimersByTimeAsync(5_000);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds a fetch implementation that ignores approval cancellation", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
      vi.stubGlobal("fetch", fetchMock);

      const approval = approveDeviceCodeViaHttp("alice", "test-only-password", "ABC-123");
      const failure = expect(approval).rejects.toThrow(/approval cancelled/);
      await vi.advanceTimersByTimeAsync(15_000);
      await failure;
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
