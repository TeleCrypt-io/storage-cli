export interface TestUser {
  userId: string;
  accessToken: string;
  deviceId: string;
  password: string;
}

function randomSuffix(): string {
  return Math.random().toString(36).slice(2, 8);
}

export async function registerTestUser(prefix: string): Promise<TestUser> {
  const suffix = randomSuffix();
  const username = `${prefix}_${suffix}`;
  const password = `pwd_${suffix}`;

  const res = await fetch("http://localhost:8008/_matrix/client/v3/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      password,
      auth: { type: "m.login.dummy" },
      inhibit_login: false,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`registration failed (${res.status}): ${body}`);
  }

  const data = (await res.json()) as {
    user_id: string;
    access_token: string;
    device_id: string;
  };

  return {
    userId: data.user_id,
    accessToken: data.access_token,
    deviceId: data.device_id,
    password,
  };
}

/**
 * Logs in as an existing user to obtain a SECOND, independent device: a new
 * device_id + access_token, with an empty crypto store of its own. This is the
 * "new laptop" scenario for key-recovery testing — distinct from `user`'s
 * original session, which keeps its own device_id/accessToken untouched.
 */
export async function loginNewDevice(user: TestUser): Promise<TestUser> {
  const res = await fetch("http://localhost:8008/_matrix/client/v3/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      type: "m.login.password",
      identifier: { type: "m.id.user", user: user.userId },
      password: user.password,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`login (new device) failed (${res.status}): ${body}`);
  }

  const data = (await res.json()) as {
    user_id: string;
    access_token: string;
    device_id: string;
  };

  if (data.device_id === user.deviceId) {
    throw new Error(
      `loginNewDevice: expected a NEW device_id, got the same one as the original session (${data.device_id})`,
    );
  }

  return {
    userId: data.user_id,
    accessToken: data.access_token,
    deviceId: data.device_id,
    password: user.password,
  };
}
