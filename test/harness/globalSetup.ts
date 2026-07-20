export async function setup(): Promise<void> {
  const res = await fetch("http://localhost:8008/_matrix/client/versions").catch(
    () => null,
  );

  if (!res || !res.ok) {
    throw new Error(
      [
        "Synapse not reachable at http://localhost:8008",
        "",
        "  Run 'npm run synapse:up' first.",
        "",
      ].join("\n"),
    );
  }

  const body = (await res.json()) as { versions?: string[] };
  if (!body.versions) {
    throw new Error(
      "Synapse responded but response has no versions field — is this a Matrix server?",
    );
  }
}
