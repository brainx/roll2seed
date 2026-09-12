import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const serverUrl = new URL("../scripts/serve.mjs", import.meta.url).href;
const children = [];
const fixtures = [];

function serverEnvironment(overrides = {}) {
  const env = { ...process.env };
  for (const key of ["HOST", "PORT", "ROLL2SEED_PORT", "ROLL2SEED_EXPOSE"]) {
    delete env[key];
  }
  return { ...env, ...overrides };
}

function inspectStartup(env) {
  // Capture the real startup decision without ever opening a network listener.
  return spawnSync(process.execPath, ["--input-type=module", "--eval", `
    import { Server } from "node:net";
    Server.prototype.listen = function (port, host, ready) {
      console.log("BIND " + JSON.stringify({ port, host }));
      ready();
      return this;
    };
    await import(${JSON.stringify(serverUrl)});
  `], { env: serverEnvironment(env), encoding: "utf8", timeout: 3_000 });
}

function binding(result) {
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  const line = result.stdout.split("\n").find((value) => value.startsWith("BIND "));
  expect(line).toBeDefined();
  return JSON.parse(line.slice(5));
}

async function startServer(host = "127.0.0.1") {
  const fixture = await mkdtemp(join(tmpdir(), "roll2seed-serve-"));
  fixtures.push(fixture);
  await mkdir(join(fixture, "dist"));
  await writeFile(join(fixture, "dist", "index.html"), "Synthetic server test page.");
  await writeFile(join(fixture, "dist", "read-error.txt"), "Synthetic read-failure fixture.");

  const child = spawn(process.execPath, ["--input-type=module", "--eval", `
    import fs from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    import { Server } from "node:net";
    import { Readable } from "node:stream";

    // Inject a portable asynchronous read failure after the real stat succeeds.
    const createFileStream = fs.createReadStream;
    fs.createReadStream = function (path, ...options) {
      if (String(path).endsWith("read-error.txt")) {
        return new Readable({ read() {
          this.destroy(Object.assign(new Error("Injected read failure"), { code: "EIO" }));
        } });
      }
      return createFileStream.call(this, path, ...options);
    };
    syncBuiltinESMExports();

    // Let the OS choose a free loopback port without changing startup validation.
    const listen = Server.prototype.listen;
    Server.prototype.listen = function (_port, host, ready) {
      return listen.call(this, 0, host, () => {
        process.send({ port: this.address().port });
        ready();
      });
    };
    await import(${JSON.stringify(serverUrl)});
  `], {
    cwd: fixture,
    env: serverEnvironment({ HOST: host }),
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exited = once(child, "exit");
  children.push({ child, exited });
  const [address] = await Promise.race([
    once(child, "message", { signal: AbortSignal.timeout(3_000) }),
    exited.then(([code]) => { throw new Error(`Server exited ${code}: ${stderr}`); }),
  ]);
  return { host, port: address.port };
}

function fetchLocal(address, path = "/", method = "GET") {
  return new Promise((resolve, reject) => {
    const req = request({ ...address, path, method, signal: AbortSignal.timeout(2_000) }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

afterEach(async () => {
  for (const { child, exited } of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      const timer = setTimeout(() => child.kill("SIGKILL"), 1_000);
      try {
        await exited;
      } finally {
        clearTimeout(timer);
      }
    }
  }
  await Promise.all(fixtures.splice(0).map((fixture) => rm(fixture, { recursive: true, force: true })));
});

describe("server binding", () => {
  it("defaults to loopback", () => {
    expect(binding(inspectStartup({}))).toEqual({ host: "127.0.0.1", port: 4173 });
  });

  it("keeps platform-assigned ports on loopback", () => {
    expect(binding(inspectStartup({ PORT: "3000" }))).toEqual({ host: "127.0.0.1", port: 3000 });
  });

  it.each(["127.0.0.1", "127.0.0.2", "localhost", "::1"])("allows local HOST=%s", (host) => {
    const result = inspectStartup({ HOST: host });
    expect(binding(result).host).toBe(host);
    expect(result.stderr).toBe("");
    if (host === "::1") {
      expect(result.stdout).toContain("http://[::1]:4173");
    }
  });

  it.each(["0.0.0.0", "::", "192.0.2.1", "127.0.0.1.example"].flatMap((host) =>
    [undefined, "0"].map((expose) => ({ host, expose })),
  ))("rejects HOST=$host with exposure=$expose before listening", ({ host, expose }) => {
    const env = { HOST: host, PORT: "3000" };
    if (expose !== undefined) env.ROLL2SEED_EXPOSE = expose;
    const result = inspectStartup(env);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Non-loopback HOST requires ROLL2SEED_EXPOSE=1");
    expect(result.stdout).not.toContain("BIND ");
  });

  it.each([
    { PORT: "3000", ROLL2SEED_EXPOSE: "1" },
    { HOST: "0.0.0.0", PORT: "3000", ROLL2SEED_EXPOSE: "1" },
  ])("retains deliberate exposure with $HOST", (env) => {
    const result = inspectStartup(env);
    expect(binding(result)).toEqual({ host: "0.0.0.0", port: 3000 });
    expect(result.stderr).toContain("trusted TLS-terminating proxy");
  });
});

describe("static HTTP responses", () => {
  it("serves GET and HEAD with the security headers", async () => {
    const address = await startServer();
    const get = await fetchLocal(address);
    expect(get.status).toBe(200);
    expect(get.body).toBe("Synthetic server test page.");
    expect(get.headers["cache-control"]).toBe("no-store");
    expect(get.headers["content-security-policy"]).toContain("connect-src 'none'");
    const head = await fetchLocal(address, "/", "HEAD");
    expect(head.status).toBe(200);
    expect(head.body).toBe("");
    expect(head.headers["content-length"]).toBe(get.headers["content-length"]);
  });

  it("preserves request-method and path restrictions", async () => {
    const address = await startServer();
    expect((await fetchLocal(address, "/", "POST")).status).toBe(405);
    expect((await fetchLocal(address, "/%ZZ")).status).toBe(400);
    expect((await fetchLocal(address, "/%2e%2e%2foutside.txt")).status).toBe(404);
    expect((await fetchLocal(address, "/missing.txt")).status).toBe(404);
  });

  it("serves the application over IPv6 loopback", async () => {
    const response = await fetchLocal(await startServer("::1"));
    expect(response.status).toBe(200);
    expect(response.body).toBe("Synthetic server test page.");
  });

  it("keeps serving after an asynchronous file-read failure", async () => {
    const address = await startServer();
    await expect(fetchLocal(address, "/read-error.txt")).rejects.toMatchObject({ code: "ECONNRESET" });
    const next = await fetchLocal(address);
    expect(next.status).toBe(200);
    expect(next.body).toBe("Synthetic server test page.");
  });
});
