import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { LocalAdminClient } from "./local-admin";

const digest = (value: string) => createHash("sha256").update(value).digest("hex");

it.effect("reuses one administrator session across API and browser identities", () =>
  Effect.acquireUseRelease(
    Effect.promise(async () => {
      const session = randomBytes(32).toString("hex");
      const csrf = randomBytes(32).toString("hex");
      let observedCookie: string | undefined;
      const server = createServer((request, response) => {
        request.resume();
        if (request.method === "POST" && request.url === "/api/v1/session") {
          response.statusCode = 200;
          response.setHeader("content-type", "application/json");
          response.setHeader("set-cookie", [
            `executor_session=${session}; Path=/; HttpOnly; SameSite=Lax`,
            `executor_csrf=${csrf}; Path=/; SameSite=Lax`,
          ]);
          response.end("{}");
          return;
        }
        if (request.method === "GET" && request.url === "/api/v1/sources") {
          observedCookie = request.headers.cookie;
          response.statusCode = 200;
          response.setHeader("content-type", "application/json");
          response.end('{"sources":[]}');
          return;
        }
        response.statusCode = 404;
        response.end();
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("administrator test server has no TCP address");
      }
      return {
        origin: `http://127.0.0.1:${address.port}`,
        server,
        observedCookie: () => observedCookie,
      };
    }),
    ({ origin, observedCookie }) =>
      Effect.gen(function* () {
        const client = yield* Effect.promise(() =>
          LocalAdminClient.signIn(origin, "admin", "test-password"),
        );
        const identity = client.asIdentity("admin");
        yield* Effect.promise(() => client.listSources());

        expect(identity.label).toBe("admin");
        expect(identity.credentials).toBeUndefined();
        expect(identity.cookies?.map((cookie) => cookie.name).sort()).toEqual([
          "executor_csrf",
          "executor_session",
        ]);
        expect(
          identity.cookies?.map((cookie) => ({
            name: cookie.name,
            valueLength: cookie.value.length,
          })),
        ).toEqual([
          { name: "executor_session", valueLength: 64 },
          { name: "executor_csrf", valueLength: 64 },
        ]);

        const apiCookie = observedCookie();
        const identityCookie = identity.headers?.cookie;
        const browserCookie = identity.cookies
          ?.map((cookie) => `${cookie.name}=${cookie.value}`)
          .join("; ");
        if (!apiCookie || !identityCookie || !browserCookie) {
          return yield* Effect.die("administrator identity omitted its session cookies");
        }
        expect(digest(identityCookie), "the browser header keeps API session A").toBe(
          digest(apiCookie),
        );
        expect(digest(browserCookie), "Playwright receives the same session A cookie pairs").toBe(
          digest(apiCookie),
        );
      }),
    ({ server }) =>
      Effect.callback<void, Error>((resume) => {
        server.close((error) => resume(error ? Effect.fail(error) : Effect.succeed(undefined)));
      }),
  ),
);

it.effect("refreshes a tool revision once after an optimistic update conflict", () =>
  Effect.acquireUseRelease(
    Effect.promise(async () => {
      const session = randomBytes(32).toString("hex");
      const csrf = randomBytes(32).toString("hex");
      const updateBodies: string[] = [];
      const server = createServer((request, response) => {
        if (request.method === "POST" && request.url === "/api/v1/session") {
          request.resume();
          response.statusCode = 200;
          response.setHeader("content-type", "application/json");
          response.setHeader("set-cookie", [
            `executor_session=${session}; Path=/; HttpOnly; SameSite=Lax`,
            `executor_csrf=${csrf}; Path=/; SameSite=Lax`,
          ]);
          response.end("{}");
          return;
        }
        if (request.method === "GET" && request.url === "/api/v1/tools/tool-1") {
          request.resume();
          response.statusCode = 200;
          response.setHeader("content-type", "application/json");
          response.end(
            JSON.stringify({
              id: "tool-1",
              sourceId: "source-1",
              stableKey: "hello",
              displayName: "Hello",
              callablePath: "tools.source_1.hello",
              sandboxPath: "executor.tools.source_1.hello",
              revision: 2,
              effectiveMode: { mode: "disabled" },
            }),
          );
          return;
        }
        if (request.method === "PATCH" && request.url === "/api/v1/tools/tool-1/mode") {
          request.setEncoding("utf8");
          let body = "";
          request.on("data", (chunk) => {
            body += chunk;
          });
          request.on("end", () => {
            updateBodies.push(body);
            response.setHeader("content-type", "application/json");
            if (updateBodies.length === 1) {
              response.statusCode = 409;
              response.end('{"error":{"code":"revision_conflict","message":"Refresh and retry."}}');
              return;
            }
            response.statusCode = 200;
            response.end(
              JSON.stringify({
                id: "tool-1",
                sourceId: "source-1",
                stableKey: "hello",
                displayName: "Hello",
                callablePath: "tools.source_1.hello",
                sandboxPath: "executor.tools.source_1.hello",
                revision: 3,
                effectiveMode: { mode: "enabled" },
              }),
            );
          });
          return;
        }
        request.resume();
        response.statusCode = 404;
        response.end();
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("administrator test server has no TCP address");
      }
      return {
        origin: `http://127.0.0.1:${address.port}`,
        server,
        updateBodies,
      };
    }),
    ({ origin, updateBodies }) =>
      Effect.gen(function* () {
        const client = yield* Effect.promise(() =>
          LocalAdminClient.signIn(origin, "admin", "test-password"),
        );
        const updated = yield* Effect.promise(() =>
          client.setToolMode(
            {
              id: "tool-1",
              sourceId: "source-1",
              stableKey: "hello",
              displayName: "Hello",
              callablePath: "tools.source_1.hello",
              sandboxPath: "executor.tools.source_1.hello",
              revision: 1,
              effectiveMode: { mode: "disabled" },
            },
            "enabled",
          ),
        );

        expect(updated.revision).toBe(3);
        expect(updateBodies.map((body) => JSON.parse(body))).toEqual([
          { mode: "enabled", expectedRevision: 1 },
          { mode: "enabled", expectedRevision: 2 },
        ]);
      }),
    ({ server }) =>
      Effect.callback<void, Error>((resume) => {
        server.close((error) => resume(error ? Effect.fail(error) : Effect.succeed(undefined)));
      }),
  ),
);
