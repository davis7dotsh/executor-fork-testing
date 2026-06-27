#!/usr/bin/env bun

import { Schema } from "effect";
import { resolve } from "node:path";

const WardenConfig = Schema.Struct({
  defaults: Schema.Struct({
    ignorePaths: Schema.Array(Schema.String),
  }),
  skills: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      paths: Schema.Array(Schema.String),
    }),
  ),
});

const decodeWardenConfig = Schema.decodeUnknownSync(WardenConfig);
const repoRoot = resolve(import.meta.dirname, "..");
const configPath = resolve(repoRoot, process.argv[2] ?? "warden.toml");
const config = decodeWardenConfig(Bun.TOML.parse(await Bun.file(configPath).text()));
const ignored = config.defaults.ignorePaths.map((pattern) => new Bun.Glob(pattern));
const zeroMatchTargets: string[] = [];
let targetCount = 0;

for (const skill of config.skills) {
  for (const pattern of skill.paths) {
    targetCount += 1;
    const matches = [
      ...new Bun.Glob(pattern).scanSync({
        cwd: repoRoot,
        dot: true,
        onlyFiles: true,
      }),
    ].filter((path) => !ignored.some((glob) => glob.match(path)));

    if (matches.length === 0) {
      zeroMatchTargets.push(`${skill.name}: ${pattern}`);
    }
  }
}

if (zeroMatchTargets.length > 0) {
  console.error("Warden targets resolving to zero non-ignored files:");
  for (const target of zeroMatchTargets) console.error(`- ${target}`);
  process.exit(1);
}

console.log(`Warden target guard checked ${targetCount} configured targets.`);
