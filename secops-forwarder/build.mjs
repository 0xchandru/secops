import * as esbuild from "esbuild";
import { writeFileSync } from "fs";

await esbuild.build({
  entryPoints: ["src/cli.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: "dist/cli.js",
  external: [],
  banner: {
    js: "#!/usr/bin/env node",
  },
  sourcemap: true,
  minify: false,
});

writeFileSync("dist/cli.js", "", { flag: "a" });
try {
  const { chmodSync } = await import("fs");
  chmodSync("dist/cli.js", 0o755);
} catch {}

console.log("⚡ secops-forwarder built to dist/cli.js");
