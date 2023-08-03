// Your bundler file
const esbuild = require("esbuild");
const { nodeExternalsPlugin } = require("esbuild-node-externals");

(async () => {
  const eslint = await import("esbuild-plugin-eslint");
  // const { polyfillNode } = await import("esbuild-plugin-polyfill-node");
  var start = process.hrtime.bigint();
  await esbuild.build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    platform: "browser",
    //   outdir: "dist",
    outfile: "dist/torus.esm.js",
    sourcemap: true,
    format: "esm",
    plugins: [nodeExternalsPlugin(), eslint.default()],
  });
  var end = process.hrtime.bigint();
  console.log(`Build time: ${Number(end - start) / 1e9}s`);

  var start = process.hrtime.bigint();
  await esbuild.build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    platform: "browser",
    //   outdir: "dist",
    outfile: "dist/torus.cjs.js",
    sourcemap: true,
    format: "cjs",
    plugins: [nodeExternalsPlugin()],
  });

  var end = process.hrtime.bigint();
  console.log(`Build time: ${Number(end - start) / 1e9}s`);

  var start = process.hrtime.bigint();
  await esbuild.build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    platform: "browser",
    //   outdir: "dist",
    outfile: "dist/torus.iife.js",
    sourcemap: true,
    format: "iife",
    minify: true,
    // plugins: [polyfillNode()],
    alias: {
      crypto: require.resolve("crypto-browserify"),
      stream: require.resolve("stream-browserify"),
      "bn.js": require.resolve("bn.js"),
    },
  });

  var end = process.hrtime.bigint();
  console.log(`Build time: ${Number(end - start) / 1e9}s`);
})();
