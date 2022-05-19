const path = require("path");
const webpack = require("webpack");
const nodeExternals = require("webpack-node-externals");

const pkg = require("./package.json");

const pkgName = "torusUtils";

exports.baseConfig = {
  resolve: {
    alias: {
      "bn.js": path.resolve(__dirname, "node_modules/bn.js"),
      lodash: path.resolve(__dirname, "node_modules/lodash"),
      "js-sha3": path.resolve(__dirname, "node_modules/js-sha3"),
    },
  },
};

exports.nodeConfig = {
  optimization: {
    minimize: false,
  },
  output: {
    filename: `${pkgName}-node.js`,
    library: {
      type: "commonjs2",
    },
  },
  externals: [
    nodeExternals({
      allowlist: "@toruslabs/http-helpers",
    }),
    "node-fetch",
    ...Object.keys(pkg.dependencies).filter((x) => !["@toruslabs/http-helpers"].includes(x)),
    /^(@babel\/runtime)/i,
  ],
  target: "node",
  plugins: [
    new webpack.ProvidePlugin({
      fetch: ["node-fetch", "default"],
    }),
  ],
};
