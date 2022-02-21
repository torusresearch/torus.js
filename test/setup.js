/* eslint-disable @typescript-eslint/no-var-requires */

require("dotenv").config();

global.fetch = require("node-fetch");
global.atob = require("atob");

const path = require("path");
require("ts-node").register({ project: path.resolve("tsconfig.json"), transpileOnly: true });

const register = require("@babel/register").default;

register({
  extensions: [".ts", ".js"],
  rootMode: "upward",
});
