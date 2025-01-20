# Torus.js

[![npm version](https://badge.fury.io/js/%40toruslabs%2Ftorus.js.svg)](https://badge.fury.io/js/%40toruslabs%2Ftorus.js)
![npm](https://img.shields.io/npm/dw/@toruslabs/torus.js)

## Introduction

A JS utility library (w/ typescript bindings!) to make calls to the Torus network

The Torus network assumes that n/4 of nodes may be malicious, and n/2 + 1 of the nodes are required
for key reconstruction. Given these threshold assumptions, all API calls to the Torus nodes need to be checked
for consistency while still allowing for early exits in optimistic scenarios where the first n/2 + 1 responses
are from honest nodes.

Also, in order to prevent front-running by nodes, a commit-reveal process is also necessary for share retrieval.

This library handles these checks and allows you to query the Torus network easily through these APIs:

- retrieveShares
- getPublicAddress

## Features

- Typescript compatible. Includes Type definitions
- All API's return `Promises`

## Installation

### Bundling

This module is distributed in 3 formats

- `lib.esm` build `dist/lib.esm/index.js` in es6 format
- `lib.cjs` build `dist/lib.cjs/index.js` in es5 format
- `umd` build `dist/torusUtils.umd.min.js` in es5 format without polyfilling corejs minified

By default, the appropriate format is used for your specified usecase
You can use a different format (if you know what you're doing eg. node) by referencing the correct file

The cjs build is not polyfilled with core-js.
It is upto the user to polyfill based on the browserlist they target

### Directly in Browser

CDN's serve the non-core-js polyfilled version by default. You can use a different

jsdeliver

```js
<script src="https://cdn.jsdelivr.net/npm/@toruslabs/torus.js"></script>
```

unpkg

```js
<script src="https://unpkg.com/@toruslabs/torus.js"></script>
```

### Tips for NUXT

This is a plugin that works [only on the client side](https://nuxtjs.org/guide/plugins/#client-side-only). So please register it as a ssr-free plugin.

## Usage

Add [`@toruslabs/torus.js`](https://www.npmjs.com/package/@toruslabs/torus.js) to your project:

Needs to be used in conjuction with [`@toruslabs/fetch-node-details`](https://www.npmjs.com/package/@toruslabs/fetch-node-details)

```ts
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import TorusUtils from "@toruslabs/torus.js";

const fetchNodeDetails = new NodeDetailManager();
const torus = new TorusUtils({ network: "mainnet", clientId: "YOUR_CLIENT_ID" }); // get your Client ID from Web3Auth Dashboard
const verifier = "google";
const verifierId = "hello@tor.us";
const { torusNodeEndpoints, torusNodePub, torusIndexes } = await fetchNodeDetails.getNodeDetails();
const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId });

const idToken = "YOUR_ID_TOKEN";
const keyData = await torus.retrieveShares(torusNodeEndpoints, torusIndexes, verifier, { verifier_id: verifierId }, idToken);
```

```js
const { NodeDetailManager: FetchNodeDetails } = require("@toruslabs/fetch-node-details");
const { Torus: TorusUtils } = require("@toruslabs/torus.js");

const fetchNodeDetails = new FetchNodeDetails();
const torus = new TorusUtils({ network: "mainnet", clientId: "YOUR_CLIENT_ID" }); // get your Client ID from Web3Auth Dashboard
const verifier = "google"; // any verifier
const verifierId = "hello@tor.us"; // any verifier id
fetchNodeDetails
  .getNodeDetails()
  .then(({ torusNodeEndpoints, torusNodePub }) => torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId }))
  .then((publicAddress) => console.log(publicAddress));

const idToken = "YOUR_ID_TOKEN";
fetchNodeDetails
  .getNodeDetails()
  .then(({ torusNodeEndpoints, torusIndexes }) =>
    torus.retrieveShares(torusNodeEndpoints, torusIndexes, verifier, { verifier_id: verifierId }, idToken)
  )
  .then((keyData) => console.log(keyData));
```

## Requirements

- This package requires a peer dependency of `@babel/runtime`
- Node 20+
