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

- Typescript compatible
- All API's return `Promises`

## Getting Started

Add [`@toruslabs/torus.js`](https://www.npmjs.com/package/@toruslabs/torus.js) to your project:

Needs to be used in conjuction with [`@toruslabs/fetch-node-details`](https://www.npmjs.com/package/@toruslabs/fetch-node-details)

```js
import FetchNodeDetails from '@toruslabs/fetch-node-details'
import TorusJs from '@toruslabs/torus.js'

const fetchNodeDetails = new FetchNodeDetails()
const TorusJs = new TorusJs()
const verifier = 'google' // any verifier
const verifierId = 'hello@tor.us' // any verifier id
const { torusNodeEndpoints, torusNodePub } = await fetchNodeDetails.getNodeDetails()
const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId })
```

## Requirements

- Node 10+
