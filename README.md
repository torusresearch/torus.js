# torus.js
A JS utility library (w/ typescript bindings!) to make calls to the Torus network

The Torus network assumes that n/4 of nodes may be malicious, and n/2 + 1 of the nodes are required
for key reconstruction. Given these threshold assumptions, all API calls to the Torus nodes need to be checked
for consistency while still allowing for early exits in optimistic scenarios where the first n/2 + 1 responses
are from honest nodes.

Also, in order to prevent front-running by nodes, a commit-reveal process is also necessary for share retrieval.

This library handles these checks and allows you to query the Torus network easily through these APIs:
- retrieveShares
- getPublicAddress


