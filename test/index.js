const FetchNodeDetails = require('@toruslabs/fetch-node-details/dist/fetchNodeDetails-node')
const TorusUtils = require('../dist/torusUtils-node')

const fetchNodeDetails = new FetchNodeDetails()
const torus = new TorusUtils()
const verifier = 'google' // any verifier
const verifierId = 'hello@tor.us' // any verifier id
fetchNodeDetails
  .getNodeDetails()
  .then(({ torusNodeEndpoints, torusNodePub }) => torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId }))
  .then((publicAddress) => console.log(publicAddress))
  .catch(console.error)
