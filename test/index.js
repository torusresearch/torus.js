import NodeManager from '@toruslabs/fetch-node-details'

import TorusUtils from '../src/torus'

const fetchNodeDetails = new NodeManager()
const torus = new TorusUtils()
const verifier = 'google' // any verifier
const verifierId = 'hello@tor.us' // any verifier id
fetchNodeDetails
  .getNodeDetails({ verifier, verifierId })
  .then(({ torusNodeEndpoints, torusNodePub }) => torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId }))
  .then((publicAddress) => console.log(publicAddress))
  .catch(console.error)
