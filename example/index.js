const Torus = require('@toruslabs/torus.js')
const FetchNodeDetails = require('@toruslabs/fetch-node-details')
global.fetch = require('node-fetch')

const torus = new Torus()
const fetchNodeDetails = new FetchNodeDetails({
  proxyAddress: '0x4023d2a0D330bF11426B12C6144Cfb96B7fa6183',
  network: 'ropsten',
})
console.log(fetchNodeDetails)
fetchNodeDetails
  .getNodeDetails()
  .then((nodeInfo) => {
    return torus.getPublicAddress(nodeInfo.torusNodeEndpoints, nodeInfo.torusNodePub, { verifier: 'google', verifierId: 'test4@tor.us' })
  })
  .then((response) => {
    console.log('private key assigned to user at address ', response)
    return response
  })
  .catch(console.log)
