import NodeManager from '@toruslabs/fetch-node-details'
import { expect } from 'chai'
import faker from 'faker'

import TorusUtils from '../src/torus'

const TORUS_NODE_MANAGER = new NodeManager({ network: 'ropsten', proxyAddress: '0x4023d2a0D330bF11426B12C6144Cfb96B7fa6183' })
const TORUS_TEST_EMAIL = 'hello@tor.us'

describe('torus onekey', function () {
  let torusNodeEndpoints
  let torusNodePub
  before('one time execution before all tests', async function () {
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails()
    torusNodeEndpoints = nodeDetails.torusNodeEndpoints
    torusNodePub = nodeDetails.torusNodePub
  })

  it('should still fetch correct v1 public address', async function () {
    const torus = new TorusUtils({ enableOneKey: true, metadataHost: 'https://beta.metadata.tor.us' })
    const verifier = 'google-lrc' // any verifier
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: TORUS_TEST_EMAIL }, true)
    expect(publicAddress.typeOfUser).to.equal('v1')
    expect(publicAddress.address).to.equal('0xFf5aDad69F4e97AF4D4567e7C333C12df6836a70')
  })

  it('should be able to key assign', async function () {
    const verifier = 'google-lrc' // any verifier
    const torus = new TorusUtils({ enableOneKey: true, metadataHost: 'https://beta.metadata.tor.us' })
    const email = faker.internet.email()
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: email }, true)
    expect(publicAddress.typeOfUser).to.equal('v2')
  })
})
