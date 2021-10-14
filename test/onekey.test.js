import NodeManager from '@toruslabs/fetch-node-details'
import { expect } from 'chai'
import faker from 'faker'
import { keccak256 } from 'web3-utils'

import TorusUtils from '../src/torus'
import { generateIdToken } from './helpers'

const TORUS_NODE_MANAGER = new NodeManager({ network: 'ropsten', proxyAddress: '0x4023d2a0D330bF11426B12C6144Cfb96B7fa6183' })
const TORUS_TEST_EMAIL = 'hello@tor.us'
const TORUS_TEST_VERIFIER = 'torus-test-health'
const TORUS_TEST_AGGREGATE_VERIFIER = 'torus-test-health-aggregate'

describe('torus onekey', function () {
  let torusNodeEndpoints
  let torusNodePub
  let torusIndexes

  before('one time execution before all tests', async function () {
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails()
    torusNodeEndpoints = nodeDetails.torusNodeEndpoints
    torusNodePub = nodeDetails.torusNodePub
    torusIndexes = nodeDetails.torusIndexes
  })

  it('should still fetch v1 public address correctly', async function () {
    const torus = new TorusUtils({ enableOneKey: true })
    const verifier = 'google-lrc' // any verifier
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: TORUS_TEST_EMAIL }, true)
    expect(publicAddress.typeOfUser).to.equal('v1')
    expect(publicAddress.address).to.equal('0xFf5aDad69F4e97AF4D4567e7C333C12df6836a70')
  })

  it('should still login v1 account correctly', async function () {
    const torus = new TorusUtils({ enableOneKey: true })
    const token = generateIdToken(TORUS_TEST_EMAIL, 'ES256')
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    )
    expect(retrieveSharesResponse.privKey).to.be.equal('068ee4f97468ef1ae95d18554458d372e31968190ae38e377be59d8b3c9f7a25')
  })

  it('should still aggregate account v1 user correctly', async function () {
    const torus = new TorusUtils({ enableOneKey: true })
    const idToken = generateIdToken(TORUS_TEST_EMAIL, 'ES256')
    const hashedIdToken = keccak256(idToken)
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: TORUS_TEST_EMAIL,
      },
      hashedIdToken.substring(2)
    )
    expect(retrieveSharesResponse.ethAddress).to.be.equal('0x5a165d2Ed4976BD104caDE1b2948a93B72FA91D2')
  })

  it('should be able to key assign', async function () {
    const verifier = 'google-lrc' // any verifier
    const torus = new TorusUtils({ enableOneKey: true })
    const email = faker.internet.email()
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: email }, true)
    expect(publicAddress.typeOfUser).to.equal('v2')
  })
})
