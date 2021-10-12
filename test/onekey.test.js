import { expect } from 'chai'
import faker from 'faker'

import TorusUtils from '../src/torus'

describe('torus onekey', function () {
  let torusNodeEndpoints
  let torusNodePub
  const TORUS_TEST_EMAIL = 'hello@tor.us'

  it('should still fetch correct v1 public address', async function () {
    const torus = new TorusUtils({ enableOneKey: true, metadataHost: 'https://beta.metadata.tor.us' })
    const verifier = 'google-lrc' // any verifier
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: TORUS_TEST_EMAIL })
    expect(publicAddress).to.equal('0xFf5aDad69F4e97AF4D4567e7C333C12df6836a70')
  })

  it('should be able to key assign', async function () {
    const verifier = 'google-lrc' // any verifier
    const torus = new TorusUtils({ enableOneKey: true, metadataHost: 'https://beta.metadata.tor.us' })
    const email = faker.internet.email()
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: email })
    expect(publicAddress.typeOfUser).to.equal('v2')
  })
})
