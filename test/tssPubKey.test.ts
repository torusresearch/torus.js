import { faker } from "@faker-js/faker";
import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { expect } from "chai";

import { GetOrSetTssDKGPubKey } from "./utils/tssPubKeyUtils";

describe("setTssKey", function () {
  const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
  const TORUS_TEST_VERIFIER = "torus-test-health";

  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach("one time execution before all tests", async function () {
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET });
  });

  it("should assign key to tss verifier id", async function () {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };

    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);

    const result = await GetOrSetTssDKGPubKey({
      endpoints: torusNodeEndpoints,
      verifier: TORUS_TEST_VERIFIER,
      verifierId: email,
      tssVerifierId,
    });
    expect(result.key.pubKeyX).to.not.equal(null);
  });

  it("should fetch pub address of tss verifier id", async function () {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };

    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);

    const result = await GetOrSetTssDKGPubKey({
      endpoints: torusNodeEndpoints,
      verifier: TORUS_TEST_VERIFIER,
      verifierId: email,
      tssVerifierId,
    });
    delete result.key.createdAt;
    expect(result).eql({
      key: {
        pubKeyX: "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c",
        pubKeyY: "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e",
        address: "0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30",
      },
      isNewKey: false,
      nodeIndexes: result.nodeIndexes,
    });
  });

  it("should fail if more than one endpoints are invalid", async function () {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };

    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    torusNodeEndpoints[2] = "https://invalid.torus.com";
    torusNodeEndpoints[3] = "https://invalid.torus.com";
    torusNodeEndpoints[4] = "https://invalid.torus.com";
    try {
      await GetOrSetTssDKGPubKey({
        endpoints: torusNodeEndpoints,
        verifier: TORUS_TEST_VERIFIER,
        verifierId: email,
        tssVerifierId,
      });
      // If the function doesn't throw an error, fail the test
      expect.fail("Expected an error to be thrown");
    } catch (error) {
      // Test passes if an error is thrown
      expect(error).to.be.instanceOf(Error);
    }
  });
});
