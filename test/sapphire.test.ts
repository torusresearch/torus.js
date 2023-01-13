// import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";
import { keccak256 } from "web3-utils";

import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "devcluster1@temp.us";
const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const TORUS_TEST_VERIFIER_ID_HASH = "torus-test-verifierid-hash";

describe.only("torus utils sapphire", function () {
  let torus: TorusUtils;

  const torusNodeEndpoints = [
    "https://sapphire-dev-2-1.authnetwork.dev/sss/jrpc",
    "https://sapphire-dev-2-2.authnetwork.dev/sss/jrpc",
    "https://sapphire-dev-2-3.authnetwork.dev/sss/jrpc",
    "https://sapphire-dev-2-4.authnetwork.dev/sss/jrpc",
    "https://sapphire-dev-2-5.authnetwork.dev/sss/jrpc",
  ];

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      metadataHost: "https://sapphire-dev-2-1.authnetwork.dev/metadata",
      network: "cyan",
      enableOneKey: true,
    });
  });
  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0x1bF0D9D1E87Df1b65D8C8bD23699811DbBD5D2FE");
  });

  it("should keep public address same", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: faker.internet.email() };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    const publicAddress2 = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal(publicAddress2);
  });
  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { address } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, true);
    expect(address).to.equal("0x1bF0D9D1E87Df1b65D8C8bD23699811DbBD5D2FE");
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal("");
    expect(publicAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal("19ac60b48fded42055087d2d177c5904f117385a890b2341cf5b79f70854e313");
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER_ID_HASH, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0xcadE762cb597790f199DF0df25469C112E51F1C8");
  });

  // to do: update pub keys
  it.skip("should lookup return hash when verifierID hash enabled", async function () {
    for (const endpoint of torusNodeEndpoints) {
      const pubKeyX = "90a86084f0e07973382ed5a20bf1b6b6634f75c46e5351891a3d3ff4155666b3";
      const pubKeyY = "644724e80f17c57f87d9c6e43db2bfc054c347691bdd79c62c30bebabd185cf2";
      const response = await lookupVerifier(endpoint, pubKeyX, pubKeyY);
      // eslint-disable-next-line no-console
      console.log("response", response);
      const verifierID = response.result.verifiers[TORUS_TEST_VERIFIER_ID_HASH][0];
      expect(verifierID).to.equal("086c23ab78578f2fce9a1da11c0071ec7c2225adb1bf499ffaee98675bee29b7");
    }
  });

  it("should fetch user type and public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER_ID_HASH, verifierId: TORUS_TEST_EMAIL };
    const { address } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, false);
    expect(address).to.equal("0xcadE762cb597790f199DF0df25469C112E51F1C8");
  });
  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      TORUS_TEST_VERIFIER_ID_HASH,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );

    expect(retrieveSharesResponse.privKey).to.be.equal("f2f4ff8d95e6d5bd15288bf6ac2a0982bde021a969237ff716b2ae922ee9e5a0");

    const responseToken = retrieveSharesResponse.sessionTokensData[0].token;
    const tokenObj = JSON.parse(Buffer.from(responseToken, "base64").toString());
    expect(tokenObj.verifier_id).to.equal(TORUS_TEST_EMAIL);
  });

  it.skip("should be able to aggregate login", async function () {
    const email = faker.internet.email();
    const idToken = generateIdToken(email, "ES256");
    const hashedIdToken = keccak256(idToken);
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: email, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: email,
      },
      hashedIdToken.substring(2)
    );
    expect(retrieveSharesResponse.ethAddress).to.not.equal(null);
    expect(retrieveSharesResponse.ethAddress).to.not.equal("");
  });
});
