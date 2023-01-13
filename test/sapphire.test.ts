// import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";
import { keccak256 } from "web3-utils";

import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "sapphiretest340@tor.us";
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
    expect(publicAddress).to.equal("0xdc9180a9aeeBd72C36030451e230b71e22Bd34Ca");
  });

  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { address } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, true);
    expect(address).to.equal("0xdc9180a9aeeBd72C36030451e230b71e22Bd34Ca");
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
    expect(retrieveSharesResponse.privKey).to.be.equal("4d21ebad6a22ac9d9118a58f487490bd2d91a64d2b715bdd5922e37653a71438");
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER_ID_HASH, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0xB26Bd08D8630c1DeD5357bd305224B0859eAE62F");
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
    expect(address).to.equal("0xB26Bd08D8630c1DeD5357bd305224B0859eAE62F");
  });
  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      TORUS_TEST_VERIFIER_ID_HASH,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(retrieveSharesResponse.privKey).to.be.equal("697d21c09526ac4b0e31b0c42564338a8f39e4c1cc7af67b80a282d96c2d5127");

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
