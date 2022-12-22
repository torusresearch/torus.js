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
    "https://mpcmain-cluster-1.k8.authnetwork.dev/sss/jrpc",
    "https://mpcmain-cluster-2.k8.authnetwork.dev/sss/jrpc",
    "https://mpcmain-cluster-3.k8.authnetwork.dev/sss/jrpc",
    "https://mpcmain-cluster-4.k8.authnetwork.dev/sss/jrpc",
    "https://mpcmain-cluster-5.k8.authnetwork.dev/sss/jrpc",
  ];

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      metadataHost: "https://mpcmain-cluster-1.k8.authnetwork.dev/metadata",
      network: "cyan",
      enableOneKey: true,
    });
    TorusUtils.enableLogging(true);
  });
  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0x3aFfea6b6F6Dc47d088F405e97808bfd5b6389FA");
  });

  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { address, typeOfUser } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, true);
    expect(address).to.equal("0x3aFfea6b6F6Dc47d088F405e97808bfd5b6389FA");
    expect(typeOfUser).to.equal("v2");
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
    expect(retrieveSharesResponse.privKey).to.be.equal("ba66d7d6884bf14660236f4be34af4465c8f370c63e10df45d167ee70cd35aac");
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER_ID_HASH, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0x1549D563482Cd8300A6c8536EaBFDfe974f75FA1");
  });

  it("should lookup return hash when verifierID hash enabled", async function () {
    for (const endpoint of torusNodeEndpoints) {
      const pubKeyX = "90a86084f0e07973382ed5a20bf1b6b6634f75c46e5351891a3d3ff4155666b3";
      const pubKeyY = "644724e80f17c57f87d9c6e43db2bfc054c347691bdd79c62c30bebabd185cf2";
      const response = await lookupVerifier(endpoint, pubKeyX, pubKeyY);
      const verifierID = response.result.verifiers[TORUS_TEST_VERIFIER_ID_HASH][0];
      expect(verifierID).to.equal("086c23ab78578f2fce9a1da11c0071ec7c2225adb1bf499ffaee98675bee29b7");
    }
  });

  it("should fetch user type and public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER_ID_HASH, verifierId: TORUS_TEST_EMAIL };
    const { address, typeOfUser } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, false);
    expect(address).to.equal("0x1549D563482Cd8300A6c8536EaBFDfe974f75FA1");
    expect(typeOfUser).to.equal("v2");
  });
  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      TORUS_TEST_VERIFIER_ID_HASH,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(retrieveSharesResponse.privKey).to.be.equal("ffdf49a798be923505333aa3c6fdb9d292f281a676d5d7b16ebe6cc34617b0bf");

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
