import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils celeste", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      // signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      network: "celeste",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_LEGACY_NETWORK.CELESTE });
  });
  it("should fetch public address", async function () {
    const verifier = "tkey-google-celeste"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242");
  });

  it("should fetch user type and public address", async function () {
    const verifier = "tkey-google-celeste"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData, metadata } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242");
    expect(metadata.typeOfUser).to.equal("v1");

    const v2Verifier = "tkey-google-celeste";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const { finalPubKeyData: finalPubKeyData1, metadata: metadata1 } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(finalPubKeyData1.evmAddress).to.equal("0x69fB3A96016817F698a1279aE2d65F3916F3Db6F");
    expect(metadata1.typeOfUser).to.equal("v1");

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const { finalPubKeyData: finalPubKeyData2, metadata: metadata2 } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    expect(finalPubKeyData2.evmAddress).to.equal("0x24aCac36F8A4bD93052207dA410dA71AF92258b7");
    expect(metadata2.typeOfUser).to.equal("v1");
  });

  it("should be able to key assign", async function () {
    const verifier = "tkey-google-celeste"; // any verifier
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.not.equal("");
    expect(finalPubKeyData.evmAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData } = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(finalKeyData.privKey).to.be.equal("0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914");
  });

  it("should be able to aggregate login", async function () {
    const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oauthKeyData } = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: TORUS_TEST_EMAIL,
      },
      hashedIdToken.substring(2)
    );
    expect(oauthKeyData.evmAddress).to.be.equal("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564");
    expect(finalKeyData.evmAddress).to.be.equal("0x451AF9da3f9F85C033308DE0097A8BCbC96386db");
  });
});
