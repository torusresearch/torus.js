import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";

import { keccak256, TorusPublicKey } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "archit1@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe.only("torus utils migrated testnet on sapphire", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({ network: "testnet", clientId: "YOUR_CLIENT_ID" });
    TORUS_NODE_MANAGER = new NodeManager({
      network: TORUS_LEGACY_NETWORK.TESTNET,
    });
  });
  it("should fetch public address", async function () {
    const verifier = "google-lrc"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0x9bcBAde70546c0796c00323CD1b97fa0a425A506");
  });

  it("should fetch user type and public address", async function () {
    const verifier = "google-lrc"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData, metadata } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0x9bcBAde70546c0796c00323CD1b97fa0a425A506");
    expect(metadata.typeOfUser).to.equal("v1");

    const v2Verifier = "tkey-google-lrc";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const { finalPubKeyData: finalPubKeyData1, metadata: metadata1 } = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    })) as TorusPublicKey;
    expect(finalPubKeyData1.evmAddress).to.equal("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D");
    expect(metadata1.typeOfUser).to.equal("v2");

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const { finalPubKeyData: finalPubKeyData2, metadata: metadata2 } = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    })) as TorusPublicKey;
    expect(finalPubKeyData2.evmAddress).to.equal("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456");
    expect(metadata2.typeOfUser).to.equal("v2");
  });

  it("should be able to key assign", async function () {
    const verifier = "google-lrc"; // any verifier
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
    expect(finalKeyData.privKey).to.be.equal("9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3");
  });

  it("should be able to aggregate login", async function () {
    const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oAuthKeyData, metadata } = await torus.retrieveShares(
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

    expect(metadata.typeOfUser).to.be.equal("v1");
    expect(oAuthKeyData.evmAddress).to.be.equal("0x938a40E155d118BD31E439A9d92D67bd55317965");

    expect(finalKeyData.evmAddress).to.be.equal("0x938a40E155d118BD31E439A9d92D67bd55317965");
  });
});
