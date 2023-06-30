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

describe("torus utils mainnet", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    // TorusUtils.enableLogging(true);
    torus = new TorusUtils({ network: "mainnet", clientId: "YOUR_CLIENT_ID" });
    TORUS_NODE_MANAGER = new NodeManager({
      network: TORUS_LEGACY_NETWORK.MAINNET,
    });
  });
  it("should fetch public address", async function () {
    const verifier = "google"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A");
  });

  it("should fetch user type and public address", async function () {
    const verifier = "google"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData, metadata } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.equal("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A");
    expect(metadata.typeOfUser).to.equal("v1");

    const v2Verifier = "tkey-google";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const { finalPubKeyData: finalPubKeyData1, metadata: metadata1 } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(finalPubKeyData1.evmAddress).to.equal("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526");
    expect(metadata1.typeOfUser).to.equal("v2");

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const { finalPubKeyData: finalPubKeyData2, metadata: metadata2 } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    expect(finalPubKeyData2.evmAddress).to.equal("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53");
    expect(metadata2.typeOfUser).to.equal("v1");
  });

  it("should be able to key assign", async function () {
    const verifier = "google"; // any verifier
    // TorusUtils.enableLogging(true);
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.not.equal("");
    expect(finalPubKeyData.evmAddress).to.not.equal(null);
    // TorusUtils.enableLogging(false);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oauthKeyData } = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(oauthKeyData.evmAddress).to.be.equal("0x90A926b698047b4A87265ba1E9D8b512E8489067");
    expect(finalKeyData.privKey).to.be.equal("0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44");
    expect(finalKeyData.evmAddress).to.be.equal("0xB4d9D085AA7f28dC60De88e343A32363079b4A59");
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

    expect(oauthKeyData.evmAddress).to.be.equal("0x621a4d458cFd345dAE831D9E756F10cC40A50381");

    expect(finalKeyData.evmAddress).to.be.equal("0xA5F7751515b8561Ec7aF1Fba589ac4eeAE008578");
  });
});
