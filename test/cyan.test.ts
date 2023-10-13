import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils cyan", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      // signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      network: "cyan",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_LEGACY_NETWORK.CYAN });
  });
  it("should fetch public address", async function () {
    const verifier = "tkey-google-cyan"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.equal("0xA3767911A84bE6907f26C572bc89426dDdDB2825");
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      finalKeyData: {
        evmAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });
  });

  it("should fetch user type and public address", async function () {
    const verifier = "tkey-google-cyan"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result1.finalKeyData.evmAddress).to.equal("0xA3767911A84bE6907f26C572bc89426dDdDB2825");
    expect(result1.metadata.typeOfUser).to.equal("v1");
    expect(result1).eql({
      oAuthKeyData: {
        evmAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      finalKeyData: {
        evmAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google-cyan";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result2.finalKeyData.evmAddress).to.equal("0x8EA83Ace86EB414747F2b23f03C38A34E0217814");
    expect(result2.metadata.typeOfUser).to.equal("v2");
    expect(result2).eql({
      oAuthKeyData: {
        evmAddress: "0x29446f428293a4E6470AEaEDa6EAfA0F842EF54e",
        X: "8b6f2048aba8c7833e3b02c5b6522bb18c484ad0025156e428f17fb8d8c34021",
        Y: "cd9ba153ff89d665f655d1be4c6912f3ff93996e6fe580d89e78bf1476fef2aa",
      },
      finalKeyData: {
        evmAddress: "0x8EA83Ace86EB414747F2b23f03C38A34E0217814",
        X: "cbe7b0f0332e5583c410fcacb6d4ff685bec053cfd943ac75f5e4aa3278a6fbb",
        Y: "b525c463f438c7a3c4b018c8c5d16c9ef33b9ac6f319140a22b48b17bdf532dd",
      },
      metadata: {
        pubNonce: {
          X: "da0039dd481e140090bed9e777ce16c0c4a16f30f47e8b08b73ac77737dd2d4",
          Y: "7fecffd2910fa47dbdbc989f5c119a668fc922937175974953cbb51c49268265",
        },
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });
    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    expect(result3.finalKeyData.evmAddress).to.equal("0xCC1f953f6972a9e3d685d260399D6B85E2117561");
    expect(result3.metadata.typeOfUser).to.equal("v2");
    expect(result3).eql({
      oAuthKeyData: {
        evmAddress: "0xe8a19482cbe5FaC896A5860Ca4156fb999DDc73b",
        X: "c491ba39155594896b27cf71a804ccf493289d918f40e6ba4d590f1c76139e9e",
        Y: "d4649ed9e46461e1af00399a4c65fabb1dc219b3f4af501a7d635c17f57ab553",
      },
      finalKeyData: {
        evmAddress: "0xCC1f953f6972a9e3d685d260399D6B85E2117561",
        X: "8d784434becaad9b23d9293d1f29c4429447315c4cac824cbf2eb21d3f7d79c8",
        Y: "fe46a0ef5efe33d16f6cfa678a597be930fbec5432cbb7f3580189c18bd7e157",
      },
      metadata: {
        pubNonce: {
          X: "50e250cc6ac1d50d32d2b0f85f11c6625a917a115ced4ef24f4eac183e1525c7",
          Y: "8067a52d02b8214bf82e91b66ce5009f674f4c3998b103059c46c386d0c17f90",
        },
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });
  });

  it("should be able to key assign", async function () {
    const verifier = "tkey-google-cyan"; // any verifier
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oAuthKeyData, metadata } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalKeyData.evmAddress).to.not.equal("");
    expect(finalKeyData.evmAddress).to.not.equal(null);
    expect(oAuthKeyData.evmAddress).to.not.equal("");
    expect(oAuthKeyData.evmAddress).to.not.equal(null);
    expect(metadata.typeOfUser).to.equal("v1");
    expect(metadata.upgraded).to.equal(false);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    delete result.sessionData;
    expect(result.finalKeyData.privKey).to.be.equal("5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8");
    expect(result).eql({
      finalKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        evmAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      oAuthKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        evmAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { pubNonce: undefined, nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: result.nodesData.nodeIndexes },
    });
  });

  it("should be able to aggregate login", async function () {
    const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
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
    delete result.sessionData;
    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04");
    expect(result.finalKeyData.evmAddress).to.be.equal("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
        X: "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
        Y: "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
        privKey: "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf",
      },
      oAuthKeyData: {
        evmAddress: "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
        X: "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
        Y: "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
        privKey: "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { pubNonce: undefined, nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: result.nodesData.nodeIndexes },
    });
  });
});
