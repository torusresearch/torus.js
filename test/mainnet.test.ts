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
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.equal("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A");
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
        X: "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
        Y: "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1",
      },
      finalKeyData: {
        evmAddress: "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
        X: "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
        Y: "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1",
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
    const verifier = "google"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result1.finalKeyData.evmAddress).to.equal("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A");
    expect(result1.metadata.typeOfUser).to.equal("v1");
    expect(result1).eql({
      oAuthKeyData: {
        evmAddress: "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
        X: "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
        Y: "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1",
      },
      finalKeyData: {
        evmAddress: "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
        X: "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
        Y: "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result2.finalKeyData.evmAddress).to.equal("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526");
    expect(result2.metadata.typeOfUser).to.equal("v2");
    expect(result2).eql({
      oAuthKeyData: {
        evmAddress: "0xA9c6829e4899b6D630130ebf59D046CA868D7f83",
        X: "5566cd940ea540ba1a3ba2ff0f5fd3d9a3a74350ac3baf47b811592ae6ea1c30",
        Y: "07a302e87e8d9eb5d143f570c248657288c13c09ecbe1e3a8720449daf9315b0",
      },
      finalKeyData: {
        evmAddress: "0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526",
        X: "bbfd26b1e61572c4e991a21b64f12b313cb6fce6b443be92d4d5fd8f311e8f33",
        Y: "df2c905356ec94faaa111a886be56ed6fa215b7facc1d1598486558355123c25",
      },
      metadata: {
        pubNonce: {
          X: "96f4b7d3c8c8c69cabdea46ae1eedda346b03cad8ba1a454871b0ec6a69861f3",
          Y: "da3aed7f7e9d612052beb1d92ec68a8dcf60faf356985435b424af2423f66672",
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
    expect(result3.finalKeyData.evmAddress).to.equal("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53");
    expect(result3.metadata.typeOfUser).to.equal("v1");
    expect(result3).eql({
      oAuthKeyData: {
        evmAddress: "0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53",
        X: "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8",
        Y: "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7",
      },
      finalKeyData: {
        evmAddress: "0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53",
        X: "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8",
        Y: "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7",
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

  it("should be able to key assign", async function () {
    const verifier = "google"; // any verifier
    // TorusUtils.enableLogging(true);
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
    // TorusUtils.enableLogging(false);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x90A926b698047b4A87265ba1E9D8b512E8489067");
    expect(result.finalKeyData.privKey).to.be.equal("0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44");
    expect(result.finalKeyData.evmAddress).to.be.equal("0xB4d9D085AA7f28dC60De88e343A32363079b4A59");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0xB4d9D085AA7f28dC60De88e343A32363079b4A59",
        X: "31600521026132112170505875906080018823972474568844927151389160616822189112799",
        Y: "17273036880415366106658985805391994876983148722894059515138336751166359563553",
        privKey: "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44",
      },
      oAuthKeyData: {
        evmAddress: "0x90A926b698047b4A87265ba1E9D8b512E8489067",
        X: "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f",
        Y: "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1",
        privKey: "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { pubNonce: undefined, nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: [] },
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
    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x621a4d458cFd345dAE831D9E756F10cC40A50381");

    expect(result.finalKeyData.evmAddress).to.be.equal("0xA5F7751515b8561Ec7aF1Fba589ac4eeAE008578");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0xA5F7751515b8561Ec7aF1Fba589ac4eeAE008578",
        X: "43564288410192394462847657942154042873928392376563036841495138510673098978279",
        Y: "59983272266567645178572545705333227687084077741077174039161990905110140858036",
        privKey: "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534",
      },
      oAuthKeyData: {
        evmAddress: "0x621a4d458cFd345dAE831D9E756F10cC40A50381",
        X: "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236",
        Y: "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e",
        privKey: "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { pubNonce: undefined, nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: [] },
    });
  });
});
