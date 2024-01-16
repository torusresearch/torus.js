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

describe("torus utils celeste", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      network: "celeste",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_LEGACY_NETWORK.CELESTE });
  });
  it("should fetch public address", async function () {
    const verifier = "tkey-google-celeste"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.equal("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242");
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
        X: "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
        Y: "085bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e",
      },
      finalKeyData: {
        evmAddress: "0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
        X: "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
        Y: "085bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e",
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
    const verifier = "tkey-google-celeste"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result1.finalKeyData.evmAddress).to.equal("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242");
    expect(result1.metadata.typeOfUser).to.equal("v1");
    expect(result1).eql({
      oAuthKeyData: {
        evmAddress: "0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
        X: "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
        Y: "085bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e",
      },
      finalKeyData: {
        evmAddress: "0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
        X: "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
        Y: "085bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google-celeste";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result2.finalKeyData.evmAddress).to.equal("0x69fB3A96016817F698a1279aE2d65F3916F3Db6F");
    expect(result2.metadata.typeOfUser).to.equal("v1");
    expect(result2).eql({
      oAuthKeyData: {
        evmAddress: "0x69fB3A96016817F698a1279aE2d65F3916F3Db6F",
        X: "9180a724488c99d7639f886e1920598618c2e599481d71ffd9f602c8a856ff20",
        Y: "c5da5c13fedf3a22964ab39afb871bff607479e2a5cb2e621608771b4276b44b",
      },
      finalKeyData: {
        evmAddress: "0x69fB3A96016817F698a1279aE2d65F3916F3Db6F",
        X: "9180a724488c99d7639f886e1920598618c2e599481d71ffd9f602c8a856ff20",
        Y: "c5da5c13fedf3a22964ab39afb871bff607479e2a5cb2e621608771b4276b44b",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    expect(result3.finalKeyData.evmAddress).to.equal("0x24aCac36F8A4bD93052207dA410dA71AF92258b7");
    expect(result3.metadata.typeOfUser).to.equal("v1");
    expect(result3).eql({
      oAuthKeyData: {
        evmAddress: "0x24aCac36F8A4bD93052207dA410dA71AF92258b7",
        X: "95b242e13e394e252d9685bfc1937a2acfa25e0c5e1d37bfd5247879ae1468cc",
        Y: "687a6754180aec931ff65e55a058032107df519334b2f5c6fb1fc5157620a219",
      },
      finalKeyData: {
        evmAddress: "0x24aCac36F8A4bD93052207dA410dA71AF92258b7",
        X: "95b242e13e394e252d9685bfc1937a2acfa25e0c5e1d37bfd5247879ae1468cc",
        Y: "687a6754180aec931ff65e55a058032107df519334b2f5c6fb1fc5157620a219",
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
    const verifier = "tkey-google-celeste"; // any verifier
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, metadata, oAuthKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
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
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token,
      torusNodePub
    );
    expect(result.finalKeyData.privKey).to.be.equal("0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x58420FB83971C4490D8c9B091f8bfC890D716617",
        X: "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
        Y: "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
        privKey: "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914",
      },
      oAuthKeyData: {
        evmAddress: "0x58420FB83971C4490D8c9B091f8bfC890D716617",
        X: "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
        Y: "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
        privKey: "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914",
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
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: TORUS_TEST_EMAIL,
      },
      hashedIdToken.substring(2),
      torusNodePub
    );
    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564");
    expect(result.finalKeyData.evmAddress).to.be.equal("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
        X: "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
        Y: "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
        privKey: "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e",
      },
      oAuthKeyData: {
        evmAddress: "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
        X: "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
        Y: "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
        privKey: "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { pubNonce: undefined, nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: [] },
    });
  });
});
