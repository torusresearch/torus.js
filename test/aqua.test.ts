import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256, TorusPublicKey } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils aqua", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      // signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      network: "aqua",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_LEGACY_NETWORK.AQUA });
  });
  it("should fetch public address", async function () {
    const verifier = "tkey-google-aqua"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalPubKeyData.evmAddress).to.equal("0xDfA967285AC699A70DA340F60d00DB19A272639d");
    expect(result).eql({
      oAuthPubKeyData: {
        evmAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        x: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
      },
      finalPubKeyData: {
        evmAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        x: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
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
    const verifier = "tkey-google-aqua"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails)) as TorusPublicKey;
    expect(result1.finalPubKeyData.evmAddress).to.equal("0xDfA967285AC699A70DA340F60d00DB19A272639d");
    expect(result1.metadata.typeOfUser).to.equal("v1");
    expect(result1).eql({
      oAuthPubKeyData: {
        evmAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        x: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
      },
      finalPubKeyData: {
        evmAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        x: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google-aqua";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    })) as TorusPublicKey;
    expect(result2.finalPubKeyData.evmAddress).to.equal("0x5735dDC8d5125B23d77C3531aab3895A533584a3");
    expect(result2.metadata.typeOfUser).to.equal("v1");
    expect(result2).eql({
      oAuthPubKeyData: {
        evmAddress: "0x5735dDC8d5125B23d77C3531aab3895A533584a3",
        x: "e1b419bc52b82e14b148c307f10479cfa464d20c947555fb4758c586eab12873",
        y: "75f47d7d5a271c0fcf51a790c1683a1cb3394b1d37d20e29c346ac249e3bfca2",
      },
      finalPubKeyData: {
        evmAddress: "0x5735dDC8d5125B23d77C3531aab3895A533584a3",
        x: "e1b419bc52b82e14b148c307f10479cfa464d20c947555fb4758c586eab12873",
        y: "75f47d7d5a271c0fcf51a790c1683a1cb3394b1d37d20e29c346ac249e3bfca2",
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
    const result3 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    })) as TorusPublicKey;
    expect(result3.finalPubKeyData.evmAddress).to.equal("0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD");
    expect(result3.metadata.typeOfUser).to.equal("v1");
    expect(result3).eql({
      oAuthPubKeyData: {
        evmAddress: "0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD",
        x: "e76d2f7fa2c0df324b4ab74629c3af47aa4609c35f1d2b6b90b77a47ab9a1281",
        y: "b33b35148d72d357070f66372e07fec436001bdb15c098276b120b9ed64c1e5f",
      },
      finalPubKeyData: {
        evmAddress: "0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD",
        x: "e76d2f7fa2c0df324b4ab74629c3af47aa4609c35f1d2b6b90b77a47ab9a1281",
        y: "b33b35148d72d357070f66372e07fec436001bdb15c098276b120b9ed64c1e5f",
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
    const verifier = "tkey-google-aqua"; // any verifier
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalPubKeyData, oAuthPubKeyData, metadata } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalPubKeyData.evmAddress).to.not.equal("");
    expect(finalPubKeyData.evmAddress).to.not.equal(null);
    expect(oAuthPubKeyData.evmAddress).to.not.equal("");
    expect(oAuthPubKeyData.evmAddress).to.not.equal(null);
    expect(metadata.typeOfUser).to.equal("v1");
    expect(metadata.upgraded).to.equal(false);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(result.finalKeyData.privKey).to.be.equal("f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0xdF92B73352Eb4aBd0385bc1e31a8b0BD6EA4D161",
        X: "45151049626334797959122802548866520276763178585564784364986393863189010875045",
        Y: "56424055808696084034226309171000882700166114824429869880517503869697125990463",
        privKey: "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d",
      },
      oAuthKeyData: {
        evmAddress: "0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
        X: "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
        Y: "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
        privKey: "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { nonce: new BN(0), typeOfUser: "v1", upgraded: null },
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

    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D");
    expect(result.finalKeyData.evmAddress).to.be.equal("0x011C64d5585E0a34Ca2E70AA0bd34daFC683B358");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x011C64d5585E0a34Ca2E70AA0bd34daFC683B358",
        X: "38590796519188980875468267478199668365197289821125554170604841336730940042946",
        Y: "32120738633526637982361662047914076954580011956651434724359038836918748645936",
        privKey: "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355",
      },
      oAuthKeyData: {
        evmAddress: "0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
        X: "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
        Y: "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
        privKey: "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355",
      },
      sessionData: { sessionTokenData: [], sessionAuthKey: "" },
      metadata: { nonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: [] },
    });
  });
});
