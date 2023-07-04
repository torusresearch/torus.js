import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256, TorusPublicKey } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "archit1@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils migrated testnet on sapphire", function () {
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
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalPubKeyData.evmAddress).to.equal("0x9bcBAde70546c0796c00323CD1b97fa0a425A506");
    expect(result).eql({
      oAuthPubKeyData: {
        evmAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        x: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
      },
      finalPubKeyData: {
        evmAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        x: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
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
    const verifier = "google-lrc"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result1.finalPubKeyData.evmAddress).to.equal("0x9bcBAde70546c0796c00323CD1b97fa0a425A506");
    expect(result1.metadata.typeOfUser).to.equal("v1");
    expect(result1).eql({
      oAuthPubKeyData: {
        evmAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        x: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
      },
      finalPubKeyData: {
        evmAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        x: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google-lrc";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    })) as TorusPublicKey;
    expect(result2.finalPubKeyData.evmAddress).to.equal("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D");
    expect(result2.metadata.typeOfUser).to.equal("v2");
    expect(result2).eql({
      oAuthPubKeyData: {
        evmAddress: "0x376597141d8d219553378313d18590F373B09795",
        x: "86cd2db15b7a9937fa8ab7d0bf8e7f4113b64d1f4b2397aad35d6d4749d2fb6c",
        y: "86ef47a3724144331c31a3a322d85b6fc1a5d113b41eaa0052053b6e3c74a3e2",
      },
      finalPubKeyData: {
        evmAddress: "0xE91200d82029603d73d6E307DbCbd9A7D0129d8D",
        x: "c350e338dde24df986915992fea6e0aef3560c245ca144ee7fe1498784c4ef4e",
        y: "a605e52b65d3635f89654519dfa7e31f7b45f206ef4189866ad0c2240d40f97f",
      },
      metadata: {
        pubNonce: {
          x: "ad121b67fa550da814bbbd54ec7070705d058c941e04c03e07967b07b2f90345",
          y: "bfe2395b177a72ebb836aaf24cedff2f14cd9ed49047990f5cdb99e4981b5753",
        },
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    })) as TorusPublicKey;
    expect(result3.finalPubKeyData.evmAddress).to.equal("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456");
    expect(result3.metadata.typeOfUser).to.equal("v2");
    expect(result3).eql({
      oAuthPubKeyData: {
        evmAddress: "0xd45383fbF04BccFa0450d7d8ee453ca86b7C6544",
        x: "d25cc473fbb448d20b5551f3c9aa121e1924b3d197353347187c47ad13ecd5d8",
        y: "3394000f43160a925e6c3017dde1354ecb2b61739571c6584f58edd6b923b0f5",
      },
      finalPubKeyData: {
        evmAddress: "0x1016DA7c47A04C76036637Ea02AcF1d29c64a456",
        x: "d3e222f6b23f0436b7c86e9cc4164eb5ea8448e4c0e7539c8b4f7fd00e8ec5c7",
        y: "1c47f5faccec6cf57c36919f6f0941fe3d8d65033cf2cc78f209304386044222",
      },
      metadata: {
        pubNonce: {
          x: "4f86b0e69992d1551f1b16ceb0909453dbe17b9422b030ee6c5471c2e16b65d0",
          y: "640384f3d39debb04c4e9fe5a5ec6a1b494b0ad66d00ac9be6f166f21d116ca4",
        },
        nonce: new BN(0),
        upgraded: true,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });
  });

  it("should be able to key assign", async function () {
    const verifier = "google-lrc"; // any verifier
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
    expect(result.finalKeyData.privKey).to.be.equal("9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
        X: "49702976712193399986731725034276818613785907981142175961484729425380356961789",
        Y: "96786966479458068943089798058579864926773560415468505198145869253238919342057",
        privKey: "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3",
      },
      oAuthKeyData: {
        evmAddress: "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
        X: "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
        Y: "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
        privKey: "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: { metadataNonce: new BN(0), typeOfUser: "v1", upgraded: null },
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
    expect(result.metadata.typeOfUser).to.be.equal("v1");
    expect(result.oAuthKeyData.evmAddress).to.be.equal("0x938a40E155d118BD31E439A9d92D67bd55317965");
    expect(result.finalKeyData.evmAddress).to.be.equal("0x938a40E155d118BD31E439A9d92D67bd55317965");
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x938a40E155d118BD31E439A9d92D67bd55317965",
        X: "12807676350687366924593653094908024592577690811576928555587654570837121768341",
        Y: "20253891874430456348096856713892060163029602605314794242419547596498838729190",
        privKey: "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1",
      },
      oAuthKeyData: {
        evmAddress: "0x938a40E155d118BD31E439A9d92D67bd55317965",
        X: "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
        Y: "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
        privKey: "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: { metadataNonce: new BN(0), typeOfUser: "v1", upgraded: null },
      nodesData: { nodeIndexes: result.nodesData.nodeIndexes },
    });
  });
});
