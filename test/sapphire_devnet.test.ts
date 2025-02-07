import { faker } from "@faker-js/faker";
import { TORUS_LEGACY_NETWORK, TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import { ec as EC } from "elliptic";

import { generatePrivateKey, keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getImportKeyParams, getRetrieveSharesParams, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "devnettestuser@tor.us";
const TORUS_HASH_ENABLED_TEST_EMAIL = "saasas@tr.us";

const TORUS_IMPORT_EMAIL = "Sydnie.Lehner73@yahoo.com";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe("torus utils sapphire devnet", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach("one time execution before all tests", async function () {
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET });
    torus = new TorusUtils({
      network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    TorusUtils.enableLogging(false);
  });

  it("should fetch public address of a legacy v1 user", async function () {
    const verifier = "google-lrc"; // any verifier
    const LEGACY_TORUS_NODE_MANAGER = new NodeDetailManager({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      // fndServerEndpoint: "http://localhost:8060/node-details",
    });

    const verifierDetails = { verifier, verifierId: "himanshu@tor.us" };
    const legacyTorus = new TorusUtils({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints, torusNodePub } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const publicKeyData = await legacyTorus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(publicKeyData.metadata.typeOfUser).to.equal("v1");
    expect(publicKeyData.finalKeyData.walletAddress).to.equal("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1");
    delete publicKeyData.metadata.serverTimeOffset;
    expect(publicKeyData).eql({
      oAuthKeyData: {
        walletAddress: "0xf1e76fcDD28b5AA06De01de508fF21589aB9017E",
        X: "b3f2b4d8b746353fe670e0c39ac9adb58056d4d7b718d06b623612d4ec49268b",
        Y: "ac9f79dff78add39cdba380dbbf517c20cf2c1e06b32842a90a84a31f6eb9a9a",
      },
      finalKeyData: {
        walletAddress: "0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1",
        X: "12f6b90d66bda29807cf9ff14b2e537c25080154fc4fafed446306e8356ff425",
        Y: "e7c92e164b83e1b53e41e5d87d478bb07d7b19d105143e426e1ef08f7b37f224",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN("186a20d9b00315855ff5622a083aca6b2d34ef66ef6e0a4de670f5b2fde37e0d", "hex"),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: publicKeyData.nodesData,
    });
  });

  it("should be able to login a v1 user", async function () {
    const email = "himanshu@tor.us";
    const verifier = "google-lrc";
    const token = generateIdToken(email, "ES256");

    const LEGACY_TORUS_NODE_MANAGER = new NodeDetailManager({
      network: TORUS_LEGACY_NETWORK.TESTNET,
    });

    const verifierDetails = { verifier, verifierId: email };
    const legacyTorus = new TorusUtils({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      clientId: "YOUR_CLIENT_ID",
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints, torusIndexes, torusNodePub } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const retrieveSharesResponse = await legacyTorus.retrieveShares(
      getRetrieveSharesParams(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: email }, token, torusNodePub)
    );
    expect(retrieveSharesResponse.finalKeyData.privKey).to.be.equal("dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9");
    delete retrieveSharesResponse.sessionData;
    delete retrieveSharesResponse.metadata.serverTimeOffset;

    expect(retrieveSharesResponse).eql({
      oAuthKeyData: {
        walletAddress: "0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
        X: "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
        Y: "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
        privKey: "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9",
      },
      postboxKeyData: {
        X: "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
        Y: "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
        privKey: "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9",
      },
      finalKeyData: {
        walletAddress: "0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
        X: "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
        Y: "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
        privKey: "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: null,
        typeOfUser: "v1",
      },
      nodesData: retrieveSharesResponse.nodesData,
    });
  });

  it("should fetch user type and public address of legacy v2 user", async function () {
    const LEGACY_TORUS_NODE_MANAGER = new NodeDetailManager({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      // fndServerEndpoint: "http://localhost:8060/node-details",
    });
    const v2Verifier = "tkey-google-lrc";
    // 1/1 user
    const v2TestEmail = "somev2user@gmail.com";
    const verifierDetails = { verifier: v2Verifier, verifierId: v2TestEmail };

    const legacyTorus = new TorusUtils({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints, torusNodePub } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);

    const result = await legacyTorus.getPublicAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result.finalKeyData.walletAddress).to.equal("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D");
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.serverTimeOffset).lessThan(20);

    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0x376597141d8d219553378313d18590F373B09795",
        X: "86cd2db15b7a9937fa8ab7d0bf8e7f4113b64d1f4b2397aad35d6d4749d2fb6c",
        Y: "86ef47a3724144331c31a3a322d85b6fc1a5d113b41eaa0052053b6e3c74a3e2",
      },
      finalKeyData: {
        walletAddress: "0xE91200d82029603d73d6E307DbCbd9A7D0129d8D",
        X: "c350e338dde24df986915992fea6e0aef3560c245ca144ee7fe1498784c4ef4e",
        Y: "a605e52b65d3635f89654519dfa7e31f7b45f206ef4189866ad0c2240d40f97f",
      },
      metadata: {
        pubNonce: {
          X: "ad121b67fa550da814bbbd54ec7070705d058c941e04c03e07967b07b2f90345",
          Y: "bfe2395b177a72ebb836aaf24cedff2f14cd9ed49047990f5cdb99e4981b5753",
        },
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });

    // 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const data = await legacyTorus.getPublicAddress(torusNodeEndpoints, torusNodePub, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    expect(data.metadata.typeOfUser).to.equal("v2");
    expect(data.finalKeyData.walletAddress).to.equal("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456");
    expect(data.metadata.serverTimeOffset).lessThan(20);

    delete data.metadata.serverTimeOffset;
    expect(data).eql({
      oAuthKeyData: {
        walletAddress: "0xd45383fbF04BccFa0450d7d8ee453ca86b7C6544",
        X: "d25cc473fbb448d20b5551f3c9aa121e1924b3d197353347187c47ad13ecd5d8",
        Y: "3394000f43160a925e6c3017dde1354ecb2b61739571c6584f58edd6b923b0f5",
      },
      finalKeyData: {
        walletAddress: "0x1016DA7c47A04C76036637Ea02AcF1d29c64a456",
        X: "d3e222f6b23f0436b7c86e9cc4164eb5ea8448e4c0e7539c8b4f7fd00e8ec5c7",
        Y: "1c47f5faccec6cf57c36919f6f0941fe3d8d65033cf2cc78f209304386044222",
      },
      metadata: {
        pubNonce: {
          X: "4f86b0e69992d1551f1b16ceb0909453dbe17b9422b030ee6c5471c2e16b65d0",
          Y: "640384f3d39debb04c4e9fe5a5ec6a1b494b0ad66d00ac9be6f166f21d116ca4",
        },
        nonce: new BN(0),
        upgraded: true,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
      },
      finalKeyData: {
        walletAddress: "0x462A8BF111A55C9354425F875F89B22678c0Bc44",
        X: "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
        Y: "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
      },
      metadata: {
        pubNonce: {
          X: "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
          Y: "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should fetch public address of imported user", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_IMPORT_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    expect(result.oAuthKeyData.walletAddress).to.not.equal("");
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.upgraded).to.equal(false);
  });

  it("should keep public address same", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: faker.internet.email() };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;

    const result1 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result1.metadata.serverTimeOffset).lessThan(20);

    delete result1.metadata.serverTimeOffset;
    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result2.metadata.serverTimeOffset).lessThan(20);

    delete result2.metadata.serverTimeOffset;

    expect(result1.finalKeyData).eql(result2.finalKeyData);
    expect(result1.oAuthKeyData).eql(result2.oAuthKeyData);
    expect(result1.metadata).eql(result2.metadata);
  });

  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
      },
      finalKeyData: {
        walletAddress: "0x462A8BF111A55C9354425F875F89B22678c0Bc44",
        X: "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
        Y: "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
      },
      metadata: {
        pubNonce: {
          X: "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
          Y: "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to key assign", async function () {
    const email = `${faker.internet.email()}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub,
        {}
      )
    );
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      finalKeyData: {
        walletAddress: "0x462A8BF111A55C9354425F875F89B22678c0Bc44",
        X: "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
        Y: "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
        privKey: "230dad9f42039569e891e6b066ff5258b14e9764ef5176d74aeb594d1a744203",
      },
      oAuthKeyData: {
        walletAddress: "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      postboxKeyData: {
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
          Y: "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed",
        },
        nonce: new BN("b7d126751b68ecd09e371a23898e6819dee54708a5ead4f6fe83cdc79c0f1c4a", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login without commitments", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub,
        {},
        true,
        false
      )
    );
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      finalKeyData: {
        walletAddress: "0x462A8BF111A55C9354425F875F89B22678c0Bc44",
        X: "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
        Y: "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
        privKey: "230dad9f42039569e891e6b066ff5258b14e9764ef5176d74aeb594d1a744203",
      },
      oAuthKeyData: {
        walletAddress: "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      postboxKeyData: {
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
          Y: "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed",
        },
        nonce: new BN("b7d126751b68ecd09e371a23898e6819dee54708a5ead4f6fe83cdc79c0f1c4a", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login with non dkg keys", async function () {
    const email = `atomicimporttest2`;
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        nodeDetails.torusNodePub,
        {},
        false
      )
    );

    const publicResult = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.X).eql(publicResult.finalKeyData.X);
  });

  it("should be able to login a new user with non dkg keys", async function () {
    const email = `${faker.internet.email()}`;
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        nodeDetails.torusNodePub,
        {},
        false
      )
    );

    const publicResult = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);

    expect(result.finalKeyData.X).eql(publicResult.finalKeyData.X);
  });

  it("should be able to login even when node is down", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub
      )
    );
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      finalKeyData: {
        walletAddress: "0x462A8BF111A55C9354425F875F89B22678c0Bc44",
        X: "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
        Y: "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
        privKey: "230dad9f42039569e891e6b066ff5258b14e9764ef5176d74aeb594d1a744203",
      },
      oAuthKeyData: {
        walletAddress: "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      postboxKeyData: {
        X: "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
        Y: "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
        privKey: "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
          Y: "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed",
        },
        nonce: new BN("b7d126751b68ecd09e371a23898e6819dee54708a5ead4f6fe83cdc79c0f1c4a", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to update the `sessionTime` of the token signature data", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";

    const customSessionTime = 3600;
    TorusUtils.setSessionTime(customSessionTime); // 1hr

    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub
      )
    );

    const signatures = result.sessionData.sessionTokenData.map((s) => ({ data: s.token, sig: s.signature }));

    const parsedSigsData = signatures.map((s) => JSON.parse(atob(s.data)));
    parsedSigsData.forEach((ps) => {
      const sessionTime = ps.exp - Math.floor(Date.now() / 1000);
      expect(sessionTime).greaterThan(customSessionTime - 5); // giving a latency leeway of 5 seconds
      expect(sessionTime).lessThanOrEqual(customSessionTime);
    });
  });

  it("should be able to import a key for a new user", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const ec = new EC("secp256k1");
    const privKeyBuffer = generatePrivateKey(ec, Buffer);
    const privHex = privKeyBuffer.toString("hex");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: email });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.importPrivateKey(
      getImportKeyParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        nodeDetails.torusNodePub,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        privHex
      )
    );
    expect(result.finalKeyData.privKey).to.be.equal(privHex);
    const result1 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, { verifier: TORUS_TEST_VERIFIER, verifierId: email });
    expect(result1.finalKeyData.walletAddress).to.be.equal(result.finalKeyData.walletAddress);
  });

  it("should fetch pub address of tss verifier id", async function () {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30",
        X: "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c",
        Y: "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e",
      },
      finalKeyData: {
        walletAddress: "0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30",
        X: "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c",
        Y: "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should assign key to tss verifier id", async function () {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.eql(new BN("0"));
    expect(result.metadata.upgraded).to.equal(false);
  });

  it("should allow test tss verifier id to fetch shares", async function () {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const token = generateIdToken(email, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifierId: email, verifier: TORUS_TEST_VERIFIER });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { extended_verifier_id: tssVerifierId, verifier_id: email },
        token,
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.privKey).to.not.equal(null);
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.eql(new BN("0"));
    expect(result.metadata.upgraded).to.equal(true);
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_HASH_ENABLED_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.equal("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03");
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
        X: "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
        Y: "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
      },
      finalKeyData: {
        walletAddress: "0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
        X: "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
        Y: "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e",
      },
      metadata: {
        pubNonce: {
          X: "d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
          Y: "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  // to do: update pub keys
  it.skip("should lookup return hash when verifierID hash enabled", async function () {
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: TORUS_HASH_ENABLED_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    for (const endpoint of torusNodeEndpoints) {
      const pubKeyX = "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a";
      const pubKeyY = "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e";
      const response = await lookupVerifier(endpoint, pubKeyX, pubKeyY);
      const verifierID = response.result.verifiers[HashEnabledVerifier][0];
      expect(verifierID).to.equal("086c23ab78578f2fce9a1da11c0071ec7c2225adb1bf499ffaee98675bee29b7");
    }
  });

  it("should fetch user type and public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_HASH_ENABLED_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.equal("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03");
    expect(result.metadata.serverTimeOffset).lessThan(20);

    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
        X: "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
        Y: "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
      },
      finalKeyData: {
        walletAddress: "0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
        X: "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
        Y: "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e",
      },
      metadata: {
        pubNonce: {
          X: "d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
          Y: "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_HASH_ENABLED_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_HASH_ENABLED_TEST_EMAIL };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        HashEnabledVerifier,
        { verifier_id: TORUS_HASH_ENABLED_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub
      )
    );
    delete result.metadata.serverTimeOffset;

    expect(result.finalKeyData.privKey).to.be.equal("066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32");
    expect(result).eql({
      finalKeyData: {
        walletAddress: "0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
        X: "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
        Y: "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e",
        privKey: "066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32",
      },
      oAuthKeyData: {
        walletAddress: "0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
        X: "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
        Y: "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
        privKey: "b47769e81328794adf3534e58d02803ca2a5e4588db81780f5bf679c77988946",
      },
      postboxKeyData: {
        X: "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
        Y: "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
        privKey: "b47769e81328794adf3534e58d02803ca2a5e4588db81780f5bf679c77988946",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
          Y: "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e",
        },
        nonce: new BN("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to aggregate login", async function () {
    const email = faker.internet.email();
    const idToken = generateIdToken(email, "ES256");
    const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_AGGREGATE_VERIFIER,
        {
          verify_params: [{ verifier_id: email, idtoken: idToken }],
          sub_verifier_ids: [TORUS_TEST_VERIFIER],
          verifier_id: email,
        },
        hashedIdToken.substring(2),
        nodeDetails.torusNodePub
      )
    );
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.not.equal(null);
    expect(result.metadata.upgraded).to.equal(false);
  });

  it("should be able to login with different accounts and get different addresses for each", async function () {
    const email1 = faker.internet.email();
    const email2 = faker.internet.email();

    const idToken1 = generateIdToken(email1, "ES256");
    const idToken2 = generateIdToken(email2, "ES256");
    const hashedIdToken1 = keccak256(Buffer.from(idToken1, "utf8"));
    const hashedIdToken2 = keccak256(Buffer.from(idToken2, "utf8"));
    const verifierDetails1 = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email1 };
    const verifierDetails2 = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email2 };

    const nodeDetails1 = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails1);
    const nodeDetails2 = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails2);
    const torusNodeEndpoints1 = nodeDetails1.torusNodeSSSEndpoints;
    const torusNodeEndpoints2 = nodeDetails1.torusNodeSSSEndpoints;
    const result1 = await torus.retrieveShares({
      endpoints: torusNodeEndpoints1,
      indexes: nodeDetails1.torusIndexes,
      verifier: TORUS_TEST_AGGREGATE_VERIFIER,
      verifierParams: {
        verify_params: [{ verifier_id: email1, idtoken: idToken1 }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: email1,
      },
      idToken: hashedIdToken1.substring(2),
      nodePubkeys: nodeDetails1.torusNodePub,
    });
    const result2 = await torus.retrieveShares({
      endpoints: torusNodeEndpoints2,
      indexes: nodeDetails2.torusIndexes,
      verifier: TORUS_TEST_AGGREGATE_VERIFIER,
      verifierParams: {
        verify_params: [{ verifier_id: email2, idtoken: idToken2 }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: email2,
      },
      idToken: hashedIdToken2.substring(2),
      nodePubkeys: nodeDetails2.torusNodePub,
    });
    expect(result1.metadata.serverTimeOffset).lessThan(20);

    expect(result1.finalKeyData.walletAddress).to.not.equal(null);
    expect(result1.finalKeyData.walletAddress).to.not.equal("");
    expect(result1.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result1.metadata.typeOfUser).to.equal("v2");
    expect(result1.metadata.nonce).to.not.equal(null);
    expect(result1.metadata.upgraded).to.equal(false);

    expect(result2.metadata.serverTimeOffset).lessThan(20);

    expect(result2.finalKeyData.walletAddress).to.not.equal(null);
    expect(result2.finalKeyData.walletAddress).to.not.equal("");
    expect(result2.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result2.metadata.typeOfUser).to.equal("v2");
    expect(result2.metadata.nonce).to.not.equal(null);
    expect(result2.metadata.upgraded).to.equal(false);

    expect(result2.finalKeyData.walletAddress).to.not.equal(result1.finalKeyData.walletAddress);
  });

  it("should be able to login with the same account repeatedly and get the same address", async function () {
    const addresses = [];
    const iterations = 5;
    const email = faker.internet.email();
    for (let i = 0; i <= iterations; i++) {
      const idToken = generateIdToken(email, "ES256");
      const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
      const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email };

      const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
      const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
      const result = await torus.retrieveShares({
        endpoints: torusNodeEndpoints,
        indexes: nodeDetails.torusIndexes,
        verifier: TORUS_TEST_AGGREGATE_VERIFIER,
        verifierParams: {
          verify_params: [{ verifier_id: email, idtoken: idToken }],
          sub_verifier_ids: [TORUS_TEST_VERIFIER],
          verifier_id: email,
        },
        idToken: hashedIdToken.substring(2),
        nodePubkeys: nodeDetails.torusNodePub,
      });
      expect(result.metadata.serverTimeOffset).lessThan(20);
      delete result.metadata.serverTimeOffset;

      expect(result.finalKeyData.walletAddress).to.not.equal(null);
      expect(result.finalKeyData.walletAddress).to.not.equal("");
      expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
      expect(result.metadata.typeOfUser).to.equal("v2");
      expect(result.metadata.nonce).to.not.equal(null);
      expect(result.metadata.upgraded).to.equal(false);

      addresses.push(result.finalKeyData.walletAddress);
    }
    const set = new Set(addresses);
    expect(set.size).to.equal(1);
  });

  it("should be able to login with a fixed set of different accounts repeatedly and get a constant set of addresses", async function () {
    const addresses = [];
    const iterations = 5;
    for (let i = 0; i <= iterations; i++) {
      const email = faker.internet.email();
      for (let k = 0; k <= iterations; k++) {
        const idToken = generateIdToken(email, "ES256");
        const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
        const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email };

        const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
        const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
        const result = await torus.retrieveShares({
          endpoints: torusNodeEndpoints,
          indexes: nodeDetails.torusIndexes,
          verifier: TORUS_TEST_AGGREGATE_VERIFIER,
          verifierParams: {
            verify_params: [{ verifier_id: email, idtoken: idToken }],
            sub_verifier_ids: [TORUS_TEST_VERIFIER],
            verifier_id: email,
          },
          idToken: hashedIdToken.substring(2),
          nodePubkeys: nodeDetails.torusNodePub,
        });
        expect(result.metadata.serverTimeOffset).lessThan(20);
        delete result.metadata.serverTimeOffset;

        expect(result.finalKeyData.walletAddress).to.not.equal(null);
        expect(result.finalKeyData.walletAddress).to.not.equal("");
        expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
        expect(result.metadata.typeOfUser).to.equal("v2");
        expect(result.metadata.nonce).to.not.equal(null);
        expect(result.metadata.upgraded).to.equal(false);

        addresses.push(result.finalKeyData.walletAddress);
      }
    }
    const set = new Set(addresses);
    expect(set.size).to.equal(6);
  });
});
