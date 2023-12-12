import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { generatePrivate } from "@toruslabs/eccrypto";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import { ec as EC } from "elliptic";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const ec = new EC("ed25519");
const TORUS_TEST_EMAIL = "ed25519@tor.us";
const TORUS_IMPORT_EMAIL = "importeduser5@tor.us";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe.skip("torus utils ed25519 sapphire devnet", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET });
    torus = new TorusUtils({
      network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
      keyType: "ed25519",
    });
    TorusUtils.enableLogging(false);
  });

  it("should be able to import a key for a new user", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const privKeyBuffer = new BN(generatePrivate()).umod(ec.curve.n);
    const privHex = privKeyBuffer.toString("hex", 64);
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: email });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.importPrivateKey(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      nodeDetails.torusNodePub,
      TORUS_TEST_VERIFIER,
      { verifier_id: email },
      token,
      privHex
    );
    expect(result.finalKeyData.privKey).to.be.equal(privHex);
  });
  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(result.finalKeyData.privKey).to.be.equal("08f54f7c3622a44dd4090397c001d4904d14646222775b29c5e4611f797d75e9");
  });

  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.X).to.equal("3af3d1e4e10d65ddb96210d5865ddab5b7c5fbe2bad157a6497615cfa8e9bcf5");
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x89155E126aAC6ea94D479d8D7aB5e1BE4ed51eEF",
        X: "1dfd79a9c42f3ddce4b2601fe629ab1b70c0d8d133c33aead2007b865f63ad6c",
        Y: "06ab3522dd3710bd26bbe502c4cad0ef0c4ad47e87e13fb3143367ded3426a8f",
      },
      finalKeyData: {
        evmAddress: "0x4b0426e4E8b605753336B88C2F5F8E79E9FdA7aA",
        X: "3af3d1e4e10d65ddb96210d5865ddab5b7c5fbe2bad157a6497615cfa8e9bcf5",
        Y: "47bb8524c3d6a895888e9fe4f903186a749de7766d0a14c421312d7c3ffc87ef",
      },
      metadata: {
        pubNonce: {
          X: "1cecc501e8701081c4c61b3e7696aa8f2494e79013c18cdf9c4ad528d65cc4b3",
          Y: "459cb8092ac5e99b051cf135a639353d5a6bf4bc8785ec92bbaaee763d1c8963",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });
  // we are working on a new implementation for import sss keys, so skipping it for now.
  it("should fetch public address of imported user", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_IMPORT_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.not.equal(null);
    expect(result.finalKeyData.evmAddress).to.not.equal("");
    expect(result.finalKeyData.evmAddress).to.not.equal(null);
    expect(result.oAuthKeyData.evmAddress).to.not.equal("");
    expect(result.oAuthKeyData.evmAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.upgraded).to.equal(false);
  });

  it("should keep public address same", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: faker.internet.email() };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;

    const result1 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result1.finalKeyData).eql(result2.finalKeyData);
    expect(result1.oAuthKeyData).eql(result2.oAuthKeyData);
    expect(result1.metadata).eql(result2.metadata);
  });

  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x89155E126aAC6ea94D479d8D7aB5e1BE4ed51eEF",
        X: "1dfd79a9c42f3ddce4b2601fe629ab1b70c0d8d133c33aead2007b865f63ad6c",
        Y: "06ab3522dd3710bd26bbe502c4cad0ef0c4ad47e87e13fb3143367ded3426a8f",
      },
      finalKeyData: {
        evmAddress: "0x4b0426e4E8b605753336B88C2F5F8E79E9FdA7aA",
        X: "3af3d1e4e10d65ddb96210d5865ddab5b7c5fbe2bad157a6497615cfa8e9bcf5",
        Y: "47bb8524c3d6a895888e9fe4f903186a749de7766d0a14c421312d7c3ffc87ef",
      },
      metadata: {
        pubNonce: {
          X: "1cecc501e8701081c4c61b3e7696aa8f2494e79013c18cdf9c4ad528d65cc4b3",
          Y: "459cb8092ac5e99b051cf135a639353d5a6bf4bc8785ec92bbaaee763d1c8963",
        },
        nonce: new BN("0", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.not.equal("");
    expect(result.finalKeyData.evmAddress).to.not.equal(null);
  });

  it("should be able to login even when node is down", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(result.finalKeyData.privKey).to.be.equal("08f54f7c3622a44dd4090397c001d4904d14646222775b29c5e4611f797d75e9");
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
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xdA7c5B1D01B511D8f0e921E047a17884B52a6F45",
        X: "333a0a6b95514f9a92899970f9ae97bbd23f09fbc3b18f419d7dd23ae89c9579",
        Y: "3ded16683d0c50c43749ff691e0e6f04a1597b5eccd85b602d8927d43ee2b6de",
      },
      finalKeyData: {
        evmAddress: "0xdA7c5B1D01B511D8f0e921E047a17884B52a6F45",
        X: "333a0a6b95514f9a92899970f9ae97bbd23f09fbc3b18f419d7dd23ae89c9579",
        Y: "3ded16683d0c50c43749ff691e0e6f04a1597b5eccd85b602d8927d43ee2b6de",
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
    expect(result.finalKeyData.evmAddress).to.not.equal(null);
    expect(result.oAuthKeyData.evmAddress).to.not.equal(null);
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
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { extended_verifier_id: tssVerifierId, verifier_id: email },
      token
    );
    expect(result.finalKeyData.privKey).to.not.equal(null);
    expect(result.oAuthKeyData.evmAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.eql(new BN("0"));
    expect(result.metadata.upgraded).to.equal(true);
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x2b133a232194524A421EB5A7BE8F5Ad7df25a02A",
        X: "299ad86ffe85fb33d8eee765908a031ae543af09f5226316d2367aa6d21df9af",
        Y: "45d153c52d8b1eb12c2e2b5769284a4763ca7d61d8373f109d1997b6c647742b",
      },
      finalKeyData: {
        evmAddress: "0x86571392a487219B98395106234c6c0Be3732796",
        X: "7b1ede24b623def02bc86e32702a4b1afd8dd31586e87f6d87887f3391c7bd6e",
        Y: "347a62abfdbb488e5710eab49e1b8e88c3164d92a0095eaf8d087120a03baa59",
      },
      metadata: {
        pubNonce: {
          X: "5e1b1653f2fa15da37d94a052be4e6ef37cd8bf9f5d4a10f1742e6a03134acac",
          Y: "3a12ed5ac3ca5ca7ad056edc9ea6a16498b93c7a2669044d0154527a22c7dd5a",
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
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: TORUS_TEST_VERIFIER });
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
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x2b133a232194524A421EB5A7BE8F5Ad7df25a02A",
        X: "299ad86ffe85fb33d8eee765908a031ae543af09f5226316d2367aa6d21df9af",
        Y: "45d153c52d8b1eb12c2e2b5769284a4763ca7d61d8373f109d1997b6c647742b",
      },
      finalKeyData: {
        evmAddress: "0x86571392a487219B98395106234c6c0Be3732796",
        X: "7b1ede24b623def02bc86e32702a4b1afd8dd31586e87f6d87887f3391c7bd6e",
        Y: "347a62abfdbb488e5710eab49e1b8e88c3164d92a0095eaf8d087120a03baa59",
      },
      metadata: {
        pubNonce: {
          X: "5e1b1653f2fa15da37d94a052be4e6ef37cd8bf9f5d4a10f1742e6a03134acac",
          Y: "3a12ed5ac3ca5ca7ad056edc9ea6a16498b93c7a2669044d0154527a22c7dd5a",
        },
        nonce: new BN("0"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });
  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      HashEnabledVerifier,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );
    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x86571392a487219B98395106234c6c0Be3732796",
        X: "7b1ede24b623def02bc86e32702a4b1afd8dd31586e87f6d87887f3391c7bd6e",
        Y: "347a62abfdbb488e5710eab49e1b8e88c3164d92a0095eaf8d087120a03baa59",
        privKey: "01de90970e389675a64673fd38845304cbf0a00ea98c202db3d53210ec9a337c",
      },
      oAuthKeyData: {
        evmAddress: "0x2b133a232194524A421EB5A7BE8F5Ad7df25a02A",
        X: "299ad86ffe85fb33d8eee765908a031ae543af09f5226316d2367aa6d21df9af",
        Y: "45d153c52d8b1eb12c2e2b5769284a4763ca7d61d8373f109d1997b6c647742b",
        privKey: "0db22507f8262d2b76cbb3bac9ac9e9e67fae25981f2b8091bd5e825b34e100b",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "5e1b1653f2fa15da37d94a052be4e6ef37cd8bf9f5d4a10f1742e6a03134acac",
          Y: "3a12ed5ac3ca5ca7ad056edc9ea6a16498b93c7a2669044d0154527a22c7dd5a",
        },
        nonce: new BN("142c6b8f1612694a2f7ac0426ed7b4668db3b1726d88a1d14824101ff337cb4b", "hex"),
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
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: email, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: email,
      },
      hashedIdToken.substring(2)
    );
    expect(result.finalKeyData.evmAddress).to.not.equal(null);
    expect(result.finalKeyData.evmAddress).to.not.equal("");
    expect(result.oAuthKeyData.evmAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.not.equal(null);
    expect(result.metadata.upgraded).to.equal(false);
  });
});
