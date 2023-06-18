import { TORUS_NETWORK } from "@toruslabs/constants";
import { generatePrivate } from "@toruslabs/eccrypto";
import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";

import { keccak256, TorusPublicKey } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "saasas@tr.us";
const TORUS_IMPORT_EMAIL = "importeduser2@tor.us";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe("torus utils sapphire", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_NETWORK.SAPPHIRE_DEVNET });
    torus = new TorusUtils({
      network: TORUS_NETWORK.SAPPHIRE_DEVNET,
      allowHost: "https://signer.tor.us/api/allow",
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    TorusUtils.enableLogging(false);
  });

  it("should fetch public address of a legacy v1 user", async function () {
    const verifier = "google-lrc"; // any verifier
    const LEGACY_TORUS_NODE_MANAGER = new NodeManager({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      fndServerEndpoint: "http://localhost:8060/node-details",
    });

    const verifierDetails = { verifier, verifierId: "himanshu@tor.us" };
    const legacyTorus = new TorusUtils({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      allowHost: "https://signer.tor.us/api/allow",
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const publicAddress = (await legacyTorus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    expect(publicAddress.typeOfUser).to.equal("v1");
    expect(publicAddress.address).to.equal("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1");
  });

  it("should be able to login a v1 user", async function () {
    const email = "himanshu@tor.us";
    const verifier = "google-lrc";
    const token = generateIdToken(email, "ES256");

    const LEGACY_TORUS_NODE_MANAGER = new NodeManager({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      fndServerEndpoint: "http://localhost:8060/node-details",
    });

    const verifierDetails = { verifier, verifierId: email };
    const legacyTorus = new TorusUtils({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      allowHost: "https://signer.tor.us/api/allow",
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const retrieveSharesResponse = await legacyTorus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: email }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal("dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9");
  });

  it.skip("should fetch public address of a legacy v2 user", async function () {
    const verifier = "torus-test-health"; // any verifier
    const LEGACY_TORUS_NODE_MANAGER = new NodeManager({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      fndServerEndpoint: "http://localhost:8060/node-details",
    });

    const verifierDetails = { verifier, verifierId: "Jonathan.Nolan@hotmail.com" };
    const legacyTorus = new TorusUtils({
      network: TORUS_NETWORK.LEGACY_TESTNET,
      allowHost: "https://signer.tor.us/api/allow",
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints } = await LEGACY_TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const publicAddress = await legacyTorus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0x2876820fd9536BD5dd874189A85d71eE8bDf64c2");
  });

  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0x4924F91F5d6701dDd41042D94832bB17B76F316F");
  });

  it("should keep public address same", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: faker.internet.email() };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;

    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    const publicAddress2 = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal(publicAddress2);
  });
  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const { address } = (await torus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    expect(address).to.equal("0x4924F91F5d6701dDd41042D94832bB17B76F316F");
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal("");
    expect(publicAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal("04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c");
  });

  it("should be able to login even when node is down", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal("04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c");
  });
  it("should be able to import a key for a new user", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const privKeyBuffer = generatePrivate();
    const privHex = privKeyBuffer.toString("hex");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: email });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const importKeyResponse = await torus.importPrivateKey(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      nodeDetails.torusNodePub,
      TORUS_TEST_VERIFIER,
      { verifier_id: email },
      token,
      privHex
    );
    expect(importKeyResponse.privKey).to.be.equal(privHex);
  });

  // todo: fix this test case
  it("should be able to import a key for a existing user", async function () {
    let verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_IMPORT_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal(null);
    const token = generateIdToken(TORUS_IMPORT_EMAIL, "ES256");
    const privKeyBuffer = generatePrivate();
    const privHex = privKeyBuffer.toString("hex");
    const importKeyResponse = await torus.importPrivateKey(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      nodeDetails.torusNodePub,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_IMPORT_EMAIL },
      token,
      privHex
    );

    expect(importKeyResponse.privKey).to.be.equal(privHex);
    verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_IMPORT_EMAIL };
    const { address } = (await torus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    expect(importKeyResponse.ethAddress).to.be.equal(address);
  });

  it("should fetch pub address of tss verifier id", async function () {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.be.equal("0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30");
    const publicAddress2 = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.be.equal(publicAddress2);
  });
  it("should assign key to tss verifier id", async function () {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal(null);
  });

  it("should allow test tss verifier id to fetch shares", async function () {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const token = generateIdToken(email, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifierId: email, verifier: TORUS_TEST_VERIFIER });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { extended_verifier_id: tssVerifierId, verifier_id: email }, token);
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03");
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
    const { address } = (await torus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    expect(address).to.equal("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03");
  });
  it("should be able to login when verifierID hash enabled", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, HashEnabledVerifier, { verifier_id: TORUS_TEST_EMAIL }, token);

    expect(retrieveSharesResponse.privKey).to.be.equal("066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32");
  });

  it("should be able to aggregate login", async function () {
    const email = faker.internet.email();
    const idToken = generateIdToken(email, "ES256");
    const hashedIdToken = keccak256(Buffer.from(idToken, "utf8"));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const retrieveSharesResponse = await torus.retrieveShares(
      torusNodeEndpoints,
      TORUS_TEST_AGGREGATE_VERIFIER,
      {
        verify_params: [{ verifier_id: email, idtoken: idToken }],
        sub_verifier_ids: [TORUS_TEST_VERIFIER],
        verifier_id: email,
      },
      hashedIdToken.substring(2)
    );
    expect(retrieveSharesResponse.ethAddress).to.not.equal(null);
    expect(retrieveSharesResponse.ethAddress).to.not.equal("");
  });
});
