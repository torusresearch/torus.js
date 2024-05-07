import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { generatePrivate } from "@toruslabs/eccrypto";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-aggregate-sapphire-mainnet";
const HashEnabledVerifier = "torus-test-verifierid-hash";
const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";

describe("torus utils sapphire mainnet", function () {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeManager;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_MAINNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
    });
    TORUS_NODE_MANAGER = new NodeManager({ network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_MAINNET });
  });

  it("should fetch public address", async function () {
    const verifier = "tkey-google-sapphire-mainnet"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.equal("0x327b2742768B436d09153429E762FADB54413Ded");
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xb1a49C6E50a1fC961259a8c388EAf5953FA5152b",
        X: "a9f5a463aefb16e90f4cbb9de4a5b6b7f6c6a3831cefa0f20cccb9e7c7b01c20",
        Y: "3376c6734da57ab3a67c7792eeea20707d16992dd2c827a59499f4c056b00d08",
      },
      finalKeyData: {
        evmAddress: "0x327b2742768B436d09153429E762FADB54413Ded",
        X: "1567e030ca76e520c180c50bc6baed07554ebc35c3132495451173e9310d8be5",
        Y: "123c0560757ffe6498bf2344165d0f295ea74eb8884683675e5f17ae7bb41cdb",
      },
      metadata: {
        pubNonce: {
          X: "56e803db7710adbfe0ecca35bc6a3ad27e966df142e157e76e492773c88e8433",
          Y: "f4168594c1126ca731756dd480f992ee73b0834ba4b787dd892a9211165f50a3",
        },
        nonce: new BN("0", "hex"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it.skip("should be able to import a key for a new user", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const privKeyBuffer = generatePrivate();
    const privHex = privKeyBuffer.toString("hex");
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

  it("should be able to key assign", async function () {
    const verifier = "tkey-google-sapphire-mainnet"; // any verifier
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oAuthKeyData, metadata } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalKeyData.evmAddress).to.not.equal("");
    expect(finalKeyData.evmAddress).to.not.equal(null);
    expect(oAuthKeyData.evmAddress).to.not.equal("");
    expect(oAuthKeyData.evmAddress).to.not.equal(null);
    expect(metadata.typeOfUser).to.equal("v2");
    expect(metadata.upgraded).to.equal(false);
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

  it("should fetch pub address of tss verifier id", async function () {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.be.equal("0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A");
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A",
        X: "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29",
        Y: "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb",
      },
      finalKeyData: {
        evmAddress: "0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A",
        X: "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29",
        Y: "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb",
      },
      metadata: {
        pubNonce: undefined,
        nonce: new BN(0),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: result.nodesData.nodeIndexes },
    });
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
    expect(result.finalKeyData.evmAddress).to.equal("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB");
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
        X: "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
        Y: "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c",
      },
      finalKeyData: {
        evmAddress: "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
        X: "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
        Y: "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90",
      },
      metadata: {
        pubNonce: {
          X: "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
          Y: "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f",
        },
        nonce: new BN("0", "hex"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should fetch user type and public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.evmAddress).to.equal("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB");
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        evmAddress: "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
        X: "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
        Y: "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c",
      },
      finalKeyData: {
        evmAddress: "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
        X: "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
        Y: "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90",
      },
      metadata: {
        pubNonce: {
          X: "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
          Y: "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f",
        },
        nonce: new BN("0", "hex"),
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
    expect(result.finalKeyData.privKey).to.be.equal("13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6");
    expect(result.metadata.serverTimeOffset).lessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      finalKeyData: {
        evmAddress: "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
        X: "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
        Y: "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90",
        privKey: "13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6",
      },
      oAuthKeyData: {
        evmAddress: "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
        X: "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
        Y: "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c",
        privKey: "d768b327cbde681e5850a7d14f1c724bba2b8f8ab7fe2b1c4f1ee6979fc25478",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
          Y: "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f",
        },
        nonce: new BN("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(result.finalKeyData.privKey).to.be.equal("dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419");
    expect(result.metadata.serverTimeOffset).lessThan(20);

    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      finalKeyData: {
        evmAddress: "0x70520A7F04868ACad901683699Fa32765C9F6871",
        X: "adff099b5d3b1e238b43fba1643cfa486e8d9e8de22c1e6731d06a5303f9025b",
        Y: "21060328e7889afd303acb63201b6493e3061057d1d81279931ab4a6cabf94d4",
        privKey: "dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419",
      },
      oAuthKeyData: {
        evmAddress: "0x925c97404F1aBdf4A8085B93edC7B9F0CEB3C673",
        X: "5cd8625fc01c7f7863a58c914a8c43b2833b3d0d5059350bab4acf6f4766a33d",
        Y: "198a4989615c5c2c7fa4d49c076ea7765743d09816bb998acb9ff54f5db4a391",
        privKey: "90a219ac78273e82e36eaa57c15f9070195e436644319d6b9aea422bb4d31906",
      },
      sessionData: { sessionTokenData: result.sessionData.sessionTokenData, sessionAuthKey: result.sessionData.sessionAuthKey },
      metadata: {
        pubNonce: {
          X: "ab4d287c263ab1bb83c37646d0279764e50fe4b0c34de4da113657866ddcf318",
          Y: "ad35db2679dfad4b62d77cf753d7b98f73c902e5d101cc2c3c1209ece6d94382",
        },
        nonce: new BN("4f1181d8689f0d0960f1a6f9fe26e03e557bdfba11f4b6c8d7b1285e9c271b13", "hex"),
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

  it("should be able to update the `sessionTime` of the token signature data", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";

    const customSessionTime = 3600;
    TorusUtils.setSessionTime(customSessionTime); // 1hr

    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    );

    const signatures = result.sessionData.sessionTokenData.map((s) => ({ data: s.token, sig: s.signature }));

    const parsedSigsData = signatures.map((s) => JSON.parse(atob(s.data)));
    parsedSigsData.forEach((ps) => {
      const sessionTime = ps.exp - Math.floor(Date.now() / 1000);
      expect(sessionTime).greaterThan(customSessionTime - 5); // giving a latency leeway of 5 seconds
      expect(sessionTime).lessThanOrEqual(customSessionTime);
    });
  });
});
