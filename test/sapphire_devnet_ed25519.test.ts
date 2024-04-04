import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "ed25519testuser@tor.us";
const TORUS_TEST_EMAIL_HASHED = "ed25519testuserhashed19@tor.us";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierided25519@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe("torus utils ed25519 sapphire devnet", function () {
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

  it("should should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: "Willa_Funk11@gmail.com" };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).eql("HHmiJMCAwhyf9ZWNtj7FEKGXeeC2NjUjPobpDKm43yKs");
    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "49yLu8yLqpuCXchzjQSt1tpBz8AP2E9EzzP7a8QtxmTE",
        X: "5d39eba90fafbce150b33b9a60b41e1cfdf9e2640b55bf96b787173d74f8e415",
        Y: "099639b7da35c1f31a44da7399a29d7db8eaa9639582cf7ed80aa4f7216adf2e",
      },
      finalKeyData: {
        walletAddress: "HHmiJMCAwhyf9ZWNtj7FEKGXeeC2NjUjPobpDKm43yKs",
        X: "575203523b34bcfa2c25c428871c421afd69dbcb7375833b52ef264aaa466a81",
        Y: "26f0b1f5740088c2ecf676081b8e2fe5254f1cbb693947ae391af13500d706f2",
      },
      metadata: {
        pubNonce: {
          X: "71bf997547c1ac3f0babee87ebac055e8542863ebb1ba66e8092499eacbffd22",
          Y: "71a0a70c5ae06d7eeb45673d4081fdfc9f29c4acfbbb57bf52a33dd7630599b1",
        },
        nonce: new BN("0", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to import a key for a new user", async function () {
    const email = "Willa_Funk1289@gmail.com";
    const token = generateIdToken(email, "ES256");
    // const privKeyBuffer = new BN(generatePrivateKey(ec, Buffer));
    // key exported from phantom wallet
    const privHex = "BjremmcjdFWexYJWcNSsT3U8ekuq6KnenBCSvxVfx2fQuvWbZQzDtQuAuXtQzcgxNY9CRyVNXJu2W5Rgt7ufQDh";
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
    expect(result.finalKeyData.walletAddress).eql("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
    expect(result.finalKeyData.privKey).to.be.equal(privHex);

    const token1 = generateIdToken(email, "ES256");
    const result1 = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: email },
      token1,
      nodeDetails.torusNodePub
    );
    expect(result1.finalKeyData.walletAddress).eql("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
    expect(result.finalKeyData.privKey).to.be.equal(privHex);

    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, {
      verifier: TORUS_TEST_VERIFIER,
      verifierId: email,
    });
    expect(result2.finalKeyData.walletAddress).eql("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
  });

  it("should be able to login", async function () {
    const testEmail = "edd2519TestUser@example.com";
    const token = generateIdToken(testEmail, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: testEmail });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: testEmail },
      token,
      nodeDetails.torusNodePub
    );

    delete result.metadata.serverTimeOffset;
    delete result.sessionData;
    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "7yZNbrFdLgE1ck8BQvDfNpVsgU5BYXotEoXiasTwdWWr",
        X: "7a5d7618aa6abff0a27fd273cd38ef2f81c19a67c488f65d2587b2d7a744dd70",
        Y: "179de2aa479958f2a744b6a8810a38e27257679d09f183f9aa5b2ff81f40a367",
        privKey: "0325b66f131f040fbd23f8feb9633f10440986c5413063f6dd3f23166503b5ea",
      },
      finalKeyData: {
        walletAddress: "7iBcf5du7C7pCocbvoXHDbNXnzF9hSTNRuRiqfGC56Th",
        X: "738dfd57d80945defc6d3bc4deeeffbcecf344a4186b1e756eae54c5f60a4b63",
        Y: "7082c093c550e1069935a6f7f639901c84e14e4030a8561cba4b8ccfd7efb263",
        privKey: "AV2s1hzK6xWHNPeSaaKiiJtgbDSjTx9LjDN9AtPhf3t7mAzxCjf9mDx25UzPrEHS8HcswFzSx4eSxCEEPmmyyEX",
      },
      metadata: {
        pubNonce: {
          X: "4533a0c1907b12187ab41bceaefee8d62b2709d66b67b51a6f39925bfb543933",
          Y: "6862380e59f04a6bbdb3515ee386af44961b403cc61c7cb9725d2e60d250b82",
        },
        nonce: new BN("da32347189e4a992a9367cb8970d741fff3febccd9d92bb5ac247d97dc5c510", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, {
      verifier: TORUS_TEST_VERIFIER,
      verifierId: testEmail,
    });
    expect(result2.finalKeyData.walletAddress).eql(result.finalKeyData.walletAddress);
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    const result2 = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: email },
      token,
      nodeDetails.torusNodePub
    );
    expect(result.finalKeyData.walletAddress).to.equal(result2.finalKeyData.walletAddress);
  });

  it("should be able to login a new user with non dkg keys", async function () {
    const email = `${faker.internet.email()}`;
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: email },
      token,
      nodeDetails.torusNodePub,
      {},
      false
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
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token,
      nodeDetails.torusNodePub
    );
    expect(result.finalKeyData.privKey).to.be.equal("5gcMa5vaPupHmFbDLeQR14odwCke5W3pF9y92BuLjFSACKuyNNCAEYfh3yZ7KyVJpZsjjpwZpneshfzB5ae6P89c");
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
    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "8YXTwFuGWc15bYSw7npC9nJpZzg3yoQpYPDe81DuKjGZ",
        X: "0a89d65e3ba433f52aa86c6b1b832501dea6200a178ec1d1f2a17d556b551cba",
        Y: "7ed3af68be167f590faec6a951c920730b760dd8f11af6a708dde3cc80421570",
      },
      finalKeyData: {
        walletAddress: "8YXTwFuGWc15bYSw7npC9nJpZzg3yoQpYPDe81DuKjGZ",
        X: "0a89d65e3ba433f52aa86c6b1b832501dea6200a178ec1d1f2a17d556b551cba",
        Y: "7ed3af68be167f590faec6a951c920730b760dd8f11af6a708dde3cc80421570",
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
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      TORUS_TEST_VERIFIER,
      { extended_verifier_id: tssVerifierId, verifier_id: email },
      token,
      nodeDetails.torusNodePub
    );
    expect(result.finalKeyData.privKey).to.not.equal(null);
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.eql(new BN("0"));
    expect(result.metadata.upgraded).to.equal(true);
  });

  it("should fetch public address when verifierID hash enabled", async function () {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL_HASHED };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    delete result.metadata.serverTimeOffset;

    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "DybMLmBwiPqt8GXpDW2MwHi5ZqEtrbgxgwcf7shPdTWg",
        X: "45c531429896ab89078789018b21639dab308b7d3952d9df243177e60fc0eb1f",
        Y: "6155cf9bb00f8eedf398361c2140a5ed3fe2b3c51b883e757addcb06e09bcbc0",
      },
      finalKeyData: {
        walletAddress: "HK9Xo2UgjuMNxBi6WxX76hfQm9oTtJdDUSGKFhzGQiSo",
        X: "6002549f42c1f3504652ce4b3fb1cbff4f1eaa1b66551313dd9c44d48b31a63d",
        Y: "44af643f9200d11c5f60212de9470f92806df18eeea730a8736e4570611761f2",
      },
      metadata: {
        pubNonce: {
          X: "4cc875975c4ed6fed34758eab0be8954c50decbe736f85b3c5011f5035dd9e27",
          Y: "233fe212cf0d6033be989f9dd5ffd5dfe77f0c3340984fcc5b0dd745bdfded12",
        },
        nonce: new BN("0", "hex"),
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login when verifierID hash enabled", async function () {
    const testEmail = TORUS_TEST_EMAIL_HASHED;
    const token = generateIdToken(testEmail, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL_HASHED });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      HashEnabledVerifier,
      { verifier_id: TORUS_TEST_EMAIL_HASHED },
      token,
      nodeDetails.torusNodePub
    );
    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      finalKeyData: {
        walletAddress: "HK9Xo2UgjuMNxBi6WxX76hfQm9oTtJdDUSGKFhzGQiSo",
        X: "6002549f42c1f3504652ce4b3fb1cbff4f1eaa1b66551313dd9c44d48b31a63d",
        Y: "44af643f9200d11c5f60212de9470f92806df18eeea730a8736e4570611761f2",
        privKey: "2SDsHqpEGTszmk73SyFu1tR85bK2kt7HmnBercBSiBZpHpYHBiqpquG8ARhRuDWXGquTM7NVRva3xFMSJ8sd2aQ3",
      },
      oAuthKeyData: {
        walletAddress: "DybMLmBwiPqt8GXpDW2MwHi5ZqEtrbgxgwcf7shPdTWg",
        X: "45c531429896ab89078789018b21639dab308b7d3952d9df243177e60fc0eb1f",
        Y: "6155cf9bb00f8eedf398361c2140a5ed3fe2b3c51b883e757addcb06e09bcbc0",
        privKey: "0423cd18b36b862054489ad706d9be0226204af69b0407907dc1f3ee9ca72b7a",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "4cc875975c4ed6fed34758eab0be8954c50decbe736f85b3c5011f5035dd9e27",
          Y: "233fe212cf0d6033be989f9dd5ffd5dfe77f0c3340984fcc5b0dd745bdfded12",
        },
        nonce: new BN("8ff7137ce3f5648b8722779e0d3c153bf76042800783bd6793f38672d8c129d", "hex"),
        typeOfUser: "v2",
        upgraded: false,
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
      hashedIdToken.substring(2),
      nodeDetails.torusNodePub
    );
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.oAuthKeyData.walletAddress).to.not.equal(null);
    expect(result.metadata.typeOfUser).to.equal("v2");
    expect(result.metadata.nonce).to.not.equal(null);
    expect(result.metadata.upgraded).to.equal(false);
  });
});
