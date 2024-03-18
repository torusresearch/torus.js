import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import NodeManager from "@toruslabs/fetch-node-details";
import BN from "bn.js";
import { expect } from "chai";
import faker from "faker";

import { keccak256 } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "ed25519testuser@tor.us";
const TORUS_TEST_EMAIL_HASHED = "ed25519testuserhash@tor.us";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierided25519@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe.only("torus utils ed25519 sapphire devnet", function () {
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
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: "Willa_Funk1@gmail.com" };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).eql("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      oAuthKeyData: {
        walletAddress: "A5fzWVa6YDLpsZ3d8Zg6qwB9dLgGMw1UbtRctZeXy89n",
        X: "175d1cb8a3fe85a6079d1d1892ef0421cc5f692ebda617bc61f1c8891b1fbcb6",
        Y: "397d5c7c0c1f543d83c0a8be2d2824ca4298ff5b34714c2982dae82beb97eb86",
      },
      finalKeyData: {
        walletAddress: "3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM",
        X: "664cf57e06afdbd897a8be4ce6e572bd836e306611597d30be31e6250571e87a",
        Y: "4cf0a015e6b97a36f513025734a03d0ff429385574b04eb4a8db520f57137e24",
      },
      metadata: {
        pubNonce: {
          X: "439fe891f2f06a93f533aec3c2a1b0b247b7a6e52de4c8b943529e95224979b8",
          Y: "51ed278447e030a8fca05362189f358c9d7eaff7818036b8c6c828e3eef40898",
        },
        nonce: new BN("0", "hex"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });
  it("should be able to import a key for a new user", async function () {
    const email = "Willa_Funk1@gmail.com";
    const token = generateIdToken(email, "ES256");
    // const privKeyBuffer = new BN(generatePrivateKey(ec, Buffer));
    // key exported from phantom wallet
    const privHex =
      "0942c4f0dfe419364b716925e1138977b66844c96873aeaa02efb7bbc7d82628247e13570f52dba8b44eb074553829f40f3da034570213f5367ab9e615a0f04c";
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
        privKey: "082d9495b9147bac19699ae3109606cbaeea1bf65772b6d7e652ebf77f67f78363b2efd7cf8c4bba1c56a830404ee1841c9039f6f7a6359906e150c593c082f0",
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
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).to.not.equal("");
    expect(result.finalKeyData.walletAddress).to.not.equal(null);
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
    expect(result.finalKeyData.privKey).to.be.equal(
      "ea39cc89d2d8b8403858d1c518fe82e2500cc83e472ba86d006323b57835a5197139cf3a4c9b145471ac5efcdcbeab630bfa7a387e672b4940f18d686effa30f"
    );
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
        walletAddress: "FucMH9d3YMJD2qh2ums4Xqfw5Htc8PR6pYUzQnr2xgmK",
        X: "161da0ab7a991abb8981968de76652880f09e479d1df4a15e5f4b537d244f1a5",
        Y: "0effa9486c130b7e25e4181023c92ea69f1ee0ee835a0735bd7b446cfbc97ddd",
      },
      finalKeyData: {
        walletAddress: "74stJxXes7SP6T4uH2wRPiDQaeSc6dpEHdh1RtsFYsGQ",
        X: "361660e9eb925988579d824ff6f4ea6cc8f35399b118f227ab233081aa72d50e",
        Y: "3dbabd3baae7ad031e048d0b8f42efe1917d9291fd6a7d9476820dc04166245a",
      },
      metadata: {
        pubNonce: {
          X: "51b5cc6c5d917b97b28f0472bde7b04f67a1ce6745cd374d2586cc088a49b887",
          Y: "39e4d6c342716e1bd9fca5553714d3e147a148c2b1eba5a77207db4a3246c205",
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
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: testEmail });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      torusNodeEndpoints,
      nodeDetails.torusIndexes,
      HashEnabledVerifier,
      { verifier_id: testEmail },
      token,
      nodeDetails.torusNodePub
    );
    delete result.metadata.serverTimeOffset;
    expect(result).eql({
      finalKeyData: {
        walletAddress: "74stJxXes7SP6T4uH2wRPiDQaeSc6dpEHdh1RtsFYsGQ",
        X: "361660e9eb925988579d824ff6f4ea6cc8f35399b118f227ab233081aa72d50e",
        Y: "3dbabd3baae7ad031e048d0b8f42efe1917d9291fd6a7d9476820dc04166245a",
        privKey: "0e12e0192aeb716da5d836eec85a97b13e227843d7a897656c520c119f7eb4af5a246641c00d8276947d6afd91927d91e1ef428f0b8d041e03ade7aa3bbdba3d",
      },
      oAuthKeyData: {
        walletAddress: "FucMH9d3YMJD2qh2ums4Xqfw5Htc8PR6pYUzQnr2xgmK",
        X: "161da0ab7a991abb8981968de76652880f09e479d1df4a15e5f4b537d244f1a5",
        Y: "0effa9486c130b7e25e4181023c92ea69f1ee0ee835a0735bd7b446cfbc97ddd",
        privKey: "0bd77284601dbc3a5c0c6f9829f4d0d0f2d87d439014042b13953724e4d49db8",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "51b5cc6c5d917b97b28f0472bde7b04f67a1ce6745cd374d2586cc088a49b887",
          Y: "39e4d6c342716e1bd9fca5553714d3e147a148c2b1eba5a77207db4a3246c205",
        },
        nonce: new BN("7bad1284d129014a24737a275021085c1789b03d5b7ee37d1f7a47eeb23877f", "hex"),
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
