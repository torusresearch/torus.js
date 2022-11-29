// import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import { ec as EC } from "elliptic";
import faker from "faker";
import { keccak256 } from "web3-utils";

import { TorusPublicKey } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "sapphiretest329@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe.only("torus utils sapphire", function () {
  let torus: TorusUtils;
  let sk: string;
  let pk: TorusPublicKey;

  const torusNodeEndpoints = [
    "https://lrc-edwards-1.k8.authnetwork.dev/sss/jrpc",
    "https://lrc-edwards-2.k8.authnetwork.dev/sss/jrpc",
    "https://lrc-edwards-3.k8.authnetwork.dev/sss/jrpc",
    "https://lrc-edwards-4.k8.authnetwork.dev/sss/jrpc",
    "https://lrc-edwards-5.k8.authnetwork.dev/sss/jrpc",
  ];

  before("one time execution before all tests", async function () {
    torus = new TorusUtils({
      signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      metadataHost: "https://lrc-edwards-1.k8.authnetwork.dev/metadata",
      network: "cyan",
      enableOneKey: true,
    });

    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    pk = (await torus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    sk = retrieveSharesResponse.privKey;
  });

  it("should be able to construct public key from private key", async function () {
    const ec = new EC("ed25519");
    const pkFromSk = ec.keyFromPrivate(sk).getPublic();
    expect(pk.X).to.be.equal(pkFromSk.getX().toString(16));
    expect(pk.Y).to.be.equal(pkFromSk.getY().toString(16));
  });

  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = (await torus.getPublicAddress(torusNodeEndpoints, verifierDetails, true)) as TorusPublicKey;
    expect(publicAddress.address).to.be.equal(pk.address);
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal("");
    expect(publicAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal(sk);
  });

  it.skip("should be able to aggregate login", async function () {
    const email = faker.internet.email();
    const idToken = generateIdToken(email, "ES256");
    const hashedIdToken = keccak256(idToken);
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
