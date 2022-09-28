// import NodeManager from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";

// import { keccak256 } from "web3-utils";
import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

const TORUS_TEST_EMAIL = "sapphiretest329@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";

// const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe.only("torus utils sapphire", function () {
  let torus: TorusUtils;

  const torusNodeEndpoints = [
    "https://swaraj-test-coordinator-1.k8.authnetwork.dev/sss/jrpc",
    "https://swaraj-test-coordinator-2.k8.authnetwork.dev/sss/jrpc",
    "https://swaraj-test-coordinator-3.k8.authnetwork.dev/sss/jrpc",
  ];
  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      signerHost: "https://signer-polygon.tor.us/api/sign",
      allowHost: "https://signer-polygon.tor.us/api/allow",
      network: "cyan",
      enableOneKey: true,
    });
  });
  it("should fetch public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.equal("0xa8d7966138191e9505F8Baecf05c73E55A6d212F");
  });

  it("should fetch user type and public address", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { address, typeOfUser } = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails, true);
    expect(address).to.equal("0xa8d7966138191e9505F8Baecf05c73E55A6d212F");
    expect(typeOfUser).to.equal("v2");
  });

  it("should be able to key assign", async function () {
    const email = faker.internet.email();
    // eslint-disable-next-line no-console
    console.log("email", email);
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, verifierDetails);
    expect(publicAddress).to.not.equal("");
    expect(publicAddress).to.not.equal(null);
  });

  it("should be able to login", async function () {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const retrieveSharesResponse = await torus.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token);
    expect(retrieveSharesResponse.privKey).to.be.equal("681f35d6a359365f3f60e23cabced1b69f19ce08677e76cf024e2b1172bc6b66");
  });

  //   it("should be able to aggregate login", async function () {
  //     const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
  //     const hashedIdToken = keccak256(idToken);
  //     const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
  //     const { torusNodeEndpoints, torusIndexes } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
  //     const retrieveSharesResponse = await torus.retrieveShares(
  //       torusNodeEndpoints,
  //       torusIndexes,
  //       TORUS_TEST_AGGREGATE_VERIFIER,
  //       {
  //         verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
  //         sub_verifier_ids: [TORUS_TEST_VERIFIER],
  //         verifier_id: TORUS_TEST_EMAIL,
  //       },
  //       hashedIdToken.substring(2)
  //     );
  //     expect(retrieveSharesResponse.ethAddress).to.be.equal("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04");
  //   });
});
