import FetchNodeDetails from "@toruslabs/fetch-node-details";
import { expect } from "chai";
import faker from "faker";
import { keccak256 } from "web3-utils";
import { generatePrivate, getPublicCompressed } from "@toruslabs/eccrypto";


import TorusUtils from "../src/torus";
import { generateIdToken } from "./helpers";

// const TORUS_NODE_MANAGER = new FetchNodeDetails({
//   network: "ropsten",
//   proxyAddress: "0x6258c9d6c12ed3edda59a1a6527e469517744aa7",
// });
// const TORUS_TEST_EMAIL = "hello@tor.us";
// const TORUS_TEST_VERIFIER = "torus-test-health";
// const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";


describe("torus YOIUIOUWROIEU", function () {
  let torus;

  beforeEach("one time execution before all tests", async function () {
    torus = new TorusUtils({
      enableOneKey: true,
      network: "testnet",
    });
  });

  it("generate some keys", async function () {
    for (let i = 0; i < 3; i ++) {
      const tmpKey = generatePrivate()
      console.log(tmpKey.toString("hex"))
      console.log("PUBKEY \n",getPublicCompressed(tmpKey).toString("hex"))

    }
  })


  it("should be able to do full flow", async function () {
    const verifierContract = "5EXwNCZMSVsjuuC4FqrPC5XHm7hHyq1CBLAqxKBKiBa8Rfmi"; // replacement for verifierName/ identifier
    const mockToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik9EYzFSVVV6UkRFeU56WXpPREZHUXpKRk5ERkJSVEEyTXpBMk1qbEZOVU01TVRWRk1EVTRNUSJ9.eyJuaWNrbmFtZSI6ImxlbnRhbjEwMjkiLCJuYW1lIjoibGVudGFuMTAyOUBnbWFpbC5jb20iLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvNTFhNjU1YTRmYjM0MDkxNzFiNWE2MjM4YzA0ZjAyYjE_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZsZS5wbmciLCJ1cGRhdGVkX2F0IjoiMjAyMC0wNS0wNFQwMTo0MDowNC4xOTVaIiwiZW1haWwiOiJsZW50YW4xMDI5QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL2xlbnRhbi5hdXRoMC5jb20vIiwic3ViIjoiZW1haWx8NWVhNmE1MjA1ODBhMWQ5YWY0MTgzMDQ4IiwiYXVkIjoiTFBEVUdnU3FOUDVtU3hsbEdQMFRFZ0p3UnJOVTBsVkgiLCJpYXQiOjE1ODg1NTY0MDUsImV4cCI6MTU4ODYxNjQwNSwibm9uY2UiOiJvVWY2dzJFZkhvenJEcnBCX3lURnQuZjBDekowY2FqREFGOUV6YXE4Y043In0.TNtgcW7dPF7CG_nW3G3sr8tG0Fu7ZinMy92XuZ6SYuFBEvgA_qhJa9l-df10W5zUcm-LcFcZnOn_5UckRxNV3wNYpcFEX6MVARuTG0eo26TwCvDiTr7wLsqtLJ0ZzuKElHARAVBnmi8_8alTHrbuoV-FR_FzUozEAb5TlnjXHn08-IF578etUCjJU7evT3UTU0ThGTIozNAIGsCuUS1kVuYxtL2n49m2nvIRvNhFzJ5mOPwz1Ruu0KFbdBZQjJ3vH-l7aJXuRW52_RU--QSf2lZ8Giig8s0oys7WmfbcZ-8Z-eTsfbDrWqp2TtqDcxVFxbH46NUaoPNYizZw0rZW2A";
    const endpoints = ["http://[::1]:8800","http://[::1]:8801","http://[::1]:8802","http://[::1]:8803"];
    // const email = faker.internet.email();
    const verifierDetails = { verifier: verifierContract, verifierId: "email|5ea6a520580a1d9af4183048" };
    // const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
     // const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    //  torusNodePub
     await torus.retrieveShares(endpoints, verifierContract, verifierDetails, mockToken, true);
    // expect(publicAddress.typeOfUser).to.equal("v2");
  });
});
