// import NodeManager from '@toruslabs/fetch-node-details'
import { expect } from 'chai'
import faker from 'faker'
import Web3EthContract from "web3-eth-contract";
import { toHex } from "web3-utils";

import TorusUtils from '../src/torus'
import { generateIdToken } from './generate'
const abi = [
  {
    "constant": true,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      }
    ],
    "name": "getEpochInfo",
    "outputs": [
      {
        "name": "id",
        "type": "uint256"
      },
      {
        "name": "n",
        "type": "uint256"
      },
      {
        "name": "k",
        "type": "uint256"
      },
      {
        "name": "t",
        "type": "uint256"
      },
      {
        "name": "nodeList",
        "type": "address[]"
      },
      {
        "name": "prevEpoch",
        "type": "uint256"
      },
      {
        "name": "nextEpoch",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "epochInfo",
    "outputs": [
      {
        "name": "id",
        "type": "uint256"
      },
      {
        "name": "n",
        "type": "uint256"
      },
      {
        "name": "k",
        "type": "uint256"
      },
      {
        "name": "t",
        "type": "uint256"
      },
      {
        "name": "prevEpoch",
        "type": "uint256"
      },
      {
        "name": "nextEpoch",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      },
      {
        "name": "nodeAddress",
        "type": "address"
      },
      {
        "name": "allowed",
        "type": "bool"
      }
    ],
    "name": "updateWhitelist",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      }
    ],
    "name": "getNodes",
    "outputs": [
      {
        "name": "",
        "type": "address[]"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "uint256"
      },
      {
        "name": "",
        "type": "address"
      }
    ],
    "name": "whitelist",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "uint256"
      },
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "name": "pssStatus",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "oldEpoch",
        "type": "uint256"
      },
      {
        "name": "newEpoch",
        "type": "uint256"
      },
      {
        "name": "status",
        "type": "uint256"
      }
    ],
    "name": "updatePssStatus",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [],
    "name": "renounceOwnership",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      },
      {
        "name": "nodeAddress",
        "type": "address"
      }
    ],
    "name": "isWhitelisted",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "name": "nodeDetails",
    "outputs": [
      {
        "name": "declaredIp",
        "type": "string"
      },
      {
        "name": "position",
        "type": "uint256"
      },
      {
        "name": "pubKx",
        "type": "uint256"
      },
      {
        "name": "pubKy",
        "type": "uint256"
      },
      {
        "name": "tmP2PListenAddress",
        "type": "string"
      },
      {
        "name": "p2pListenAddress",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      },
      {
        "name": "nodeAddress",
        "type": "address"
      }
    ],
    "name": "nodeRegistered",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "owner",
    "outputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "isOwner",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      },
      {
        "name": "n",
        "type": "uint256"
      },
      {
        "name": "k",
        "type": "uint256"
      },
      {
        "name": "t",
        "type": "uint256"
      },
      {
        "name": "nodeList",
        "type": "address[]"
      },
      {
        "name": "prevEpoch",
        "type": "uint256"
      },
      {
        "name": "nextEpoch",
        "type": "uint256"
      }
    ],
    "name": "updateEpoch",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "nodeAddress",
        "type": "address"
      }
    ],
    "name": "getNodeDetails",
    "outputs": [
      {
        "name": "declaredIp",
        "type": "string"
      },
      {
        "name": "position",
        "type": "uint256"
      },
      {
        "name": "tmP2PListenAddress",
        "type": "string"
      },
      {
        "name": "p2pListenAddress",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "epoch",
        "type": "uint256"
      },
      {
        "name": "declaredIp",
        "type": "string"
      },
      {
        "name": "pubKx",
        "type": "uint256"
      },
      {
        "name": "pubKy",
        "type": "uint256"
      },
      {
        "name": "tmP2PListenAddress",
        "type": "string"
      },
      {
        "name": "p2pListenAddress",
        "type": "string"
      }
    ],
    "name": "listNode",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "oldEpoch",
        "type": "uint256"
      },
      {
        "name": "newEpoch",
        "type": "uint256"
      }
    ],
    "name": "getPssStatus",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "newOwner",
        "type": "address"
      }
    ],
    "name": "transferOwnership",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "name": "publicKey",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "epoch",
        "type": "uint256"
      },
      {
        "indexed": false,
        "name": "position",
        "type": "uint256"
      }
    ],
    "name": "NodeListed",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "previousOwner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "newOwner",
        "type": "address"
      }
    ],
    "name": "OwnershipTransferred",
    "type": "event"
  }
]

// export const abi = [
//   {
//     constant: true,
//     inputs: [],
//     name: "currentEpoch",
//     outputs: [
//       {
//         internalType: "uint256",
//         name: "",
//         type: "uint256",
//       },
//     ],
//     payable: false,
//     stateMutability: "view",
//     type: "function",
//   },
//   {
//     constant: true,
//     inputs: [
//       {
//         internalType: "uint256",
//         name: "epoch",
//         type: "uint256",
//       },
//     ],
//     name: "getEpochInfo",
//     outputs: [
//       {
//         internalType: "uint256",
//         name: "id",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "n",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "k",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "t",
//         type: "uint256",
//       },
//       {
//         internalType: "address[]",
//         name: "nodeList",
//         type: "address[]",
//       },
//       {
//         internalType: "uint256",
//         name: "prevEpoch",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "nextEpoch",
//         type: "uint256",
//       },
//     ],
//     payable: false,
//     stateMutability: "view",
//     type: "function",
//   },
//   {
//     constant: true,
//     inputs: [
//       {
//         internalType: "address",
//         name: "nodeAddress",
//         type: "address",
//       },
//     ],
//     name: "getNodeDetails",
//     outputs: [
//       {
//         internalType: "string",
//         name: "declaredIp",
//         type: "string",
//       },
//       {
//         internalType: "uint256",
//         name: "position",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "pubKx",
//         type: "uint256",
//       },
//       {
//         internalType: "uint256",
//         name: "pubKy",
//         type: "uint256",
//       },
//       {
//         internalType: "string",
//         name: "tmP2PListenAddress",
//         type: "string",
//       },
//       {
//         internalType: "string",
//         name: "p2pListenAddress",
//         type: "string",
//       },
//     ],
//     payable: false,
//     stateMutability: "view",
//     type: "function",
//   },
// ];

class NodeManager {
  _currentEpoch = "1";

  _torusNodeEndpoints = []

  _torusNodePub = [{}
  ];

  _torusIndexes = [1, 2, 3, 4, 5, 6, 7, 8, 9];

  _network = ""

  nodeListAddress;

  updated;
  nodeListContract;

  constructor({ network = "mainnet", proxyAddress = "0xC4c6463988bD5B9B4B633Ff8A295403e4EE166CA" } = {}) {
    let url;
    try {
      const localUrl = new URL(network);
      url = localUrl.href;
    } catch (_) {
      const projectId = process.env.INFURA_PROJECT_ID;
      url = `https://${network}.infura.io/v3/${projectId}`;
    }
    Web3EthContract.setProvider(url);
    this.nodeListContract = new Web3EthContract(abi, proxyAddress);
    this.nodeListAddress = proxyAddress;
    this.updated = false;
    this._network = network;
  }

  get _nodeDetails() {
    return {
      currentEpoch: this._currentEpoch,
      nodeListAddress: this.nodeListAddress,
      torusNodeEndpoints: this._torusNodeEndpoints,
      torusNodePub: this._torusNodePub,
      torusIndexes: this._torusIndexes,
      updated: this.updated,
    };
  }

  getCurrentEpoch(){
    return this.nodeListContract.methods.currentEpoch().call();
  }

  getEpochInfo(epoch) {
    return this.nodeListContract.methods.getEpochInfo(epoch).call();
  }

  async getNodeEndpoint(nodeEthAddress) {
    console.log("actually called this?")
    var res = await this.nodeListContract.methods.nodeDetails(nodeEthAddress).call();
    console.log("nodethaddress", nodeEthAddress, "nodeendpoint", res)
    return res
  }
  
  async getNodeDetails(skip = false, skipPostEpochCheck = false) {
    try {
      const latestEpoch = "1"
      this._currentEpoch = latestEpoch;
      console.log("1")
      const latestEpochInfo = await this.getEpochInfo(latestEpoch);
      console.log("2")
      const indexes = latestEpochInfo.nodeList.map((_, pos) => pos + 1);
      console.log("3")
      this._torusIndexes = indexes;
      console.log("4")

      const nodeEndpointRequests = latestEpochInfo.nodeList.map((nodeEthAddress) => this.getNodeEndpoint(nodeEthAddress));
      console.log("5")
      
      const nodeEndPoints = await Promise.all(nodeEndpointRequests);
      console.log("6", nodeEndPoints)
      const updatedEndpoints = [];
      console.log("7")
      const updatedNodePub = [];
      console.log("8")
      for (let index = 0; index < nodeEndPoints.length; index += 1) {
        console.log("9")
        const endPointElement = nodeEndPoints[index];
        console.log("10")
        const endpoint = `https://${endPointElement.declaredIp.split(":")[0]}/jrpc`;
        console.log("11")
        updatedEndpoints.push(endpoint);
        console.log("12", endPointElement)
        updatedNodePub.push({ X: toHex(endPointElement.pubKx).replace("0x", ""), Y: toHex(endPointElement.pubKy).replace("0x", "") });
        console.log("13")
      }
      this._torusNodeEndpoints = updatedEndpoints;
      this._torusNodePub = updatedNodePub;
      this.updated = true;
      console.log("14")
      return this._nodeDetails;
    } catch (err) {
      console.log("Error", err)
      return this._nodeDetails;
    }
  }

}


describe('torus utils', function () {
  let nodeManager = null
  let torusNodeEndpoints
  let torusNodePub
  let torusIndexes
  const TORUS_TEST_EMAIL = 'hello@tor.us'
  const TORUS_TEST_VERIFIER = 'torus-test-health'
  // const TORUS_TEST_AGGREGATE_VERIFIER = 'torus-test-health-aggregate'
  before('one time execution before all tests', async function () {
    nodeManager = new NodeManager({
      network: 'https://polygon-mainnet.infura.io/v3/f82e5c0474074608b22476858e84dddf',
      proxyAddress: '0x60CBF553CCd3355f452B71A7d261976c208d9170',
    })
    const nodeDetails = await nodeManager.getNodeDetails()
    torusNodeEndpoints = nodeDetails.torusNodeEndpoints
    torusNodePub = nodeDetails.torusNodePub
    torusIndexes = nodeDetails.torusIndexes

    console.log("nodeendpoints", torusNodeEndpoints)
    console.log("pub", torusNodePub)
    console.log("index", torusIndexes)
    // process.exit(0)
  })
  it('should fetch public address', async function () {
    const torus = new TorusUtils()
    const verifier = 'torus-test-health' // any verifier
    const publicAddress = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: TORUS_TEST_EMAIL })
    expect(publicAddress).to.equal('0xCded71b8B667D1e10e2e6aE03746E6396C5c6520')
  })

  // it('should fetch user type and public address', async function () {
  //   const torus = new TorusUtils()
  //   const verifier = 'google-lrc' // any verifier
  //   const { address, typeOfUser } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: TORUS_TEST_EMAIL })
  //   expect(address).to.equal('0xFf5aDad69F4e97AF4D4567e7C333C12df6836a70')
  //   expect(typeOfUser).to.equal('v1')

  //   const v2Verifier = 'tkey-google-lrc'
  //   // 1/1 user
  //   const v2TestEmail = 'somev2user@gmail.com'
  //   const { address: v2Address, typeOfUser: v2UserType } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
  //     verifier: v2Verifier,
  //     verifierId: v2TestEmail,
  //   })
  //   expect(v2Address).to.equal('0xE91200d82029603d73d6E307DbCbd9A7D0129d8D')
  //   expect(v2UserType).to.equal('v2')

  //   // 2/n user
  //   const v2nTestEmail = 'caspertorus@gmail.com'
  //   const { address: v2nAddress, typeOfUser: v2nUserType } = await torus.getUserTypeAndAddress(torusNodeEndpoints, torusNodePub, {
  //     verifier: v2Verifier,
  //     verifierId: v2nTestEmail,
  //   })
  //   expect(v2nAddress).to.equal('0x1016DA7c47A04C76036637Ea02AcF1d29c64a456')
  //   expect(v2nUserType).to.equal('v2')
  // })

  it('should be able to key assign', async function () {
    const verifier = 'torus-test-health' // any verifier
    const torusUtils = new TorusUtils()
    const email = faker.internet.email()
    const publicAddress = await torusUtils.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId: email })
    expect(publicAddress).to.not.equal('')
    expect(publicAddress).to.not.equal(null)
  })

  it('should be able to login', async function () {
    const torusUtils = new TorusUtils()
    const token = generateIdToken(TORUS_TEST_EMAIL, 'ES256')
    const retrieveSharesResponse = await torusUtils.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      TORUS_TEST_VERIFIER,
      { verifier_id: TORUS_TEST_EMAIL },
      token
    )
    expect(retrieveSharesResponse.privKey).to.be.equal('6ee71adb7706b28b6545cf5b1943f51b8a814ff5d48119e6a4a172db8afc8174')
  })

  // it('should be able to aggregate login', async function () {
  //   const torusUtils = new TorusUtils()
  //   const idToken = generateIdToken(TORUS_TEST_EMAIL, 'ES256')
  //   const hashedIdToken = keccak256(idToken)
  //   const retrieveSharesResponse = await torusUtils.retrieveShares(
  //     torusNodeEndpoints,
  //     torusIndexes,
  //     TORUS_TEST_AGGREGATE_VERIFIER,
  //     {
  //       verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
  //       sub_verifier_ids: [TORUS_TEST_VERIFIER],
  //       verifier_id: TORUS_TEST_EMAIL,
  //     },
  //     hashedIdToken.substring(2
  //   )
  //   expect(retrieveSharesResponse.ethAddress).to.be.equal('0x5a165d2Ed4976BD104caDE1b2948a93B72FA91D2')
  // })
})
