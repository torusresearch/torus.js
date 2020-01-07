import { ec } from 'elliptic'
import eccrypto from 'eccrypto'
import { keccak256, toChecksumAddress } from 'web3-utils'
import BN from 'bn.js'

import { generateJsonRPCObject, post } from './httpHelpers'
import { Some } from './some'

// Swallow individual fetch errors to handle node failures
// catch only logic errors
class Torus {
  constructor() {
    this.ec = ec('secp256k1')
  }

  retrieveShares(endpoints, indexes, verifier, verifierParams, idToken) {
    return new Promise((resolve, reject) => {
      const promiseArr = []
      /* 
      CommitmentRequestParams struct {
        MessagePrefix      string `json:"messageprefix"`
        TokenCommitment    string `json:"tokencommitment"`
        TempPubX           string `json:"temppubx"`
        TempPubY           string `json:"temppuby"`
        Timestamp          string `json:"timestamp"`
        VerifierIdentifier string `json:"verifieridentifier"`
      } 
      */
      const tmpKey = eccrypto.generatePrivate()
      const pubKey = eccrypto.getPublic(tmpKey).toString('hex')
      const pubKeyX = pubKey.slice(2, 66)
      const pubKeyY = pubKey.slice(66)
      const tokenCommitment = keccak256(idToken)
      for (var i = 0; i < endpoints.length; i++) {
        var p = post(
          endpoints[i],
          generateJsonRPCObject('CommitmentRequest', {
            messageprefix: 'mug00',
            tokencommitment: tokenCommitment.slice(2),
            temppubx: pubKeyX,
            temppuby: pubKeyY,
            timestamp: (Date.now() - 2000).toString().slice(0, 10),
            verifieridentifier: verifier
          })
        ).catch(_ => {})
        promiseArr.push(p)
      }
      Promise.all(promiseArr)
        .then(responses => {
          const promiseArrRequest = []
          /*
          ShareRequestParams struct {
            Item []bijson.RawMessage `json:"item"`
          }
          ShareRequestItem struct {
            IDToken            string          `json:"idtoken"`
            NodeSignatures     []NodeSignature `json:"nodesignatures"`
            VerifierIdentifier string          `json:"verifieridentifier"`
          }
          NodeSignature struct {
            Signature   string
            Data        string
            NodePubKeyX string
            NodePubKeyY string
          }
          CommitmentRequestResult struct {
            Signature string `json:"signature"`
            Data      string `json:"data"`
            NodePubX  string `json:"nodepubx"`
            NodePubY  string `json:"nodepuby"`
          }
          */
          var nodeSigs = []
          for (var i = 0; i < responses.length; i++) {
            if (responses[i]) nodeSigs.push(responses[i].result)
          }
          for (i = 0; i < endpoints.length; i++) {
            var p = post(
              endpoints[i],
              generateJsonRPCObject('ShareRequest', {
                encrypted: 'yes',
                item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier }]
              })
            ).catch(_ => {})
            promiseArrRequest.push(p)
          }
          return Promise.all(promiseArrRequest)
        })
        .then(async shareResponses => {
          /*
          ShareRequestResult struct {
            Keys []KeyAssignment
          }
                  / KeyAssignmentPublic -
          type KeyAssignmentPublic struct {
          	Index     big.Int
          	PublicKey common.Point
          	Threshold int
          	Verifiers map[string][]string // Verifier => VerifierID
          }

          // KeyAssignment -
          type KeyAssignment struct {
          	KeyAssignmentPublic
          	Share big.Int // Or Si
          }
          */
          var sharePromises = []
          var nodeIndex = []
          for (var i = 0; i < shareResponses.length; i++) {
            if (shareResponses[i] && shareResponses[i].result && shareResponses[i].result.keys && shareResponses[i].result.keys.length > 0) {
              shareResponses[i].result.keys.sort((a, b) => new BN(a.Index, 16).cmp(new BN(b.Index, 16)))
              if (shareResponses[i].result.keys[0].Metadata) {
                const metadata = {
                  ephemPublicKey: Buffer.from(shareResponses[i].result.keys[0].Metadata.ephemPublicKey, 'hex'),
                  iv: Buffer.from(shareResponses[i].result.keys[0].Metadata.iv, 'hex'),
                  mac: Buffer.from(shareResponses[i].result.keys[0].Metadata.mac, 'hex'),
                  mode: Buffer.from(shareResponses[i].result.keys[0].Metadata.mode, 'hex')
                }
                sharePromises.push(
                  eccrypto.decrypt(tmpKey, {
                    ...metadata,
                    ciphertext: Buffer.from(atob(shareResponses[i].result.keys[0].Share).padStart(64, '0'), 'hex')
                  })
                )
              } else {
                sharePromises.push(Promise.resolve(Buffer.from(shareResponses[i].result.keys[0].Share.padStart(64, '0'), 'hex')))
              }
              nodeIndex.push(new BN(indexes[i], 16))
            }
          }

          const sharesResolved = await Promise.all(sharePromises)
          var shares = sharesResolved.map(x => new BN(x))
          var privateKey = this.lagrangeInterpolation(shares.slice(0, 3), nodeIndex.slice(0, 3))
          var ethAddress = this.generateAddressFromPrivKey(privateKey)
          resolve({
            ethAddress,
            privKey: privateKey.toString('hex', 64)
          })
        })
        .catch(err => {
          reject(err)
        })
    })
  }

  lagrangeInterpolation(shares, nodeIndex) {
    if (shares.length !== nodeIndex.length) {
      return null
    }
    var secret = new BN(0)
    for (let i = 0; i < shares.length; i++) {
      var upper = new BN(1)
      var lower = new BN(1)
      for (let j = 0; j < shares.length; j++) {
        if (i !== j) {
          upper = upper.mul(nodeIndex[j].neg())
          upper = upper.umod(this.ec.curve.n)
          let temp = nodeIndex[i].sub(nodeIndex[j])
          temp = temp.umod(this.ec.curve.n)
          lower = lower.mul(temp).umod(this.ec.curve.n)
        }
      }
      let delta = upper.mul(lower.invm(this.ec.curve.n)).umod(this.ec.curve.n)
      delta = delta.mul(shares[i]).umod(this.ec.curve.n)
      secret = secret.add(delta)
    }
    return secret.umod(this.ec.curve.n)
  }

  generateAddressFromPrivKey(privateKey) {
    var key = this.ec.keyFromPrivate(privateKey.toString('hex', 64), 'hex')
    var publicKey = key
      .getPublic()
      .encode('hex')
      .slice(2)
    var ethAddressLower = '0x' + keccak256(Buffer.from(publicKey, 'hex')).slice(64 - 38) // remove 0x
    var ethAddress = toChecksumAddress(ethAddressLower)
    return ethAddress
  }

  getPubKeyAsync(endpoints, { verifier, verifierId }) {
    return new Promise((resolve, reject) => {
      const lookupPromises = endpoints.map(x =>
        post(
          x,
          generateJsonRPCObject('VerifierLookupRequest', {
            verifier,
            verifier_id: verifierId.toString().toLowerCase()
          })
        )
      )
      Some(lookupPromises, lookupPromises / 2 + 1)
        .catch(_ => {})
        .then(lookupShares => {
          if (lookupShares.every(x => Object.prototype.hasOwnProperty.call(x, 'error'))) {
            return post(
              endpoints[Math.floor(Math.random() * endpoints.length)],
              generateJsonRPCObject('KeyAssign', {
                verifier,
                verifier_id: verifierId.toString().toLowerCase()
              })
            )
          } else if (lookupShares.every(x => x.result === lookupShares[0].result)) {
            return Some(lookupPromises, lookupPromises / 2 + 1)
          } else {
            return reject(new Error('node results do not match'))
          }
        })
        .catch(_ => {})
        .then(lookupShares => {
          if (lookupShares.every(x => x.result === lookupShares[0].result)) {
            var ethAddress = lookupShares[0].result.keys[0].address
            resolve(ethAddress)
          } else {
            reject(new Error('node results do not match'))
          }
        })
        .catch(err => {
          reject(err)
        })
    })
  }
}

export default Torus
