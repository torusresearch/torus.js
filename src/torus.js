import { ec } from 'elliptic'
import eccrypto from 'eccrypto'
import { keccak256, toChecksumAddress } from 'web3-utils'
import BN from 'bn.js'

import { generateJsonRPCObject, post } from './httpHelpers'
import { Some } from './some'
import { thresholdSame, kCombinations } from './utils'

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
      for (let i = 0; i < endpoints.length; i++) {
        const p = post(
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
      Some(promiseArr, resultArr => {
        const completedRequests = resultArr.filter(x => x)
        if (completedRequests.length >= ~~(endpoints.length / 4) * 3 + 1) {
          return Promise.resolve(resultArr)
        }
        return Promise.reject(new Error('invalid'))
      })
        .then(responses => {
          const promiseArrRequest = []
          const nodeSigs = []
          // Do we only need 3/4th of node commitment requests to pass?
          for (let i = 0; i < responses.length; i++) {
            // no need to check if responses[i] is valid because we only pass the predicate if it's valid
            if (responses[i]) nodeSigs.push(responses[i].result)
          }
          for (let i = 0; i < endpoints.length; i++) {
            const p = post(
              endpoints[i],
              generateJsonRPCObject('ShareRequest', {
                encrypted: 'yes',
                item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier }]
              })
            ).catch(_ => {})
            promiseArrRequest.push(p)
          }
          return Some(promiseArrRequest, async shareResponses => {
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
            const completedRequests = shareResponses.filter(x => x)
            const thresholdPublicKey = thresholdSame(
              shareResponses.map(x => x && x.result && x.result.keys[0].PublicKey),
              ~~(endpoints.length / 2) + 1
            )
            if (completedRequests.length >= ~~(endpoints.length / 2) + 1 && thresholdPublicKey) {
              const sharePromises = []
              const nodeIndex = []
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
                      eccrypto
                        .decrypt(tmpKey, {
                          ...metadata,
                          ciphertext: Buffer.from(atob(shareResponses[i].result.keys[0].Share).padStart(64, '0'), 'hex')
                        })
                        .catch(_ => {})
                    )
                  } else {
                    sharePromises.push(Promise.resolve(Buffer.from(shareResponses[i].result.keys[0].Share.padStart(64, '0'), 'hex')))
                  }
                } else {
                  sharePromises.push(Promise.resolve(undefined))
                }
                nodeIndex.push(new BN(indexes[i], 16))
              }
              const sharesResolved = await Promise.all(sharePromises)
              const decryptedShares = sharesResolved.reduce((acc, curr, index) => {
                if (curr) acc.push({ index: nodeIndex[index], value: new BN(curr) })
                return acc
              }, [])
              const allCombis = kCombinations(decryptedShares.length, ~~(endpoints.length / 2) + 1)
              let privateKey
              for (let j = 0; j < allCombis.length; j++) {
                const currentCombi = allCombis[j]
                const currentCombiShares = decryptedShares.filter((v, index) => currentCombi.includes(index))
                const shares = currentCombiShares.map(x => x.value)
                const indices = currentCombiShares.map(x => x.index)
                const derivedPrivateKey = this.lagrangeInterpolation(shares, indices)
                const pubKey = eccrypto.getPublic(Buffer.from(derivedPrivateKey.toString(16, 64), 'hex')).toString('hex')
                const pubKeyX = pubKey.slice(2, 66)
                const pubKeyY = pubKey.slice(66)
                if (pubKeyX === thresholdPublicKey.X && pubKeyY === thresholdPublicKey.Y) {
                  privateKey = derivedPrivateKey
                  break
                }
              }
              if (privateKey === undefined) {
                throw new Error('could not derive private key')
              }
              const ethAddress = this.generateAddressFromPrivKey(privateKey)
              return {
                ethAddress,
                privKey: privateKey.toString('hex', 64)
              }
            }
            throw new Error('invalid')
          })
        })
        .then(response => {
          resolve(response)
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
      Some(lookupPromises, lookupResults => {
        if (lookupResults.filter(x => x).length >= ~~(endpoints.length / 4) * 3 + 1) {
          return Promise.resolve(lookupResults)
        }
        return Promise.reject(new Error('invalid'))
      })
        .catch(_ => {})
        .then(unfilteredLookupShares => {
          const lookupShares = unfilteredLookupShares.filter(x => x)
          // getting 7 and checking if 5 are the same
          const errorResult = thresholdSame(
            lookupShares.map(x => x && x.error),
            ~~(endpoints.length / 2) + 1
          )
          const keyResult = thresholdSame(
            lookupShares.map(x => x && x.result),
            ~~(endpoints.length / 2) + 1
          )
          if (errorResult) {
            return post(
              endpoints[Math.floor(Math.random() * endpoints.length)],
              generateJsonRPCObject('KeyAssign', {
                verifier,
                verifier_id: verifierId.toString().toLowerCase()
              })
            )
          } else if (keyResult) {
            return Some(lookupPromises, lookupResults => {
              if (lookupResults.filter(x => x).length >= ~~(endpoints.length / 2) + 1) {
                return Promise.resolve(lookupResults)
              }
              return Promise.reject(new Error('invalid'))
            })
          } else {
            return reject(new Error('node results do not match'))
          }
        })
        .catch(_ => {})
        .then(lookupShares => {
          // we are practically checking if all are the same here.! Should it not be based on returned responses
          // getting 5 and checking if 5 are the same.!
          const keyResult = thresholdSame(
            lookupShares.map(x => x && x.result),
            ~~(endpoints.length / 2) + 1
          )
          if (keyResult) {
            var ethAddress = keyResult.keys[0].address
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
