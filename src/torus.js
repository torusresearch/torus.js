/* eslint-disable class-methods-use-this */
import { get } from '@toruslabs/http-helpers'
import BN from 'bn.js'
import { decrypt, generatePrivate, getPublic } from 'eccrypto'
import { ec as EC } from 'elliptic'
import { keccak256, toChecksumAddress } from 'web3-utils'

import { generateJsonRPCObject, post } from './httpHelpers'
import log from './loglevel'
import { Some } from './some'
import { kCombinations, keyAssign, keyLookup, thresholdSame } from './utils'

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  constructor({ enableLogging = false, metadataHost = 'https://metadata.tor.us', allowHost = 'https://signer.tor.us/api/allow' } = {}) {
    this.ec = new EC('secp256k1')
    this.metadataHost = metadataHost
    this.allowHost = allowHost
    log.setDefaultLevel('DEBUG')
    if (!enableLogging) log.disableAll()
  }

  async retrieveShares(endpoints, indexes, verifier, verifierParams, idToken) {
    const promiseArr = []
    await get(this.allowHost)
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

    // generate temporary private and public key that is used to secure receive shares
    const tmpKey = generatePrivate()
    const pubKey = getPublic(tmpKey).toString('hex')
    const pubKeyX = pubKey.slice(2, 66)
    const pubKeyY = pubKey.slice(66)
    const tokenCommitment = keccak256(idToken)

    // make commitment requests to endpoints
    for (let i = 0; i < endpoints.length; i += 1) {
      const p = post(
        endpoints[i],
        generateJsonRPCObject('CommitmentRequest', {
          messageprefix: 'mug00',
          tokencommitment: tokenCommitment.slice(2),
          temppubx: pubKeyX,
          temppuby: pubKeyY,
          timestamp: (Date.now() - 2000).toString().slice(0, 10),
          verifieridentifier: verifier,
        })
      ).catch((err) => log.debug('commitment', err))
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
    // send share request once k + t number of commitment requests have completed
    return Some(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => x)
      if (completedRequests.length >= ~~(endpoints.length / 4) * 3 + 1) {
        return Promise.resolve(resultArr)
      }
      return Promise.reject(new Error('invalid'))
    }).then((responses) => {
      const promiseArrRequest = []
      const nodeSigs = []
      for (let i = 0; i < responses.length; i += 1) {
        if (responses[i]) nodeSigs.push(responses[i].result)
      }
      for (let i = 0; i < endpoints.length; i += 1) {
        // eslint-disable-next-line promise/no-nesting
        const p = post(
          endpoints[i],
          generateJsonRPCObject('ShareRequest', {
            encrypted: 'yes',
            item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier }],
          })
        ).catch((err) => log.debug('share req', err))
        promiseArrRequest.push(p)
      }
      return Some(promiseArrRequest, async (shareResponses, sharedState) => {
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
        // check if threshold number of nodes have returned the same user public key
        const completedRequests = shareResponses.filter((x) => x)
        const thresholdPublicKey = thresholdSame(
          shareResponses.map((x) => x && x.result && x.result.keys[0].PublicKey),
          ~~(endpoints.length / 2) + 1
        )
        // optimistically run lagrange interpolation once threshold number of shares have been received
        // this is matched against the user public key to ensure that shares are consistent
        if (completedRequests.length >= ~~(endpoints.length / 2) + 1 && thresholdPublicKey) {
          const sharePromises = []
          const nodeIndex = []
          for (let i = 0; i < shareResponses.length; i += 1) {
            if (shareResponses[i] && shareResponses[i].result && shareResponses[i].result.keys && shareResponses[i].result.keys.length > 0) {
              shareResponses[i].result.keys.sort((a, b) => new BN(a.Index, 16).cmp(new BN(b.Index, 16)))
              if (shareResponses[i].result.keys[0].Metadata) {
                const metadata = {
                  ephemPublicKey: Buffer.from(shareResponses[i].result.keys[0].Metadata.ephemPublicKey, 'hex'),
                  iv: Buffer.from(shareResponses[i].result.keys[0].Metadata.iv, 'hex'),
                  mac: Buffer.from(shareResponses[i].result.keys[0].Metadata.mac, 'hex'),
                  mode: Buffer.from(shareResponses[i].result.keys[0].Metadata.mode, 'hex'),
                }
                sharePromises.push(
                  // eslint-disable-next-line promise/no-nesting
                  decrypt(tmpKey, {
                    ...metadata,
                    ciphertext: Buffer.from(atob(shareResponses[i].result.keys[0].Share).padStart(64, '0'), 'hex'),
                  }).catch((err) => log.debug('share decryption', err))
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
          if (sharedState.resolved) return undefined

          const decryptedShares = sharesResolved.reduce((acc, curr, index) => {
            if (curr) acc.push({ index: nodeIndex[index], value: new BN(curr) })
            return acc
          }, [])
          // run lagrange interpolation on all subsets, faster in the optimistic scenario than berlekamp-welch due to early exit
          const allCombis = kCombinations(decryptedShares.length, ~~(endpoints.length / 2) + 1)
          let privateKey
          for (let j = 0; j < allCombis.length; j += 1) {
            const currentCombi = allCombis[j]
            const currentCombiShares = decryptedShares.filter((v, index) => currentCombi.includes(index))
            const shares = currentCombiShares.map((x) => x.value)
            const indices = currentCombiShares.map((x) => x.index)
            const derivedPrivateKey = this.lagrangeInterpolation(shares, indices)
            const decryptedPubKey = getPublic(Buffer.from(derivedPrivateKey.toString(16, 64), 'hex')).toString('hex')
            const decryptedPubKeyX = decryptedPubKey.slice(2, 66)
            const decryptedPubKeyY = decryptedPubKey.slice(66)
            if (
              new BN(decryptedPubKeyX, 16).cmp(new BN(thresholdPublicKey.X, 16)) === 0 &&
              new BN(decryptedPubKeyY, 16).cmp(new BN(thresholdPublicKey.Y, 16)) === 0
            ) {
              privateKey = derivedPrivateKey
              break
            }
          }
          if (privateKey === undefined) {
            throw new Error('could not derive private key')
          }

          const metadataNonce = await this.getMetadata({ pub_key_X: thresholdPublicKey.X, pub_key_Y: thresholdPublicKey.Y })
          if (sharedState.resolved) return undefined
          privateKey = privateKey.add(metadataNonce).umod(this.ec.curve.n)

          const ethAddress = this.generateAddressFromPrivKey(privateKey)
          // return reconstructed private key and ethereum address
          return {
            ethAddress,
            privKey: privateKey.toString('hex', 64),
          }
        }
        throw new Error('invalid')
      })
    })
  }

  async getMetadata(data, options) {
    try {
      const metadataResponse = await post(`${this.metadataHost}/get`, data, options, { useAPIKey: true })
      if (!metadataResponse || !metadataResponse.message) {
        return new BN(0)
      }
      return new BN(metadataResponse.message, 16) // nonce
    } catch (error) {
      log.error(error)
      return new BN(0)
    }
  }

  generateMetadataParams(message, privateKey) {
    const key = this.ec.keyFromPrivate(privateKey.toString('hex', 64))
    const setData = {
      data: message,
      timestamp: new BN(Date.now()).toString(16),
    }
    const sig = key.sign(keccak256(JSON.stringify(setData)).slice(2))
    return {
      pub_key_X: key.getPublic().getX().toString('hex'),
      pub_key_Y: key.getPublic().getY().toString('hex'),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN(sig.v).toString(16, 2), 'hex').toString('base64'),
    }
  }

  async setMetadata(data, options) {
    try {
      const metadataResponse = await post(`${this.metadataHost}/set`, data, options, { useAPIKey: true })
      return metadataResponse.message // IPFS hash
    } catch (error) {
      log.error(error)
      return ''
    }
  }

  lagrangeInterpolation(shares, nodeIndex) {
    if (shares.length !== nodeIndex.length) {
      return null
    }
    let secret = new BN(0)
    for (let i = 0; i < shares.length; i += 1) {
      let upper = new BN(1)
      let lower = new BN(1)
      for (let j = 0; j < shares.length; j += 1) {
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
    const key = this.ec.keyFromPrivate(privateKey.toString('hex', 64), 'hex')
    const publicKey = key.getPublic().encode('hex').slice(2)
    const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, 'hex')).slice(64 - 38)}`
    return toChecksumAddress(ethAddressLower)
  }

  generateAddressFromPubKey(publicKeyX, publicKeyY) {
    const key = this.ec.keyFromPublic({ x: publicKeyX.toString('hex', 64), y: publicKeyY.toString('hex', 64) })
    const publicKey = key.getPublic().encode('hex').slice(2)
    const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, 'hex')).slice(64 - 38)}`
    return toChecksumAddress(ethAddressLower)
  }

  getPublicAddress(endpoints, torusNodePubs, { verifier, verifierId }, isExtended = false) {
    return keyLookup(endpoints, verifier, verifierId)
      .then(({ keyResult, errorResult } = {}) => {
        if (errorResult) {
          // eslint-disable-next-line promise/no-nesting
          return keyAssign(endpoints, torusNodePubs, undefined, undefined, verifier, verifierId).then((_) => {
            return keyLookup(endpoints, verifier, verifierId)
          })
        }
        if (keyResult) {
          return { keyResult }
        }
        throw new Error('node results do not match')
      })
      .then(async ({ keyResult } = {}) => {
        if (keyResult) {
          let { pub_key_X: X, pub_key_Y: Y } = keyResult.keys[0]
          const nonce = await this.getMetadata({ pub_key_X: X, pub_key_Y: Y })
          const modifiedPubKey = this.ec
            .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
            .getPublic()
            .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic())
          X = modifiedPubKey.getX().toString(16)
          Y = modifiedPubKey.getY().toString(16)
          const address = this.generateAddressFromPubKey(modifiedPubKey.getX(), modifiedPubKey.getY())
          if (!isExtended) return address
          return {
            address,
            X,
            Y,
          }
        }
        throw new Error('node results do not match')
      })
  }
}

export default Torus
