import { decrypt, generatePrivate, getPublic } from '@toruslabs/eccrypto'
import { get, setAPIKey, setEmbedHost } from '@toruslabs/http-helpers'
import BN from 'bn.js'
import { ec as EC } from 'elliptic'
import stringify from 'json-stable-stringify'
import memoryCache from 'memory-cache'
import { keccak256, toChecksumAddress } from 'web3-utils'

import { generateJsonRPCObject, post } from './httpHelpers'
import log from './loglevel'
import { Some } from './some'
import { kCombinations, keyAssign, keyLookup, thresholdSame, waitKeyLookup } from './utils'

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  constructor({
    enableLogging = false,
    metadataHost = 'https://metadata.tor.us',
    allowHost = 'https://signer.tor.us/api/allow',
    serverTimeOffset = 0,
  } = {}) {
    this.ec = new EC('secp256k1')
    this.metadataHost = metadataHost
    this.allowHost = allowHost
    this.metadataCache = memoryCache
    if (!enableLogging) log.disableAll()
    this.metadataLock = {}
    this.serverTimeOffset = serverTimeOffset || 0 // ms
    this.oneKey = {
      getPublicAddress: this.getOneKeyPublicAddress.bind(this),
      retrieveShares: this.retrieveOneKeyShares.bind(this),
    }
  }

  static setAPIKey(apiKey) {
    setAPIKey(apiKey)
  }

  static setEmbedHost(embedHost) {
    setEmbedHost(embedHost)
  }

  async setCustomKey({ privKeyHex, metadataNonce, torusKeyHex, customKeyHex }) {
    let torusKey
    if (torusKeyHex) {
      torusKey = new BN(torusKeyHex, 16)
    } else {
      const privKey = new BN(privKeyHex, 16)
      torusKey = privKey.sub(metadataNonce).umod(this.ec.curve.n)
    }
    const customKey = new BN(customKeyHex, 16)
    const newMetadataNonce = customKey.sub(torusKey).umod(this.ec.curve.n)
    const data = this.generateMetadataParams(newMetadataNonce.toString(16), torusKey.toString(16))
    await this.setMetadata(data)
  }

  async retrieveShares(
    endpoints,
    indexes,
    verifier,
    verifierParams,
    idToken,
    {
      __getMetadataNonce__, // Allow custom nonce getter, e.g. in OneKey, we have a different impl of retrieving metadata nonce
      ...extraParams
    } = {}
  ) {
    const promiseArr = []
    await get(
      this.allowHost,
      {
        headers: {
          verifier,
          verifier_id: verifierParams.verifier_id,
        },
      },
      { useAPIKey: true }
    )
    /*
      CommitmentRequestParams struct {
        MessagePrefix      string `json:"messageprefix"`
        TokenCommitment    string `json:"tokencommitment"`
        TempPubX           string `json:"temppubx"`
        TempPubY           string `json:"temppuby"`
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
          verifieridentifier: verifier,
        })
      ).catch((err) => log.error('commitment', err))
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
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== 'object') {
          return false
        }
        if (x.error) {
          return false
        }
        return true
      })
      if (completedRequests.length >= ~~(endpoints.length / 4) * 3 + 1) {
        return Promise.resolve(resultArr)
      }
      return Promise.reject(new Error(`invalid ${JSON.stringify(resultArr)}`))
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
            item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier, ...extraParams }],
          })
        ).catch((err) => log.error('share req', err))
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

          const getMetadataNonce = __getMetadataNonce__ ?? this.getMetadata.bind(this)
          const metadataNonce = await getMetadataNonce({ pub_key_X: thresholdPublicKey.X, pub_key_Y: thresholdPublicKey.Y, private_key: privateKey })
          if (sharedState.resolved) return undefined
          privateKey = privateKey.add(metadataNonce).umod(this.ec.curve.n)

          const ethAddress = this.generateAddressFromPrivKey(privateKey)
          // return reconstructed private key and ethereum address
          return {
            ethAddress,
            privKey: privateKey.toString('hex', 64),
            metadataNonce,
          }
        }
        throw new Error('invalid')
      })
    })
  }

  async getMetadata(data, options) {
    let unlock
    try {
      const dataKey = stringify(data)
      if (this.metadataLock[dataKey] !== null) {
        await this.metadataLock[dataKey]
      } else {
        this.metadataLock[dataKey] = new Promise((resolve) => {
          unlock = () => {
            this.metadataLock[dataKey] = null
            resolve()
          }
        })
      }
      const cachedResult = this.metadataCache.get(dataKey)
      if (cachedResult !== null) {
        if (unlock) unlock()
        return cachedResult
      }
      const metadataResponse = await post(`${this.metadataHost}/get`, data, options, { useAPIKey: true })
      if (!metadataResponse || !metadataResponse.message) {
        this.metadataCache.put(dataKey, new BN(0), 60000)
        if (unlock) unlock()
        return new BN(0)
      }
      this.metadataCache.put(dataKey, new BN(metadataResponse.message, 16), 60000)
      return new BN(metadataResponse.message, 16) // nonce
    } catch (error) {
      log.error('get metadata error', error)
      if (unlock) unlock()
      return new BN(0)
    }
  }

  generateMetadataParams(message, privateKey) {
    const key = this.ec.keyFromPrivate(privateKey.toString('hex', 64))
    const setData = {
      data: message,
      timestamp: new BN(~~(this.serverTimeOffset + Date.now() / 1000)).toString(16),
    }
    const sig = key.sign(keccak256(stringify(setData)).slice(2))
    return {
      pub_key_X: key.getPublic().getX().toString('hex'),
      pub_key_Y: key.getPublic().getY().toString('hex'),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN(sig.v).toString(16, 2), 'hex').toString('base64'),
    }
  }

  async setMetadata(data, options) {
    try {
      this.metadataCache.del(stringify({ pub_key_X: data.pub_key_X, pub_key_Y: data.pub_key_Y }))
      const metadataResponse = await post(`${this.metadataHost}/set`, data, options, { useAPIKey: true })
      return metadataResponse.message // IPFS hash
    } catch (error) {
      log.error('set metadata error', error)
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

  async getPublicAddress(endpoints, torusNodePubs, { verifier, verifierId }, isExtended = false) {
    let finalKeyResult
    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {}
    if (errorResult && JSON.stringify(errorResult).includes('Verifier + VerifierID has not yet been assigned')) {
      await keyAssign(endpoints, torusNodePubs, undefined, undefined, verifier, verifierId)
      const assignResult = (await waitKeyLookup(endpoints, verifier, verifierId, 1000)) || {}
      finalKeyResult = assignResult.keyResult
    } else if (keyResult) {
      finalKeyResult = keyResult
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`)
    }

    if (finalKeyResult) {
      let { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0]
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
        metadataNonce: nonce,
      }
    }
    throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`)
  }

  async getOrSetNonce(X, Y, privKey) {
    try {
      let data
      if (privKey) {
        data = this.generateMetadataParams('getOrSetNonce', privKey)
      } else {
        data = {
          pub_key_X: X,
          pub_key_Y: Y,
        }
      }
      const metadataResponse = await post(`${this.metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true })
      return metadataResponse
    } catch (error) {
      log.error('getOrSetNonce error', error)
      return ''
    }
  }

  async retrieveOneKeyShares(endpoints, indexes, verifier, verifierParams, idToken, extraParams = {}) {
    return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, {
      ...extraParams,
      // OneKey get metadata nonce, works for both existing v1, v2 and new v2 users, but may generate unnecessary nonce for v1 users
      __getMetadataNonce__: async ({ pub_key_X: pubKeyX, pub_key_Y: publicKeyY, private_key: privKey }) => {
        const { nonce } = await this.getOrSetNonce(pubKeyX, publicKeyY, privKey)
        return new BN(nonce, 16)
      },
    })
  }

  async getOneKeyPublicAddress(endpoints, torusNodePubs, { verifier, verifierId }, isExtended = false) {
    let finalKeyResult
    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {}
    if (errorResult && JSON.stringify(errorResult).includes('Verifier + VerifierID has not yet been assigned')) {
      await keyAssign(endpoints, torusNodePubs, undefined, undefined, verifier, verifierId)
      const assignResult = (await waitKeyLookup(endpoints, verifier, verifierId, 1000)) || {}
      finalKeyResult = assignResult.keyResult
    } else if (keyResult) {
      finalKeyResult = keyResult
    } else {
      throw new Error(`node results do not match at first lookup v2 ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`)
    }

    if (finalKeyResult) {
      let { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0]
      const { nonce, pubNonce, typeOfUser, newUser } = await this.getOrSetNonce(X, Y)
      let noncePubKey
      if (typeOfUser === 'v1') {
        noncePubKey = this.ec.keyFromPrivate(nonce.toString(16)).getPublic()
      } else if (typeOfUser === 'v2') {
        noncePubKey = this.ec.keyFromPublic({ x: pubNonce.x, y: pubNonce.y })
      } else {
        throw new Error('getOrSetNonce API should always return version')
      }
      const modifiedPubKey = this.ec
        .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
        .getPublic()
        .add(noncePubKey)
      X = modifiedPubKey.getX().toString(16)
      Y = modifiedPubKey.getY().toString(16)
      const address = this.generateAddressFromPubKey(modifiedPubKey.getX(), modifiedPubKey.getY())
      if (!isExtended) return address
      return {
        address,
        X,
        Y,
        metadataNonce: nonce,
        pubNonce,
        typeOfUser,
        newUser,
      }
    }
    throw new Error(`node results do not match at end of lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`)
  }

  getPostboxKeyFrom1OutOf1(privKey, nonce) {
    const privKeyBN = new BN(privKey, 16)
    const nonceBN = new BN(nonce, 16)
    return privKeyBN.sub(nonceBN).umod(this.ec.curve.n).toString('hex')
  }
}

export default Torus
