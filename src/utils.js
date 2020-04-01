import Hash from 'eth-lib/lib/hash'
import JsonStringify from 'json-stable-stringify'

import { generateJsonRPCObject, post } from './httpHelpers'
import { Some } from './some'
/**
 * Check if string is HEX, requires a 0x in front
 *
 * @method isHexStrict
 * @param {String} hex to be checked
 * @returns {Boolean}
 */
function isHexStrict(hex) {
  return (typeof hex === 'string' || typeof hex === 'number') && /^(-)?0x[0-9a-f]*$/i.test(hex)
}

/**
 * Convert a hex string to a byte array
 *
 * Note: Implementation from crypto-js
 *
 * @method hexToBytes
 * @param {string} hex
 * @return {Array} the byte array
 */
function hexToBytes(hex) {
  let hexStr = hex.toString(16)
  let bytes
  let c

  if (!isHexStrict(hexStr)) {
    throw new Error(`Given value "${hexStr}" is not a valid hex string.`)
  }

  hexStr = hexStr.replace(/^0x/i, '')

  for (bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16))
  return bytes
}

/**
 * Hashes values to a sha3 hash using keccak 256
 *
 * To hash a HEX string the hex must have 0x in front.
 *
 * @method sha3
 * @return {String} the sha3 string
 */
const SHA3_NULL_S = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

function sha3(value) {
  let val = value
  if (isHexStrict(val) && /^0x/i.test(val.toString())) {
    val = hexToBytes(val)
  }

  const returnValue = Hash.keccak256(val)

  if (returnValue === SHA3_NULL_S) {
    return null
  }
  return returnValue
}

export const keccak256 = sha3

/**
 * Converts to a checksum address
 *
 * @method toChecksumAddress
 * @param {String} address the given HEX address
 * @return {String}
 */
export const toChecksumAddress = (addr) => {
  if (typeof addr === 'undefined') return ''
  let address = addr

  if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) throw new Error(`Given address "${address}" is not a valid Ethereum address.`)

  address = address.toLowerCase().replace(/^0x/i, '')
  const addressHash = keccak256(address).replace(/^0x/i, '')
  let checksumAddress = '0x'

  for (let i = 0; i < address.length; i += 1) {
    // If ith character is 9 to f then make it uppercase
    if (parseInt(addressHash[i], 16) > 7) {
      checksumAddress += address[i].toUpperCase()
    } else {
      checksumAddress += address[i]
    }
  }
  return checksumAddress
}

export const kCombinations = (s, k) => {
  let set = s
  if (typeof set === 'number') {
    set = Array.from({ length: set }, (_, i) => i)
  }
  if (k > set.length || k <= 0) {
    return []
  }

  if (k === set.length) {
    return [set]
  }

  if (k === 1) {
    return set.reduce((acc, cur) => [...acc, [cur]], [])
  }

  const combs = []
  let tailCombs = []

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1)
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i], ...tailCombs[j]])
    }
  }

  return combs
}

export const thresholdSame = (arr, t) => {
  const hashMap = {}
  for (let i = 0; i < arr.length; i += 1) {
    const str = JsonStringify(arr[i])
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1
    if (hashMap[str] === t) {
      return arr[i]
    }
  }
  return undefined
}

export const keyLookup = (endpoints, verifier, verifierId) => {
  const lookupPromises = endpoints.map((x) =>
    post(
      x,
      generateJsonRPCObject('VerifierLookupRequest', {
        verifier,
        verifier_id: verifierId.toString().toLowerCase(),
      })
    ).catch((_) => undefined)
  )
  return Some(lookupPromises, (lookupResults) => {
    const lookupShares = lookupResults.filter((x) => x)
    const errorResult = thresholdSame(
      lookupShares.map((x) => x && x.error),
      ~~(endpoints.length / 2) + 1
    )
    const keyResult = thresholdSame(
      lookupShares.map((x) => x && x.result),
      ~~(endpoints.length / 2) + 1
    )
    if (keyResult || errorResult) {
      return Promise.resolve({ keyResult, errorResult })
    }
    return Promise.reject(new Error('invalid'))
  }).catch((_) => undefined)
}

export const keyAssign = (endpoints, torusNodePubs, lastPoint, firstPoint, verifier, verifierId) => {
  let nodeNum
  let initialPoint
  if (lastPoint === undefined) {
    nodeNum = Math.floor(Math.random() * endpoints.length)
    initialPoint = nodeNum
  } else {
    nodeNum = lastPoint % endpoints.length
  }
  if (nodeNum === firstPoint) throw new Error('Looped through all')
  if (firstPoint !== undefined) initialPoint = firstPoint

  const data = generateJsonRPCObject('KeyAssign', {
    verifier,
    verifier_id: verifierId.toString().toLowerCase(),
  })
  return post('https://signer.tor.us/api/sign', data, {
    headers: {
      pubKeyX: torusNodePubs[nodeNum].X,
      pubKeyY: torusNodePubs[nodeNum].Y,
    },
  }).then((signedData) =>
    // eslint-disable-next-line promise/no-nesting
    post(
      endpoints[nodeNum],
      { ...data, ...signedData },
      {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
        },
      }
    ).catch((_) => keyAssign(endpoints, torusNodePubs, nodeNum + 1, initialPoint, verifier, verifierId))
  )
}
