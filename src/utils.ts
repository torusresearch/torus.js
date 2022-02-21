import { generateJsonRPCObject, post } from '@toruslabs/http-helpers'
import JsonStringify from 'json-stable-stringify'

import log from './loglevel'
import { Some } from './some'
import { Verifier, KeyLookupResult, TorusNodePub } from '../types/types'

export class GetOrSetNonceError extends Error {}

export const kCombinations = (s, k: number) => {
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

export const thresholdSame = (arr: any[], t: number) => {
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

export const keyLookup = async (endpoints: string[], verifier: Verifier, verifierId: string): Promise<KeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post(
      x,
      generateJsonRPCObject('VerifierLookupRequest', {
        verifier,
        verifier_id: verifierId.toString(),
      })
    ).catch((err) => log.error('lookup request failed', err))
  )
  return Some(lookupPromises, (lookupResults) => {
    const lookupShares = lookupResults.filter((x1) => x1)
    const errorResult = thresholdSame(
      lookupShares.map((x2) => x2 && x2.error),
      ~~(endpoints.length / 2) + 1
    )
    const keyResult = thresholdSame(
      lookupShares.map((x3) => x3 && x3.result),
      ~~(endpoints.length / 2) + 1
    )
    if (keyResult || errorResult) {
      return Promise.resolve({ keyResult, errorResult })
    }
    return Promise.reject(new Error(`invalid results ${JSON.stringify(lookupResults)}`))
  })
}

export const waitKeyLookup = (endpoints: string[], verifier: Verifier, verifierId: string, timeout: number): Promise<KeyLookupResult> => {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      keyLookup(endpoints, verifier, verifierId).then(resolve).catch(reject)
    }, timeout)
  })
}

export const keyAssign = async ({ endpoints, torusNodePubs, lastPoint, firstPoint, verifier, verifierId, signerHost }) => {
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
    verifier_id: verifierId.toString(),
  })
  try {
    const signedData = await post(
      signerHost,
      data,
      {
        headers: {
          pubKeyX: torusNodePubs[nodeNum].X,
          pubKeyY: torusNodePubs[nodeNum].Y,
        },
      },
      { useAPIKey: true }
    )
    return post(
      endpoints[nodeNum],
      { ...data, ...signedData },
      {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
        },
      }
    )
  } catch (error) {
    log.error(error)
    const acceptedErrorMsgs = [
      // Slow node
      'Timed out',
      // Happens when the node is not reachable (dns issue etc)
      'TypeError: Failed to fetch', // All except iOS and Firefox
      'TypeError: cancelled', // iOS
      'TypeError: NetworkError when attempting to fetch resource.', // Firefox
    ]
    if (acceptedErrorMsgs.includes(error.message))
      return keyAssign({ endpoints, torusNodePubs, lastPoint: nodeNum + 1, firstPoint: initialPoint, verifier, verifierId, signerHost })
    throw new Error(
      `Sorry, the Torus Network that powers Web3Auth is currently very busy.
    We will generate your key in time. Pls try again later. \n
    ${error.message || ''}`
    )
  }
}
