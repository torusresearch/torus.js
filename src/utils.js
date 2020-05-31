import JsonStringify from 'json-stable-stringify'

import { generateJsonRPCObject, post } from './httpHelpers'
import { Some } from './some'

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

export const keyAssign = (endpoints, torusNodePubs, lastPoint, firstPoint, verifier, verifierId, apiKey) => {
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
  return post('http://localhost:8080/torus-signer/api/sign', data, {
    headers: {
      pubKeyX: torusNodePubs[nodeNum].X,
      pubKeyY: torusNodePubs[nodeNum].Y,
      authorization: apiKey,
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
    ).catch((_) => keyAssign(endpoints, torusNodePubs, nodeNum + 1, initialPoint, verifier, verifierId, apiKey))
  )
}
