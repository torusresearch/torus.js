import JsonStringify from 'json-stable-stringify'

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

  for (let i = 0; i <= set.length - k + 1; i++) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1)
    for (let j = 0; j < tailCombs.length; j++) {
      combs.push([set[i], ...tailCombs[j]])
    }
  }

  return combs
}

export const thresholdSame = (arr, t) => {
  const hashMap = {}
  for (let i = 0; i < arr.length; i++) {
    const str = JsonStringify(arr[i])
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1
    if (hashMap[str] === t) {
      return arr[i]
    }
  }
  return undefined
}
