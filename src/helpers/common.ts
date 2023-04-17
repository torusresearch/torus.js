import JsonStringify from "json-stable-stringify";

import { VerifierLookupResponse } from "../interfaces";

// this function normalizes the result from nodes before passing the result to threshold check function
// For ex: some fields returns by nodes might be different thn each other
// like created_at field might vary and nonce_data might not be returned by all nodes because
// of the metadata implementation in sapphire.
export const normalizeKeysResult = (result: VerifierLookupResponse) => {
  if (result && result.keys && result.keys.length > 0) {
    const normalizedKeys = result.keys.map((key) => {
      // created_at can different for each node
      delete key.created_at;
      // nonce_data response is not guaranteed from all nodes so not including it in threshold check.
      delete key.nonce_data;
      return key;
    });
    result.keys = normalizedKeys;
    return result;
  }
  return result;
};

export const kCombinations = (s: number | number[], k: number): number[][] => {
  let set = s;
  if (typeof set === "number") {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return [];
  }

  if (k === set.length) {
    return [set];
  }

  if (k === 1) {
    return set.reduce((acc, cur) => [...acc, [cur]], [] as number[][]);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i], ...tailCombs[j]]);
    }
  }

  return combs;
};

export const thresholdSame = <T>(arr: T[], t: number): T | undefined => {
  const hashMap: Record<string, number> = {};
  for (let i = 0; i < arr.length; i += 1) {
    const str = JsonStringify(arr[i]);
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return arr[i];
    }
  }
  return undefined;
};
