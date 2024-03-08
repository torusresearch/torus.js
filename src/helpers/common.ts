import { Ecies } from "@toruslabs/eccrypto";
import { BN } from "bn.js";
import JsonStringify from "json-stable-stringify";

import { EciesHex, LegacyVerifierLookupResponse, VerifierLookupResponse } from "../interfaces";
import { keccak256 } from ".";

// this function normalizes the result from nodes before passing the result to threshold check function
// For ex: some fields returns by nodes might be different from each other
// like created_at field might vary and nonce_data might not be returned by all nodes because
// of the metadata implementation in sapphire.
export const normalizeKeysResult = (result: VerifierLookupResponse) => {
  const finalResult: Pick<VerifierLookupResponse, "keys" | "is_new_key"> = {
    keys: [],
    is_new_key: result.is_new_key,
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
};

// this function normalizes the result from nodes before passing the result to threshold check function
// For ex: some fields returns by nodes might be different from each other
// like key_index which may differ on sapphire_network for each queried node
export const normalizeLegacyKeysResult = (result: LegacyVerifierLookupResponse) => {
  const finalResult: Pick<LegacyVerifierLookupResponse, "keys"> = {
    keys: [],
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
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

export function encParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: Buffer.from(encParams.iv).toString("hex"),
    ephemPublicKey: Buffer.from(encParams.ephemPublicKey).toString("hex"),
    ciphertext: Buffer.from(encParams.ciphertext).toString("hex"),
    mac: Buffer.from(encParams.mac).toString("hex"),
    mode: "AES256",
  };
}

export function encParamsHexToBuf(eciesData: Omit<EciesHex, "ciphertext">): Omit<Ecies, "ciphertext"> {
  return {
    ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, "hex"),
    iv: Buffer.from(eciesData.iv, "hex"),
    mac: Buffer.from(eciesData.mac, "hex"),
  };
}

export function getProxyCoordinatorEndpointIndex(endpoints: string[], verifier: string, verifierId: string) {
  const verifierIdStr = `${verifier}${verifierId}`;
  const hashedVerifierId = keccak256(Buffer.from(verifierIdStr, "utf8")).slice(2);
  const proxyEndpointNum = new BN(hashedVerifierId, "hex").mod(new BN(endpoints.length)).toNumber();
  return proxyEndpointNum;
}

export function calculateMedian(arr: number[]): number {
  const arrSize = arr.length;

  if (arrSize === 0) return 0;
  const sortedArr = arr.sort(function (a, b) {
    return a - b;
  });

  // odd length
  if (arrSize % 2 !== 0) {
    return sortedArr[Math.floor(arrSize / 2)];
  }

  // return average of two mid values in case of even arrSize
  const mid1 = sortedArr[arrSize / 2 - 1];

  const mid2 = sortedArr[arrSize / 2];
  return (mid1 + mid2) / 2;
}
