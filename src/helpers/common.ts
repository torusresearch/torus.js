import { Ecies } from "@toruslabs/eccrypto";
import JsonStringify from "json-stable-stringify";

import { EciesHex, VerifierLookupResponse } from "../interfaces";

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
    finalResult.keys = result.keys.map((key) => {
      return {
        pub_key_X: key.pub_key_X,
        pub_key_Y: key.pub_key_Y,
        address: key.address,
      };
    });
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
