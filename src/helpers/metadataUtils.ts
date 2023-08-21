import { decrypt } from "@toruslabs/eccrypto";
import { Data, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { ec } from "elliptic";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { EciesHex, GetOrSetNonceResult, MetadataParams } from "../interfaces";
import { encParamsHexToBuf } from "./common";
import { keccak256 } from "./keyUtils";

export function convertMetadataToNonce(params: { message?: string }) {
  if (!params || !params.message) {
    return new BN(0);
  }
  return new BN(params.message, 16);
}

export async function decryptNodeData(eciesData: EciesHex, ciphertextHex: string, privKey: Buffer): Promise<Buffer> {
  const metadata = encParamsHexToBuf(eciesData);
  const decryptedSigBuffer = await decrypt(privKey, {
    ...metadata,
    ciphertext: Buffer.from(ciphertextHex, "hex"),
  });
  return decryptedSigBuffer;
}

export function generateMetadataParams(ecCurve: ec, serverTimeOffset: number, message: string, privateKey: BN): MetadataParams {
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64));
  const setData = {
    data: message,
    timestamp: new BN(~~(serverTimeOffset + Date.now() / 1000)).toString(16),
  };
  const sig = key.sign(keccak256(Buffer.from(stringify(setData), "utf8")).slice(2));
  return {
    pub_key_X: key.getPublic().getX().toString("hex"), // DO NOT PAD THIS. BACKEND DOESN'T
    pub_key_Y: key.getPublic().getY().toString("hex"), // DO NOT PAD THIS. BACKEND DOESN'T
    set_data: setData,
    signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
  };
}

export async function getMetadata(
  legacyMetadataHost: string,
  data: Omit<MetadataParams, "set_data" | "signature">,
  options: RequestInit = {}
): Promise<BN> {
  try {
    const metadataResponse = await post<{ message?: string }>(`${legacyMetadataHost}/get`, data, options, { useAPIKey: true });
    if (!metadataResponse || !metadataResponse.message) {
      return new BN(0);
    }
    return new BN(metadataResponse.message, 16); // nonce
  } catch (error) {
    log.error("get metadata error", error);
    return new BN(0);
  }
}

export async function getOrSetNonce(
  legacyMetadataHost: string,
  ecCurve: ec,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: BN,
  getOnly = false
): Promise<GetOrSetNonceResult> {
  let data: Data;
  const msg = getOnly ? "getNonce" : "getOrSetNonce";
  if (privKey) {
    data = generateMetadataParams(ecCurve, serverTimeOffset, msg, privKey);
  } else {
    data = {
      pub_key_X: X,
      pub_key_Y: Y,
      set_data: { data: msg },
    };
  }
  return post<GetOrSetNonceResult>(`${legacyMetadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
}

export async function getNonce(
  legacyMetadataHost: string,
  ecCurve: ec,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: BN
): Promise<GetOrSetNonceResult> {
  return getOrSetNonce(legacyMetadataHost, ecCurve, serverTimeOffset, X, Y, privKey, true);
}
