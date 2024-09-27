import { KEY_TYPE, LEGACY_NETWORKS_ROUTE_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE, TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { decrypt } from "@toruslabs/eccrypto";
import { Data, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { SAPPHIRE_DEVNET_METADATA_URL, SAPPHIRE_METADATA_URL } from "../constants";
import {
  EciesHex,
  EncryptedSeed,
  GetOrSetNonceResult,
  KeyType,
  MetadataParams,
  NonceMetadataParams,
  SapphireMetadataParams,
  SetNonceData,
} from "../interfaces";
import { encParamsHexToBuf, getKeyCurve, keccak256 } from "./common";

export const getSecpKeyFromEd25519 = (
  ed25519Scalar: BN
): {
  scalar: BN;
  point: curve.base.BasePoint;
} => {
  const secp256k1Curve = getKeyCurve(KEY_TYPE.SECP256K1);

  const ed25519Key = ed25519Scalar.toString("hex", 64);
  const keyHash = keccakHash(Buffer.from(ed25519Key, "hex"));
  const secpKey = new BN(keyHash).umod(secp256k1Curve.n).toString("hex", 64);
  const bufferKey = Buffer.from(secpKey, "hex");

  const secpKeyPair = secp256k1Curve.keyFromPrivate(bufferKey);

  if (bufferKey.length !== 32) {
    throw new Error(`Key length must be equal to 32. got ${bufferKey.length}`);
  }
  return {
    scalar: secpKeyPair.getPrivate(),
    point: secpKeyPair.getPublic(),
  };
};

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

export async function decryptNodeDataWithPadding(eciesData: EciesHex, ciphertextHex: string, privKey: Buffer): Promise<Buffer> {
  const metadata = encParamsHexToBuf(eciesData);
  try {
    const decryptedSigBuffer = await decrypt(privKey, {
      ...metadata,
      ciphertext: Buffer.from(ciphertextHex, "hex"),
    });
    return decryptedSigBuffer;
  } catch (error) {
    // ciphertext can be any length. not just 64. depends on input. we have this for legacy reason
    const ciphertextHexPadding = ciphertextHex.padStart(64, "0");

    log.warn("Failed to decrypt padded share cipher", error);
    // try without cipher text padding
    return decrypt(privKey, { ...metadata, ciphertext: Buffer.from(ciphertextHexPadding, "hex") });
  }
}

export function generateMetadataParams(ecCurve: EC, serverTimeOffset: number, message: string, privateKey: BN): MetadataParams {
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
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

export function generateNonceMetadataParams(
  serverTimeOffset: number,
  operation: string,
  privateKey: BN,
  keyType: KeyType,
  nonce?: BN,
  seed?: string
): NonceMetadataParams {
  // metadata only uses secp for sig validation
  const key = getKeyCurve(KEY_TYPE.SECP256K1).keyFromPrivate(privateKey.toString("hex", 64), "hex");
  const setData: Partial<SetNonceData> = {
    operation,
    timestamp: new BN(~~(serverTimeOffset + Date.now() / 1000)).toString(16),
  };

  if (nonce) {
    setData.data = nonce.toString("hex", 64);
  }

  if (seed) {
    setData.seed = seed;
  } else {
    setData.seed = ""; // setting it as empty to keep ordering same while serializing the data on backend.
  }

  const sig = key.sign(keccak256(Buffer.from(stringify(setData), "utf8")).slice(2));
  return {
    pub_key_X: key.getPublic().getX().toString("hex", 64),
    pub_key_Y: key.getPublic().getY().toString("hex", 64),
    set_data: setData,
    key_type: keyType,
    signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
  };
}

export async function getOrSetNonce(
  metadataHost: string,
  ecCurve: EC,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: BN,
  getOnly = false,
  isLegacyMetadata = true,
  nonce = new BN(0),
  keyType: KeyType = "secp256k1",
  seed = ""
): Promise<GetOrSetNonceResult> {
  // for legacy metadata
  if (isLegacyMetadata) {
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
    return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
  }

  // for sapphire metadata
  const operation = getOnly ? "getNonce" : "getOrSetNonce";
  if (operation === "getOrSetNonce") {
    if (!privKey) {
      throw new Error("privKey is required while `getOrSetNonce` for non legacy metadata");
    }
    if (nonce.cmp(new BN(0)) === 0) {
      throw new Error("nonce is required while `getOrSetNonce` for non legacy metadata");
    }
    if (keyType === KEY_TYPE.ED25519 && !seed) {
      throw new Error("seed is required while `getOrSetNonce` for non legacy metadata for ed25519 key type");
    }
    const data = generateNonceMetadataParams(serverTimeOffset, operation, privKey, keyType, nonce, seed);

    return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
  }
  const data = {
    pub_key_X: X,
    pub_key_Y: Y,
    set_data: { operation },
    key_type: keyType,
  };
  return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
}
export async function getNonce(
  legacyMetadataHost: string,
  ecCurve: EC,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: BN
): Promise<GetOrSetNonceResult> {
  return getOrSetNonce(legacyMetadataHost, ecCurve, serverTimeOffset, X, Y, privKey, true);
}

export const decryptSeedData = async (seedBase64: string, finalUserKey: BN) => {
  const decryptionKey = getSecpKeyFromEd25519(finalUserKey);
  const seedUtf8 = Buffer.from(seedBase64, "base64").toString("utf-8");
  const seedJson = JSON.parse(seedUtf8) as EncryptedSeed;
  const bufferMetadata = { ...encParamsHexToBuf(seedJson.metadata), mode: "AES256" };
  const bufferKey = decryptionKey.scalar.toArrayLike(Buffer, "be", 32);
  const decText = await decrypt(bufferKey, {
    ...bufferMetadata,
    ciphertext: Buffer.from(seedJson.enc_text, "hex"),
  });

  return decText;
};

export async function getOrSetSapphireMetadataNonce(
  network: TORUS_NETWORK_TYPE,
  X: string,
  Y: string,
  serverTimeOffset?: number,
  privKey?: BN
): Promise<GetOrSetNonceResult> {
  if (LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
    throw new Error("getOrSetSapphireMetadataNonce should only be used for sapphire networks");
  }
  let data: SapphireMetadataParams = {
    pub_key_X: X,
    pub_key_Y: Y,
    key_type: "secp256k1",
    set_data: { operation: "getOrSetNonce" },
  };
  if (privKey) {
    const key = getKeyCurve(KEY_TYPE.SECP256K1).keyFromPrivate(privKey.toString("hex", 64), "hex");

    const setData = {
      operation: "getOrSetNonce",
      timestamp: new BN(~~(serverTimeOffset + Date.now() / 1000)).toString(16),
    };
    const sig = key.sign(keccak256(Buffer.from(stringify(setData), "utf8")).slice(2));
    data = {
      ...data,
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
    };
  }

  const metadataUrl = network === TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET ? SAPPHIRE_DEVNET_METADATA_URL : SAPPHIRE_METADATA_URL;

  return post<GetOrSetNonceResult>(`${metadataUrl}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
}
