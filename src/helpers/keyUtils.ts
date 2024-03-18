import { INodePub } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";
import base58 from "bs58";
import { curve, ec as EC } from "elliptic";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import { sha512 } from "ethereum-cryptography/sha512";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { EncryptedSeed, ImportedShare, KeyType, PrivateKeyData } from "../interfaces";
import { ed25519Curve, encParamsBufToHex, getKeyCurve, secp256k1Curve } from "./common";
import { generateRandomPolynomial } from "./langrangeInterpolatePoly";
import { generateNonceMetadataParams } from "./metadataUtils";

export function keccak256(a: Buffer): string {
  const hash = Buffer.from(keccakHash(a)).toString("hex");
  return `0x${hash}`;
}

export const generatePrivateKey = (ecCurve: EC, buf: typeof Buffer): Buffer => {
  return ecCurve.genKeyPair().getPrivate().toArrayLike(buf);
};

export function stripHexPrefix(str: string): string {
  return str.startsWith("0x") ? str.slice(2) : str;
}

export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const buf = Buffer.from(address, "utf8");
  const hash = Buffer.from(keccakHash(buf)).toString("hex");
  let ret = "0x";

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }

  return ret;
}

function adjustScalarBytes(bytes: Buffer): Buffer {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

/** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
export function getEd25519ExtendedPublicKey(keyHex: BN): {
  scalar: BN;
  point: curve.base.BasePoint;
} {
  const len = 32;
  const G = ed25519Curve.g;
  const N = ed25519Curve.n;
  const keyBuffer = keyHex.toArrayLike(Buffer);

  if (keyBuffer.length !== 32) {
    log.error("Invalid seed for ed25519 key derivation", keyBuffer.length);
    throw new Error("Invalid seed for ed25519 key derivation");
  }
  // Hash private key with curve's hash function to produce uniformingly random input
  // Check byte lengths: ensure(64, h(ensure(32, key)))
  const hashed = sha512(keyBuffer);
  if (hashed.length !== 64) {
    throw new Error("Invalid hash length for ed25519 seed");
  }
  const head = new BN(adjustScalarBytes(Buffer.from(hashed.slice(0, len))), "le");
  const scalar = new BN(head.umod(N), "le"); // The actual private scalar
  const point = G.mul(scalar) as curve.base.BasePoint; // Point on Edwards curve aka public key
  return { scalar, point };
}

export const getSecpKeyFromEd25519 = (
  ed25519Scalar: BN
): {
  scalar: BN;
  point: curve.base.BasePoint;
} => {
  const ed25519Key = ed25519Scalar.toString("hex", 64);
  const keyHash = keccakHash(Buffer.from(ed25519Key, "hex"));
  const secpKey = new BN(keyHash).umod(secp256k1Curve.curve.n);
  const secpKeyPair = secp256k1Curve.keyFromPrivate(secpKey.toString("hex", 64));
  return {
    scalar: secpKeyPair.getPrivate(),
    point: secpKeyPair.getPublic(),
  };
};

export function encodeEd25519Point(point: curve.base.BasePoint) {
  const encodingLength = Math.ceil(ed25519Curve.n.bitLength() / 8);
  const enc = point.getY().toArrayLike(Buffer, "le", encodingLength);
  enc[encodingLength - 1] |= point.getX().isOdd() ? 0x80 : 0;
  return enc;
}

export const generateEd25519KeyData = async (ed25519Seed: BN): Promise<PrivateKeyData> => {
  const finalEd25519Key = getEd25519ExtendedPublicKey(ed25519Seed);
  const encryptionKey = getSecpKeyFromEd25519(finalEd25519Key.scalar);
  const encryptedSeed = await encrypt(Buffer.from(encryptionKey.point.encodeCompressed("hex"), "hex"), ed25519Seed.toArrayLike(Buffer));
  const encData: EncryptedSeed = {
    enc_text: encryptedSeed.ciphertext.toString("hex"),
    metadata: encParamsBufToHex(encryptedSeed),
    public_key: encodeEd25519Point(finalEd25519Key.point).toString("hex"),
  };

  const encDataBase64 = Buffer.from(JSON.stringify(encData), "utf-8").toString("base64");
  const metadataPrivNonce = ed25519Curve.genKeyPair().getPrivate();
  const oauthKey = finalEd25519Key.scalar.sub(metadataPrivNonce).umod(ed25519Curve.n);
  const oauthKeyPair = ed25519Curve.keyFromPrivate(oauthKey.toArrayLike(Buffer));
  return {
    oAuthKeyScalar: oauthKeyPair.getPrivate(),
    oAuthPubX: oauthKeyPair.getPublic().getX(),
    oAuthPubY: oauthKeyPair.getPublic().getY(),
    SigningPubX: encryptionKey.point.getX(),
    SigningPubY: encryptionKey.point.getY(),
    metadataNonce: metadataPrivNonce,
    metadataSigningKey: encryptionKey.scalar,
    encryptedSeed: encDataBase64,
    finalUserPubKeyPoint: finalEd25519Key.point,
  };
};

export const generateSecp256k1KeyData = async (scalar: BN): Promise<PrivateKeyData> => {
  const randomNonce = new BN(generatePrivateKey(secp256k1Curve, Buffer));
  const oAuthKey = scalar.sub(randomNonce).umod(secp256k1Curve.curve.n);
  const oAuthKeyPair = secp256k1Curve.keyFromPrivate(oAuthKey.toString("hex").padStart(64, "0"));
  const oAuthPubKey = oAuthKeyPair.getPublic();

  const finalUserKeyPair = secp256k1Curve.keyFromPrivate(scalar.toString("hex", 64));

  return {
    oAuthKeyScalar: oAuthKeyPair.getPrivate(),
    oAuthPubX: oAuthPubKey.getX(),
    oAuthPubY: oAuthPubKey.getY(),
    SigningPubX: oAuthPubKey.getX(),
    SigningPubY: oAuthPubKey.getY(),
    metadataNonce: randomNonce,
    encryptedSeed: "",
    metadataSigningKey: oAuthKeyPair.getPrivate(),
    finalUserPubKeyPoint: finalUserKeyPair.getPublic(),
  };
};

export function generateAddressFromPrivKey(keyType: KeyType, privateKey: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  if (keyType === "secp256k1") {
    const publicKey = key.getPublic().encode("hex", false).slice(2);
    const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(evmAddressLower);
  } else if (keyType === "ed25519") {
    const publicKey = encodeEd25519Point(key.getPublic());
    const address = base58.encode(publicKey);
    return address;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

export function generateAddressFromPubKey(keyType: KeyType, publicKeyX: BN, publicKeyY: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  if (keyType === "secp256k1") {
    const publicKey = key.getPublic().encode("hex", false).slice(2);
    const evmAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(evmAddressLower);
  } else if (keyType === "ed25519") {
    const publicKey = encodeEd25519Point(key.getPublic());
    const address = base58.encode(publicKey);
    return address;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

export function getPostboxKeyFrom1OutOf1(ecCurve: EC, privKey: string, nonce: string): string {
  const privKeyBN = new BN(privKey, 16);
  const nonceBN = new BN(nonce, 16);
  return privKeyBN.sub(nonceBN).umod(ecCurve.curve.n).toString("hex");
}

export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex).getPublic();
}

export const encryptionEC = new EC("secp256k1");

export const generateShares = async (
  ecCurve: EC,
  keyType: KeyType,
  serverTimeOffset: number,
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  privKey: BN
) => {
  const keyData = keyType === "ed25519" ? await generateEd25519KeyData(privKey) : await generateSecp256k1KeyData(privKey);
  const { metadataNonce, oAuthKeyScalar: oAuthKey, encryptedSeed, metadataSigningKey } = keyData;
  const threshold = ~~(nodePubkeys.length / 2) + 1;
  const degree = threshold - 1;
  const nodeIndexesBn: BN[] = [];

  for (const nodeIndex of nodeIndexes) {
    nodeIndexesBn.push(new BN(nodeIndex));
  }
  const oAuthPubKey = ecCurve.keyFromPrivate(oAuthKey.toString("hex").padStart(64, "0")).getPublic();
  const poly = generateRandomPolynomial(ecCurve, degree, oAuthKey);
  const shares = poly.generateShares(nodeIndexesBn);
  const nonceParams = generateNonceMetadataParams(serverTimeOffset, "getOrSetNonce", metadataSigningKey, keyType, metadataNonce, encryptedSeed);
  const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf8").toString("base64");
  const sharesData: ImportedShare[] = [];
  const encPromises: Promise<Ecies>[] = [];
  for (let i = 0; i < nodeIndexesBn.length; i++) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${nodeIndexesBn[i].toString("hex", 64)}`);
    }
    const nodePubKey = encryptionEC.keyFromPublic({ x: nodePubkeys[i].X, y: nodePubkeys[i].Y });
    encPromises.push(
      encrypt(Buffer.from(nodePubKey.getPublic().encodeCompressed("hex"), "hex"), Buffer.from(shareJson.share.padStart(64, "0"), "hex"))
    );
  }
  const encShares = await Promise.all(encPromises);
  for (let i = 0; i < nodeIndexesBn.length; i++) {
    const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
    const encParams = encShares[i];
    const encParamsMetadata = encParamsBufToHex(encParams);
    const shareData: ImportedShare = {
      encrypted_seed: keyData.encryptedSeed,
      final_user_point: keyData.finalUserPubKeyPoint,
      oauth_pub_key_x: oAuthPubKey.getX().toString("hex", 64),
      oauth_pub_key_y: oAuthPubKey.getY().toString("hex", 64),
      signing_pub_key_x: keyData.SigningPubX.toString("hex"),
      signing_pub_key_y: keyData.SigningPubY.toString("hex"),
      encrypted_share: encParamsMetadata.ciphertext,
      encrypted_share_metadata: encParamsMetadata,
      node_index: Number.parseInt(shareJson.shareIndex, 16),
      key_type: keyType,
      nonce_data: nonceData,
      nonce_signature: nonceParams.signature,
    };
    sharesData.push(shareData);
  }

  return sharesData;
};
